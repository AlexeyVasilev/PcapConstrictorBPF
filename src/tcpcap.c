#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <stddef.h>
#include <net/if.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "shared/packet_policy_types.h"
#include "tcpcap.skel.h"

/* Compile-time event payload capacity shared with the BPF event layout. */
#define MAX_CAPTURE_LEN 4096
/* Default pcap global snaplen. Runtime capture policy cannot exceed the
 * compile-time event payload capacity above.
 */
#define SNAPLEN MAX_CAPTURE_LEN

#define DIR_INGRESS 0
#define DIR_EGRESS  1

#define PCAP_MAGIC_USEC 0xa1b2c3d4
#define PCAP_VERSION_MAJOR 2
#define PCAP_VERSION_MINOR 4
#define LINKTYPE_ETHERNET 1

static volatile sig_atomic_t exiting = 0;

static const char *const stat_names[STAT_MAX] = {
    [STAT_EVENTS_TOTAL] = "events_total",
    [STAT_EVENTS_SUBMITTED] = "events_submitted",
    [STAT_RINGBUF_RESERVE_FAILED] = "ringbuf_reserve_failed",
    [STAT_COPY_FAILED] = "copy_failed",
    [STAT_REASON_DEFAULT] = "reason_default",
    [STAT_REASON_PARSE_ERROR] = "reason_parse_error",
    [STAT_REASON_IPV4] = "reason_ipv4",
    [STAT_REASON_IPV6] = "reason_ipv6",
    [STAT_REASON_TCP] = "reason_tcp",
    [STAT_REASON_UDP] = "reason_udp",
    [STAT_REASON_TLS_APP_DATA] = "reason_tls_app_data",
    [STAT_REASON_QUIC_LONG] = "reason_quic_long",
    [STAT_REASON_QUIC_SHORT_CANDIDATE] = "reason_quic_short_candidate",
    [STAT_TCP_443] = "tcp_443",
    [STAT_UDP_443] = "udp_443",
    [STAT_QUIC_LONG] = "quic_long",
    [STAT_QUIC_SHORT_CANDIDATE] = "quic_short_candidate",
    [STAT_QUIC_CID_LEARNED] = "quic_cid_learned",
    [STAT_QUIC_CID_UPDATE] = "quic_cid_update",
    [STAT_QUIC_CID_STORE_FAILED] = "quic_cid_store_failed",
    [STAT_QUIC_FLOW_LEARNED] = "quic_flow_learned",
    [STAT_QUIC_FLOW_UPDATE] = "quic_flow_update",
    [STAT_QUIC_FLOW_STORE_FAILED] = "quic_flow_store_failed",
    [STAT_QUIC_SHORT_FLOW_MATCH] = "quic_short_flow_match",
    [STAT_QUIC_SHORT_CONSTRICTED] = "quic_short_constricted",
};

struct event {
    uint64_t ts_ns;
    uint32_t ifindex;
    uint32_t pkt_len;
    uint32_t cap_len;
    uint16_t l3_off;
    uint16_t l4_off;
    uint16_t payload_off;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t direction;
    uint8_t ip_proto;
    uint8_t l4_proto;
    uint8_t reason;
    uint8_t data[MAX_CAPTURE_LEN];
};

struct pcap_global_header {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

struct pcap_packet_header {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};

struct app_state {
    FILE *pcap_file;
    uint64_t mono_base_ns;
    uint64_t real_base_ns;
    uint64_t packets;
    uint64_t ingress_packets;
    uint64_t egress_packets;
};

static void print_usage(const char *argv0)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s <interface> <output.pcap> [--config <config.ini>]\n",
            argv0);
}

static void handle_signal(int sig)
{
    (void)sig;
    exiting = 1;
}

static struct pcapc_capture_config default_capture_config(void)
{
    struct pcapc_capture_config cfg = {
        4096u,
        8u,
        4096u,
        0u,
        32u
    };

    return cfg;
}

static char *trim_whitespace(char *s)
{
    char *end;

    while (*s != '\0' && isspace((unsigned char)*s))
        s++;

    if (*s == '\0')
        return s;

    end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) {
        *end = '\0';
        end--;
    }

    return s;
}

static int parse_u32_value(const char *text, uint32_t *value)
{
    char *end = NULL;
    unsigned long parsed;

    if (text == NULL || *text == '\0')
        return -1;

    errno = 0;
    parsed = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || parsed > 0xffffffffUL)
        return -1;

    *value = (uint32_t)parsed;
    return 0;
}

static int parse_bool_value(const char *text, bool *value)
{
    if (strcmp(text, "true") == 0) {
        *value = true;
        return 0;
    }
    if (strcmp(text, "false") == 0) {
        *value = false;
        return 0;
    }

    return -1;
}

static void normalize_capture_config(const char *source,
                                     struct pcapc_capture_config *cfg)
{
    if (cfg->default_snaplen == 0u) {
        fprintf(stderr,
                "warning: %s sets default_snaplen=0; keeping 4096\n",
                source);
        cfg->default_snaplen = 4096u;
    }
    if (cfg->max_capture_len == 0u) {
        fprintf(stderr,
                "warning: %s sets max_capture_len=0; keeping 4096\n",
                source);
        cfg->max_capture_len = 4096u;
    }
    if (cfg->encrypted_snaplen == 0u) {
        fprintf(stderr,
                "warning: %s sets encrypted_snaplen=0; keeping 8\n",
                source);
        cfg->encrypted_snaplen = 8u;
    }
    if (cfg->quic_short_header_keep_packet_bytes == 0u) {
        fprintf(stderr,
                "warning: %s sets quic short keep=0; keeping 32\n",
                source);
        cfg->quic_short_header_keep_packet_bytes = 32u;
    }

    if (cfg->default_snaplen > MAX_CAPTURE_LEN) {
        fprintf(stderr,
                "warning: %s default_snaplen=%u exceeds MAX_CAPTURE_LEN=%u; clamping\n",
                source,
                cfg->default_snaplen,
                MAX_CAPTURE_LEN);
        cfg->default_snaplen = MAX_CAPTURE_LEN;
    }
    if (cfg->max_capture_len > MAX_CAPTURE_LEN) {
        fprintf(stderr,
                "warning: %s max_capture_len=%u exceeds MAX_CAPTURE_LEN=%u; clamping\n",
                source,
                cfg->max_capture_len,
                MAX_CAPTURE_LEN);
        cfg->max_capture_len = MAX_CAPTURE_LEN;
    }
    if (cfg->default_snaplen > cfg->max_capture_len) {
        fprintf(stderr,
                "warning: %s default_snaplen=%u exceeds max_capture_len=%u; clamping default_snaplen\n",
                source,
                cfg->default_snaplen,
                cfg->max_capture_len);
        cfg->default_snaplen = cfg->max_capture_len;
    }
}

static int load_config_file(const char *path, struct pcapc_capture_config *cfg)
{
    enum { LINE_BUF_SIZE = 512 };
    FILE *f;
    char line[LINE_BUF_SIZE];
    char section[32] = "";
    unsigned int line_no = 0;

    f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "failed to open config file '%s': %s\n",
                path, strerror(errno));
        return -1;
    }

    while (fgets(line, sizeof(line), f) != NULL) {
        char *trimmed;
        char *eq;
        char *key;
        char *value;

        line_no++;
        line[strcspn(line, "\r\n")] = '\0';
        trimmed = trim_whitespace(line);
        if (*trimmed == '\0' || *trimmed == '#' || *trimmed == ';')
            continue;

        if (*trimmed == '[') {
            size_t len;

            len = strlen(trimmed);
            if (len < 3 || trimmed[len - 1] != ']') {
                fprintf(stderr,
                        "warning: %s:%u invalid section header ignored\n",
                        path, line_no);
                continue;
            }

            trimmed[len - 1] = '\0';
            trimmed = trim_whitespace(trimmed + 1);
            if (strlen(trimmed) >= sizeof(section)) {
                fprintf(stderr,
                        "warning: %s:%u section name too long ignored\n",
                        path, line_no);
                section[0] = '\0';
                continue;
            }

            strcpy(section, trimmed);
            continue;
        }

        eq = strchr(trimmed, '=');
        if (!eq) {
            fprintf(stderr,
                    "warning: %s:%u invalid line ignored\n",
                    path, line_no);
            continue;
        }

        *eq = '\0';
        key = trim_whitespace(trimmed);
        value = trim_whitespace(eq + 1);

        if (strcmp(section, "capture") == 0) {
            uint32_t parsed;

            if (strcmp(key, "default_snaplen") == 0) {
                if (parse_u32_value(value, &parsed) != 0 || parsed == 0u) {
                    fprintf(stderr,
                            "warning: %s:%u invalid capture.default_snaplen ignored\n",
                            path, line_no);
                    continue;
                }
                cfg->default_snaplen = parsed;
            } else if (strcmp(key, "max_capture_len") == 0) {
                if (parse_u32_value(value, &parsed) != 0 || parsed == 0u) {
                    fprintf(stderr,
                            "warning: %s:%u invalid capture.max_capture_len ignored\n",
                            path, line_no);
                    continue;
                }
                cfg->max_capture_len = parsed;
            } else {
                fprintf(stderr,
                        "warning: %s:%u unknown capture key '%s' ignored\n",
                        path, line_no, key);
            }
        } else if (strcmp(section, "tls") == 0) {
            uint32_t parsed;

            if (strcmp(key, "encrypted_snaplen") == 0) {
                if (parse_u32_value(value, &parsed) != 0 || parsed == 0u) {
                    fprintf(stderr,
                            "warning: %s:%u invalid tls.encrypted_snaplen ignored\n",
                            path, line_no);
                    continue;
                }
                cfg->encrypted_snaplen = parsed;
            } else {
                fprintf(stderr,
                        "warning: %s:%u unknown tls key '%s' ignored\n",
                        path, line_no, key);
            }
        } else if (strcmp(section, "quic") == 0) {
            uint32_t parsed;
            bool parsed_bool;

            if (strcmp(key, "short_header_keep_packet_bytes") == 0) {
                if (parse_u32_value(value, &parsed) != 0 || parsed == 0u) {
                    fprintf(stderr,
                            "warning: %s:%u invalid quic.short_header_keep_packet_bytes ignored\n",
                            path, line_no);
                    continue;
                }
                cfg->quic_short_header_keep_packet_bytes = parsed;
            } else if (strcmp(key, "require_dcid_match") == 0) {
                if (parse_bool_value(value, &parsed_bool) != 0) {
                    fprintf(stderr,
                            "warning: %s:%u invalid quic.require_dcid_match ignored\n",
                            path, line_no);
                } else if (!parsed_bool) {
                    fprintf(stderr,
                            "warning: %s:%u quic.require_dcid_match is fixed to true in current BPF policy\n",
                            path, line_no);
                }
            } else if (strcmp(key, "allow_short_header_without_known_dcid") == 0) {
                if (parse_bool_value(value, &parsed_bool) != 0) {
                    fprintf(stderr,
                            "warning: %s:%u invalid quic.allow_short_header_without_known_dcid ignored\n",
                            path, line_no);
                } else if (parsed_bool) {
                    fprintf(stderr,
                            "warning: %s:%u quic.allow_short_header_without_known_dcid is fixed to false in current BPF policy\n",
                            path, line_no);
                }
            } else {
                fprintf(stderr,
                        "warning: %s:%u unknown quic key '%s' ignored\n",
                        path, line_no, key);
            }
        } else {
            fprintf(stderr,
                    "warning: %s:%u key outside supported section ignored\n",
                    path, line_no);
        }
    }

    fclose(f);
    normalize_capture_config(path, cfg);
    return 0;
}

static uint64_t clock_ns(clockid_t clock_id)
{
    struct timespec ts;

    if (clock_gettime(clock_id, &ts) != 0)
        return 0;

    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static int write_pcap_global_header(FILE *f)
{
    struct pcap_global_header hdr = {
        .magic_number = PCAP_MAGIC_USEC,
        .version_major = PCAP_VERSION_MAJOR,
        .version_minor = PCAP_VERSION_MINOR,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = SNAPLEN,
        .network = LINKTYPE_ETHERNET,
    };

    return fwrite(&hdr, sizeof(hdr), 1, f) == 1 ? 0 : -1;
}

static void bpf_timestamp_to_pcap_time(const struct app_state *state,
                                       uint64_t bpf_ts_ns,
                                       uint32_t *ts_sec,
                                       uint32_t *ts_usec)
{
    uint64_t real_ns;

    if (bpf_ts_ns >= state->mono_base_ns) {
        real_ns = state->real_base_ns + (bpf_ts_ns - state->mono_base_ns);
    } else {
        real_ns = state->real_base_ns;
    }

    *ts_sec = (uint32_t)(real_ns / 1000000000ULL);
    *ts_usec = (uint32_t)((real_ns % 1000000000ULL) / 1000ULL);
}

static void print_capture_stats(const struct tcpcap_bpf *skel)
{
    bool printed = false;
    int map_fd;
    uint32_t key;

    if (!skel)
        return;

    map_fd = bpf_map__fd(skel->maps.capture_stats);
    if (map_fd < 0) {
        fprintf(stderr, "warning: failed to access capture_stats map\n");
        return;
    }

    for (key = 0; key < STAT_MAX; key++) {
        uint64_t value = 0;

        if (bpf_map_lookup_elem(map_fd, &key, &value) != 0)
            continue;

        if (value == 0)
            continue;

        if (!printed) {
            fprintf(stderr, "stats:\n");
            printed = true;
        }

        fprintf(stderr, "  %s=%llu\n",
                stat_names[key] ? stat_names[key] : "unknown",
                (unsigned long long)value);
    }
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    (void)data_sz;

    struct app_state *state = ctx;
    const struct event *e = data;
    const size_t data_off = offsetof(struct event, data);

    if (data_sz < data_off)
        return 0;

    if (e->cap_len > MAX_CAPTURE_LEN)
        return 0;

    if (data_off + e->cap_len > data_sz)
        return 0;

    struct pcap_packet_header ph = {};

    bpf_timestamp_to_pcap_time(state, e->ts_ns, &ph.ts_sec, &ph.ts_usec);

    ph.incl_len = e->cap_len;
    ph.orig_len = e->pkt_len;

    if (fwrite(&ph, sizeof(ph), 1, state->pcap_file) != 1)
        return -1;

    if (fwrite(e->data, e->cap_len, 1, state->pcap_file) != 1)
        return -1;

    state->packets++;

    if (e->direction == DIR_INGRESS)
        state->ingress_packets++;
    else if (e->direction == DIR_EGRESS)
        state->egress_packets++;

    if ((state->packets % 1000) == 0) {
        fprintf(stderr,
                "captured=%llu ingress=%llu egress=%llu\n",
                (unsigned long long)state->packets,
                (unsigned long long)state->ingress_packets,
                (unsigned long long)state->egress_packets);
        fflush(state->pcap_file);
    }

    return 0;
}

int main(int argc, char **argv)
{
    struct tcpcap_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;

    struct bpf_tc_hook hook = {};
    struct bpf_tc_opts ingress_opts = {};
    struct bpf_tc_opts egress_opts = {};

    bool ingress_attached = false;
    bool egress_attached = false;

    struct app_state state = {};

    const char *ifname;
    const char *output_path;
    const char *config_path = NULL;
    unsigned int ifindex;
    uint32_t config_key = 0;
    struct pcapc_capture_config capture_config = default_capture_config();
    int ingress_fd;
    int egress_fd;
    int err = 0;

    if (argc != 3 && argc != 5) {
        print_usage(argv[0]);
        return 1;
    }

    ifname = argv[1];
    output_path = argv[2];
    if (argc == 5) {
        if (strcmp(argv[3], "--config") == 0 || strcmp(argv[3], "-c") == 0) {
            config_path = argv[4];
        } else {
            print_usage(argv[0]);
            return 1;
        }
    }

    if (config_path) {
        if (load_config_file(config_path, &capture_config) != 0)
            return 1;
    } else {
        normalize_capture_config("runtime defaults", &capture_config);
    }

    ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "failed to get ifindex for interface '%s': %s\n",
                ifname, strerror(errno));
        return 1;
    }

    state.pcap_file = fopen(output_path, "wb");
    if (!state.pcap_file) {
        fprintf(stderr, "failed to open output file '%s': %s\n",
                output_path, strerror(errno));
        return 1;
    }

    if (write_pcap_global_header(state.pcap_file) != 0) {
        fprintf(stderr, "failed to write pcap global header\n");
        err = 1;
        goto cleanup;
    }

    state.mono_base_ns = clock_ns(CLOCK_MONOTONIC);
    state.real_base_ns = clock_ns(CLOCK_REALTIME);

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    skel = tcpcap_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to open/load BPF skeleton\n");
        err = 1;
        goto cleanup;
    }

    err = bpf_map_update_elem(bpf_map__fd(skel->maps.capture_config),
                              &config_key,
                              &capture_config,
                              BPF_ANY);
    if (err) {
        fprintf(stderr, "failed to initialize capture config map: %s\n",
                strerror(errno));
        err = 1;
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, &state, NULL);
    if (!rb) {
        fprintf(stderr, "failed to create ring buffer\n");
        err = 1;
        goto cleanup;
    }

    ingress_fd = bpf_program__fd(skel->progs.handle_ingress);
    if (ingress_fd < 0) {
        fprintf(stderr, "failed to get ingress BPF program fd\n");
        err = 1;
        goto cleanup;
    }

    egress_fd = bpf_program__fd(skel->progs.handle_egress);
    if (egress_fd < 0) {
        fprintf(stderr, "failed to get egress BPF program fd\n");
        err = 1;
        goto cleanup;
    }

    hook.sz = sizeof(hook);
    hook.ifindex = ifindex;
    hook.attach_point = BPF_TC_INGRESS;

    err = bpf_tc_hook_create(&hook);
    if (err && err != -EEXIST) {
        fprintf(stderr, "failed to create TC hook: %d\n", err);
        goto cleanup;
    }

    ingress_opts.sz = sizeof(ingress_opts);
    ingress_opts.prog_fd = ingress_fd;
    ingress_opts.handle = 1;
    ingress_opts.priority = 1;
    ingress_opts.flags = BPF_TC_F_REPLACE;

    hook.attach_point = BPF_TC_INGRESS;
    err = bpf_tc_attach(&hook, &ingress_opts);
    if (err) {
        fprintf(stderr, "failed to attach TC ingress program: %d\n", err);
        goto cleanup;
    }
    ingress_attached = true;

    egress_opts.sz = sizeof(egress_opts);
    egress_opts.prog_fd = egress_fd;
    egress_opts.handle = 1;
    egress_opts.priority = 1;
    egress_opts.flags = BPF_TC_F_REPLACE;

    hook.attach_point = BPF_TC_EGRESS;
    err = bpf_tc_attach(&hook, &egress_opts);
    if (err) {
        fprintf(stderr, "failed to attach TC egress program: %d\n", err);
        goto cleanup;
    }
    egress_attached = true;

    printf("Capturing TC ingress+egress on %s ifindex=%u into %s\n",
           ifname, ifindex, output_path);
    printf("SNAPLEN=%u, max_capture_len=%u, TLS encrypted_keep=%u, "
           "QUIC short keep=%u. BPF policy: simple TLS AppData constriction; "
           "QUIC Long Header CID/flow learning and short-header flow "
           "matching/constriction enabled. "
           "Multi-record TLS remains disabled. "
           "Press Ctrl+C to stop.\n",
           capture_config.default_snaplen,
           capture_config.max_capture_len,
           capture_config.encrypted_snaplen,
           capture_config.quic_short_header_keep_packet_bytes);

    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err < 0) {
            if (err == -EINTR && exiting) {
                err = 0;
                break;
            }
            fprintf(stderr, "ring_buffer__poll error: %d\n", err);
            break;
        }
    }

cleanup:
    print_capture_stats(skel);

    if (egress_attached) {
        hook.attach_point = BPF_TC_EGRESS;
        bpf_tc_detach(&hook, &egress_opts);
    }

    if (ingress_attached) {
        hook.attach_point = BPF_TC_INGRESS;
        bpf_tc_detach(&hook, &ingress_opts);
    }

    ring_buffer__free(rb);
    tcpcap_bpf__destroy(skel);

    if (state.pcap_file) {
        fflush(state.pcap_file);
        fclose(state.pcap_file);
    }

    fprintf(stderr,
            "done: captured=%llu ingress=%llu egress=%llu\n",
            (unsigned long long)state.packets,
            (unsigned long long)state.ingress_packets,
            (unsigned long long)state.egress_packets);

    return err < 0 ? 1 : err;
}
