#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
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

static void handle_signal(int sig)
{
    (void)sig;
    exiting = 1;
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

static const char *quic_cid_flags_to_string(uint8_t source_flags)
{
    if ((source_flags & (PCAPC_QUIC_CID_SOURCE_DCID | PCAPC_QUIC_CID_SOURCE_SCID)) ==
        (PCAPC_QUIC_CID_SOURCE_DCID | PCAPC_QUIC_CID_SOURCE_SCID))
        return "dcid|scid";
    if (source_flags & PCAPC_QUIC_CID_SOURCE_DCID)
        return "dcid";
    if (source_flags & PCAPC_QUIC_CID_SOURCE_SCID)
        return "scid";
    return "unknown";
}

static void print_quic_cids(const struct tcpcap_bpf *skel)
{
    enum { QUIC_CID_PRINT_LIMIT = 64 };

    struct pcapc_quic_cid_key key = {};
    struct pcapc_quic_cid_key next_key = {};
    bool have_key = false;
    bool printed = false;
    int map_fd;
    int shown = 0;

    if (!skel)
        return;

    map_fd = bpf_map__fd(skel->maps.quic_cids);
    if (map_fd < 0) {
        fprintf(stderr, "warning: failed to access quic_cids map\n");
        return;
    }

    while (bpf_map_get_next_key(map_fd, have_key ? &key : NULL, &next_key) == 0) {
        struct pcapc_quic_cid_value value = {};
        int more_entries = 0;
        int i;

        key = next_key;
        have_key = true;

        if (key.len == 0 || key.len > PCAPC_QUIC_MAX_CID_LEN)
            continue;

        if (bpf_map_lookup_elem(map_fd, &key, &value) != 0)
            continue;

        if (!printed) {
            fprintf(stderr, "learned_quic_cids:\n");
            printed = true;
        }

        fprintf(stderr, "  len=%u cid=", key.len);
        for (i = 0; i < key.len; i++)
            fprintf(stderr, "%02x", key.bytes[i]);
        fprintf(stderr, " packets=%llu flags=%s ifindex=%u\n",
                (unsigned long long)value.packets,
                quic_cid_flags_to_string(value.source_flags),
                value.ifindex);

        shown++;
        if (shown >= QUIC_CID_PRINT_LIMIT) {
            more_entries = (bpf_map_get_next_key(map_fd, &key, &next_key) == 0);
            if (more_entries)
                fprintf(stderr, "  ... truncated, shown=%d\n", shown);
            break;
        }
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

    unsigned int ifindex;
    uint32_t config_key = 0;
    struct pcapc_capture_config capture_config = {
        4096u,
        8u,
        4096u,
        0u
    };
    int ingress_fd;
    int egress_fd;
    int err = 0;

    if (argc != 3) {
        fprintf(stderr, "Usage: sudo %s <interface> <output.pcap>\n", argv[0]);
        fprintf(stderr, "Example: sudo %s enp0s3 out.pcap\n", argv[0]);
        return 1;
    }

    ifindex = if_nametoindex(argv[1]);
    if (!ifindex) {
        fprintf(stderr, "failed to get ifindex for interface '%s': %s\n",
                argv[1], strerror(errno));
        return 1;
    }

    state.pcap_file = fopen(argv[2], "wb");
    if (!state.pcap_file) {
        fprintf(stderr, "failed to open output file '%s': %s\n",
                argv[2], strerror(errno));
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
           argv[1], ifindex, argv[2]);
    printf("SNAPLEN=%d. BPF policy: default snaplen plus simple TLS AppData "
           "constriction; QUIC Long Header CID/flow learning and short-header "
           "flow matching enabled; QUIC constriction remains disabled. "
           "Multi-record TLS remains disabled. "
           "Press Ctrl+C to stop.\n",
           SNAPLEN);

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
    print_quic_cids(skel);

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
