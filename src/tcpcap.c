#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <net/if.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "tcpcap.skel.h"

#define SNAPLEN 256

#define DIR_INGRESS 0
#define DIR_EGRESS  1

#define PCAP_MAGIC_USEC 0xa1b2c3d4
#define PCAP_VERSION_MAJOR 2
#define PCAP_VERSION_MINOR 4
#define LINKTYPE_ETHERNET 1

static volatile sig_atomic_t exiting = 0;

struct event {
    uint64_t ts_ns;
    uint32_t ifindex;
    uint32_t pkt_len;
    uint32_t cap_len;
    uint8_t direction;
    uint8_t _pad[3];
    uint8_t data[SNAPLEN];
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

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    (void)data_sz;

    struct app_state *state = ctx;
    const struct event *e = data;

    if (e->cap_len > SNAPLEN)
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
    printf("SNAPLEN=%d. Press Ctrl+C to stop.\n", SNAPLEN);

    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err < 0) {
            fprintf(stderr, "ring_buffer__poll error: %d\n", err);
            break;
        }
    }

cleanup:
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
