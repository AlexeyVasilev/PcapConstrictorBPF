#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define PCAPC_BPF
#include "shared/packet_policy_types.h"

char LICENSE[] SEC("license") = "GPL";

#define TC_ACT_OK 0

#define DIR_INGRESS 0
#define DIR_EGRESS  1

#define MAX_CAPTURE_LEN 4096

struct event {
    __u64 ts_ns;
    __u32 ifindex;
    __u32 pkt_len;
    __u32 cap_len;
    __u16 l3_off;
    __u16 l4_off;
    __u16 payload_off;
    __u8 direction;
    __u8 ip_proto;
    __u8 l4_proto;
    __u8 reason;
    __u8 data[MAX_CAPTURE_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct pcapc_capture_config);
} capture_config SEC(".maps");

static __always_inline __u32 min_u32(__u32 a, __u32 b)
{
    return a < b ? a : b;
}

static __always_inline struct pcapc_capture_config load_capture_config(void)
{
    const __u32 key = 0;
    const struct pcapc_capture_config *cfg;
    struct pcapc_capture_config fallback = {
        256u,
        8u,
        256u,
        0u
    };

    cfg = bpf_map_lookup_elem(&capture_config, &key);
    if (cfg)
        return *cfg;

    return fallback;
}

static __always_inline int capture_packet(struct __sk_buff *skb, __u8 direction)
{
    struct event *e;
    struct pcapc_capture_config cfg;
    __u32 cap_len;

    cfg = load_capture_config();
    cap_len = min_u32(skb->len, cfg.default_snaplen);
    cap_len = min_u32(cap_len, cfg.max_capture_len);
    cap_len = min_u32(cap_len, MAX_CAPTURE_LEN);

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return TC_ACT_OK;

    e->ts_ns = bpf_ktime_get_ns();
    e->ifindex = skb->ifindex;
    e->pkt_len = skb->len;
    e->cap_len = cap_len;
    e->l3_off = 0;
    e->l4_off = 0;
    e->payload_off = 0;
    e->direction = direction;
    e->ip_proto = 0;
    e->l4_proto = 0;
    e->reason = PCAPC_REASON_DEFAULT;

    if (cap_len != 0 && bpf_skb_load_bytes(skb, 0, e->data, cap_len) < 0) {
        bpf_ringbuf_discard(e, 0);
        return TC_ACT_OK;
    }

    bpf_ringbuf_submit(e, 0);
    return TC_ACT_OK;
}


SEC("tc")
int handle_ingress(struct __sk_buff *skb)
{
    return capture_packet(skb, DIR_INGRESS);
}

SEC("tc")
int handle_egress(struct __sk_buff *skb)
{
    return capture_packet(skb, DIR_EGRESS);
}
