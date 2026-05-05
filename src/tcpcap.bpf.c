#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

#define TC_ACT_OK 0

#define DIR_INGRESS 0
#define DIR_EGRESS  1

#define SNAPLEN 256

struct event {
    __u64 ts_ns;
    __u32 ifindex;
    __u32 pkt_len;
    __u32 cap_len;
    __u8 direction;
    __u8 _pad[3];
    __u8 data[SNAPLEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);
} events SEC(".maps");

static __always_inline int capture_packet(struct __sk_buff *skb, __u8 direction)
{
    struct event *e;
    __u32 cap_len;

    cap_len = skb->len;

    if (cap_len == 0)
        return TC_ACT_OK;

    if (cap_len > SNAPLEN)
        cap_len = SNAPLEN;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return TC_ACT_OK;

    e->ts_ns = bpf_ktime_get_ns();
    e->ifindex = skb->ifindex;
    e->pkt_len = skb->len;
    e->cap_len = cap_len;
    e->direction = direction;
    e->_pad[0] = 0;
    e->_pad[1] = 0;
    e->_pad[2] = 0;

    if (bpf_skb_load_bytes(skb, 0, e->data, cap_len) < 0) {
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
