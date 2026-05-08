#include "shared/bpf_compat_min.h"
#include <bpf/bpf_helpers.h>

#define PCAPC_BPF
#include "shared/packet_policy_types.h"

char LICENSE[] SEC("license") = "GPL";

#define TC_ACT_OK 0

#define DIR_INGRESS 0
#define DIR_EGRESS  1

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88A8

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

#define ETH_HDR_LEN 14
#define VLAN_TAG_LEN 4
#define IPV4_MIN_HDR_LEN 20
#define TCP_MIN_HDR_LEN 20
#define UDP_HDR_LEN 8

#ifndef BPF_MAP_TYPE_LRU_HASH
#define BPF_MAP_TYPE_LRU_HASH 9
#endif

#define QUIC_LONG_HEADER_BIT 0x80
#define QUIC_FIXED_BIT 0x40
#define QUIC_CID_STORE_LEARNED 1
#define QUIC_CID_STORE_UPDATED 2
#define QUIC_CID_STORE_FAILED 3

/* Compile-time ringbuf event payload capacity. */
#define MAX_CAPTURE_LEN 4096
/* Verifier-safe copy limit for the current BPF path. It currently matches the
 * full event payload capacity, so copied bytes can reach MAX_CAPTURE_LEN.
 */
#define COPY_WINDOW_LEN MAX_CAPTURE_LEN

#define PCAPC_BARRIER_VAR(var) asm volatile("" : "+r"(var))

struct event {
    __u64 ts_ns;
    __u32 ifindex;
    __u32 pkt_len;
    __u32 cap_len;
    __u16 l3_off;
    __u16 l4_off;
    __u16 payload_off;
    __u16 src_port;
    __u16 dst_port;
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

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} capture_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct pcapc_quic_cid_key);
    __type(value, struct pcapc_quic_cid_value);
} quic_cids SEC(".maps");

struct bpf_packet_meta {
    __u16 l3_off;
    __u16 l4_off;
    __u16 payload_off;
    __u8 ip_proto;
    __u8 l4_proto;
    __u8 reason;
    __u16 src_port;
    __u16 dst_port;
    __u32 payload_len;
};

static __always_inline __u16 load_be16(const __u8 *p)
{
    return ((__u16)p[0] << 8) | (__u16)p[1];
}

static __always_inline void stat_inc(__u32 key)
{
    __u64 *value;

    value = bpf_map_lookup_elem(&capture_stats, &key);
    if (value)
        __sync_fetch_and_add(value, 1);
}

static __always_inline __u32 stat_key_for_reason(__u8 reason)
{
    switch (reason) {
    case PCAPC_REASON_DEFAULT:
        return STAT_REASON_DEFAULT;
    case PCAPC_REASON_PARSE_ERROR:
        return STAT_REASON_PARSE_ERROR;
    case PCAPC_REASON_IPV4:
        return STAT_REASON_IPV4;
    case PCAPC_REASON_IPV6:
        return STAT_REASON_IPV6;
    case PCAPC_REASON_TCP:
        return STAT_REASON_TCP;
    case PCAPC_REASON_UDP:
        return STAT_REASON_UDP;
    case PCAPC_REASON_TLS_APP_DATA:
        return STAT_REASON_TLS_APP_DATA;
    case PCAPC_REASON_QUIC_LONG:
        return STAT_REASON_QUIC_LONG;
    case PCAPC_REASON_QUIC_SHORT_CANDIDATE:
        return STAT_REASON_QUIC_SHORT_CANDIDATE;
    default:
        return STAT_REASON_DEFAULT;
    }
}

static __always_inline void zero_quic_cid_bytes(__u8 *dst)
{
    int i;

#pragma unroll
    for (i = 0; i < PCAPC_QUIC_MAX_CID_LEN; i++)
        dst[i] = 0;
}

static __always_inline __u8 load_quic_cid_bytes(struct __sk_buff *skb,
                                                __u32 offset,
                                                __u8 len,
                                                __u8 *dst)
{
    int i;

    zero_quic_cid_bytes(dst);

#pragma unroll
    for (i = 0; i < PCAPC_QUIC_MAX_CID_LEN; i++) {
        __u8 byte = 0;

        if ((__u8)i >= len)
            continue;
        if (bpf_skb_load_bytes(skb, offset + (__u32)i, &byte, 1) < 0)
            return 0;
        dst[i] = byte;
    }

    return 1;
}

static __always_inline __u8 learn_quic_cid(const __u8 *cid_bytes,
                                           __u8 cid_len,
                                           __u32 ifindex,
                                           __u8 source_flags)
{
    struct pcapc_quic_cid_key key = {};
    struct pcapc_quic_cid_value init_value = {};
    struct pcapc_quic_cid_value *existing;
    __u64 now;
    int i;

    if (cid_len == 0 || cid_len > PCAPC_QUIC_MAX_CID_LEN)
        return 0;

    key.len = cid_len;
#pragma unroll
    for (i = 0; i < PCAPC_QUIC_MAX_CID_LEN; i++) {
        if ((__u8)i >= cid_len)
            continue;
        key.bytes[i] = cid_bytes[i];
    }

    now = bpf_ktime_get_ns();
    existing = bpf_map_lookup_elem(&quic_cids, &key);
    if (existing) {
        existing->packets++;
        existing->last_seen_ns = now;
        existing->source_flags |= source_flags;
        return QUIC_CID_STORE_UPDATED;
    }

    init_value.first_seen_ns = now;
    init_value.last_seen_ns = now;
    init_value.packets = 1;
    init_value.ifindex = ifindex;
    init_value.source_flags = source_flags;

    if (bpf_map_update_elem(&quic_cids, &key, &init_value, BPF_ANY) != 0)
        return QUIC_CID_STORE_FAILED;

    return QUIC_CID_STORE_LEARNED;
}

static __always_inline struct pcapc_capture_config load_capture_config(void)
{
    const __u32 key = 0;
    const struct pcapc_capture_config *cfg;
    struct pcapc_capture_config fallback = {
        4096u,
        8u,
        4096u,
        0u
    };

    cfg = bpf_map_lookup_elem(&capture_config, &key);
    if (cfg)
        return *cfg;

    return fallback;
}

/* This BPF parser is intentionally small and metadata-only. It uses fixed-size
 * bpf_skb_load_bytes() reads for verifier friendliness. TLS policy remains
 * limited to a later single-record AppData check; QUIC policy is still
 * disabled in BPF and will be added later in smaller steps.
 */
static __always_inline void parse_packet_headers(struct __sk_buff *skb,
                                                 __u32 parse_limit,
                                                 struct bpf_packet_meta *meta)
{
    __u8 eth[ETH_HDR_LEN];
    __u8 vlan[VLAN_TAG_LEN];
    __u8 ipv4[IPV4_MIN_HDR_LEN];
    __u8 l4[TCP_MIN_HDR_LEN];
    __u16 ether_type;
    __u16 frag_field;
    __u16 ipv4_total_len;
    __u16 l3_off;
    __u16 l4_off;
    __u16 payload_off;
    __u8 ip_proto;
    __u8 l4_proto;
    __u8 reason;
    __u16 src_port;
    __u16 dst_port;
    __u8 version_ihl;
    __u8 ipv4_hdr_len;
    __u8 tcp_hdr_len;

    meta->l3_off = 0;
    meta->l4_off = 0;
    meta->payload_off = 0;
    meta->ip_proto = 0;
    meta->l4_proto = 0;
    meta->reason = PCAPC_REASON_DEFAULT;
    meta->src_port = 0;
    meta->dst_port = 0;
    meta->payload_len = 0;

    if (parse_limit < ETH_HDR_LEN) {
        meta->reason = PCAPC_REASON_PARSE_ERROR;
        return;
    }

    if (bpf_skb_load_bytes(skb, 0, eth, ETH_HDR_LEN) < 0) {
        meta->reason = PCAPC_REASON_PARSE_ERROR;
        return;
    }

    ether_type = load_be16(&eth[12]);
    l3_off = ETH_HDR_LEN;

    if (ether_type == ETH_P_8021Q || ether_type == ETH_P_8021AD) {
        if ((__u32)l3_off + VLAN_TAG_LEN > parse_limit) {
            meta->reason = PCAPC_REASON_PARSE_ERROR;
            return;
        }
        if (bpf_skb_load_bytes(skb, l3_off, vlan, VLAN_TAG_LEN) < 0) {
            meta->reason = PCAPC_REASON_PARSE_ERROR;
            return;
        }
        ether_type = load_be16(&vlan[2]);
        l3_off += VLAN_TAG_LEN;
    }

    if (ether_type == ETH_P_8021Q || ether_type == ETH_P_8021AD) {
        if ((__u32)l3_off + VLAN_TAG_LEN > parse_limit) {
            meta->reason = PCAPC_REASON_PARSE_ERROR;
            return;
        }
        if (bpf_skb_load_bytes(skb, l3_off, vlan, VLAN_TAG_LEN) < 0) {
            meta->reason = PCAPC_REASON_PARSE_ERROR;
            return;
        }
        ether_type = load_be16(&vlan[2]);
        l3_off += VLAN_TAG_LEN;
    }

    meta->l3_off = l3_off;

    if (ether_type == ETH_P_IPV6) {
        meta->ip_proto = 6;
        meta->reason = PCAPC_REASON_IPV6;
        return;
    }

    if (ether_type != ETH_P_IP)
        return;

    meta->ip_proto = 4;
    meta->reason = PCAPC_REASON_IPV4;

    if ((__u32)l3_off + IPV4_MIN_HDR_LEN > parse_limit) {
        meta->reason = PCAPC_REASON_PARSE_ERROR;
        return;
    }

    if (bpf_skb_load_bytes(skb, l3_off, ipv4, IPV4_MIN_HDR_LEN) < 0) {
        meta->reason = PCAPC_REASON_PARSE_ERROR;
        return;
    }

    version_ihl = ipv4[0];
    if ((version_ihl >> 4) != 4)
        return;

    ipv4_total_len = load_be16(&ipv4[2]);
    ipv4_hdr_len = (version_ihl & 0x0f) * 4u;
    if (ipv4_hdr_len < IPV4_MIN_HDR_LEN) {
        meta->reason = PCAPC_REASON_PARSE_ERROR;
        return;
    }

    if ((__u32)l3_off + ipv4_hdr_len > parse_limit) {
        meta->reason = PCAPC_REASON_PARSE_ERROR;
        return;
    }

    if (ipv4_total_len < ipv4_hdr_len) {
        meta->reason = PCAPC_REASON_PARSE_ERROR;
        return;
    }

    frag_field = load_be16(&ipv4[6]);
    if ((frag_field & 0x2000u) != 0u || (frag_field & 0x1fffu) != 0u)
        return;

    ip_proto = ipv4[9];
    l4_off = (__u16)(l3_off + ipv4_hdr_len);
    meta->l4_off = l4_off;

    if (ip_proto == IPPROTO_TCP) {
        if ((__u32)l4_off + TCP_MIN_HDR_LEN > parse_limit) {
            meta->reason = PCAPC_REASON_PARSE_ERROR;
            return;
        }

        if (bpf_skb_load_bytes(skb, l4_off, l4, TCP_MIN_HDR_LEN) < 0) {
            meta->reason = PCAPC_REASON_PARSE_ERROR;
            return;
        }

        src_port = load_be16(&l4[0]);
        dst_port = load_be16(&l4[2]);
        tcp_hdr_len = (l4[12] >> 4) * 4u;
        if (tcp_hdr_len < TCP_MIN_HDR_LEN) {
            meta->reason = PCAPC_REASON_PARSE_ERROR;
            return;
        }

        if ((__u32)ipv4_hdr_len + tcp_hdr_len > ipv4_total_len) {
            meta->reason = PCAPC_REASON_PARSE_ERROR;
            return;
        }

        if ((__u32)l4_off + tcp_hdr_len > parse_limit) {
            meta->reason = PCAPC_REASON_PARSE_ERROR;
            return;
        }

        payload_off = (__u16)(l4_off + tcp_hdr_len);
        l4_proto = IPPROTO_TCP;
        reason = PCAPC_REASON_TCP;
    } else if (ip_proto == IPPROTO_UDP) {
        if ((__u32)ipv4_hdr_len + UDP_HDR_LEN > ipv4_total_len) {
            meta->reason = PCAPC_REASON_PARSE_ERROR;
            return;
        }

        if ((__u32)l4_off + UDP_HDR_LEN > parse_limit) {
            meta->reason = PCAPC_REASON_PARSE_ERROR;
            return;
        }

        if (bpf_skb_load_bytes(skb, l4_off, l4, UDP_HDR_LEN) < 0) {
            meta->reason = PCAPC_REASON_PARSE_ERROR;
            return;
        }

        src_port = load_be16(&l4[0]);
        dst_port = load_be16(&l4[2]);
        payload_off = (__u16)(l4_off + UDP_HDR_LEN);
        l4_proto = IPPROTO_UDP;
        reason = PCAPC_REASON_UDP;
    } else {
        return;
    }

    meta->payload_off = payload_off;
    meta->payload_len = (__u32)ipv4_total_len - (__u32)ipv4_hdr_len - (__u32)(payload_off - l4_off);
    meta->l4_proto = l4_proto;
    meta->reason = reason;
    meta->src_port = src_port;
    meta->dst_port = dst_port;
}

static __always_inline __u8 detect_simple_tls_app_data(struct __sk_buff *skb,
                                                       const struct bpf_packet_meta *meta,
                                                       __u32 parse_limit,
                                                       __u32 *tls_cap_len,
                                                       const struct pcapc_capture_config *cfg)
{
    __u8 tls[5];
    __u16 record_len;
    __u32 tls_record_total_len;
    __u32 cap;

    if (meta->reason != PCAPC_REASON_TCP)
        return 0;
    if (meta->l4_proto != IPPROTO_TCP)
        return 0;
    if (meta->src_port != 443u && meta->dst_port != 443u)
        return 0;
    if (meta->payload_len < sizeof(tls))
        return 0;
    if ((__u32)meta->payload_off + sizeof(tls) > parse_limit)
        return 0;

    if (bpf_skb_load_bytes(skb, meta->payload_off, tls, sizeof(tls)) < 0)
        return 0;

    if (tls[0] != 0x17u)
        return 0;
    if (tls[1] != 0x03u)
        return 0;
    if (tls[2] < 0x01u || tls[2] > 0x04u)
        return 0;

    record_len = load_be16(&tls[3]);
    if (record_len == 0u || record_len > 18432u)
        return 0;

    /* This helper handles only a single TLS record that starts exactly at the
     * TCP payload offset. It accepts both complete and partial Application
     * Data records. If the segment contains trailing bytes after the first TLS
     * record, it is treated as a later multi-record/trailing-data case and is
     * left unconstrained for now.
     */
    tls_record_total_len = (__u32)sizeof(tls) + (__u32)record_len;
    if (meta->payload_len > tls_record_total_len)
        return 0;
    if (cfg->encrypted_snaplen > 0xffffffffu - (__u32)meta->payload_off)
        return 0;

    cap = (__u32)meta->payload_off + cfg->encrypted_snaplen;
    if (cap > parse_limit)
        cap = parse_limit;
    if (cap > MAX_CAPTURE_LEN)
        cap = MAX_CAPTURE_LEN;
    if (cap > cfg->max_capture_len)
        cap = cfg->max_capture_len;
    if (cap == 0)
        return 0;

    *tls_cap_len = cap;
    return 1;
}

static __always_inline __u8 detect_quic_long_header(struct __sk_buff *skb,
                                                    const struct bpf_packet_meta *meta,
                                                    __u32 parse_limit,
                                                    __u32 ifindex)
{
    __u8 hdr[6];
    __u8 dcid[PCAPC_QUIC_MAX_CID_LEN];
    __u8 scid[PCAPC_QUIC_MAX_CID_LEN];
    __u8 scid_len_byte = 0;
    __u8 dcid_len;
    __u8 scid_len;
    __u32 payload_off;
    __u32 payload_end;
    __u32 dcid_off;
    __u32 scid_len_off;
    __u32 scid_off;
    __u8 store_result;

    if (meta->reason != PCAPC_REASON_UDP)
        return 0;
    if (meta->l4_proto != IPPROTO_UDP)
        return 0;
    if (meta->src_port != 443u && meta->dst_port != 443u)
        return 0;
    if (meta->payload_len < 7u)
        return 0;

    payload_off = (__u32)meta->payload_off;
    payload_end = payload_off + meta->payload_len;
    if (payload_off + sizeof(hdr) > parse_limit)
        return 0;
    if (payload_off + sizeof(hdr) > payload_end)
        return 0;

    if (bpf_skb_load_bytes(skb, payload_off, hdr, sizeof(hdr)) < 0)
        return 0;

    if ((hdr[0] & QUIC_LONG_HEADER_BIT) == 0u)
        return 0;
    if ((hdr[0] & QUIC_FIXED_BIT) == 0u)
        return 0;

    dcid_len = hdr[5];
    if (dcid_len > PCAPC_QUIC_MAX_CID_LEN)
        return 0;

    dcid_off = payload_off + sizeof(hdr);
    scid_len_off = dcid_off + dcid_len;
    if (scid_len_off + 1u > payload_end)
        return 0;
    if (scid_len_off + 1u > parse_limit)
        return 0;

    if (dcid_len != 0u) {
        if (dcid_off + dcid_len > payload_end)
            return 0;
        if (dcid_off + dcid_len > parse_limit)
            return 0;
        if (!load_quic_cid_bytes(skb, dcid_off, dcid_len, dcid))
            return 0;
    } else {
        zero_quic_cid_bytes(dcid);
    }

    if (bpf_skb_load_bytes(skb, scid_len_off, &scid_len_byte, 1) < 0)
        return 0;

    scid_len = scid_len_byte;
    if (scid_len > PCAPC_QUIC_MAX_CID_LEN)
        return 0;

    scid_off = scid_len_off + 1u;
    if (scid_off + scid_len > payload_end)
        return 0;
    if (scid_off + scid_len > parse_limit)
        return 0;

    if (scid_len != 0u) {
        if (!load_quic_cid_bytes(skb, scid_off, scid_len, scid))
            return 0;
    } else {
        zero_quic_cid_bytes(scid);
    }

    stat_inc(STAT_QUIC_LONG);

    if (dcid_len != 0u) {
        store_result = learn_quic_cid(dcid, dcid_len, ifindex, PCAPC_QUIC_CID_SOURCE_DCID);
        if (store_result == QUIC_CID_STORE_LEARNED)
            stat_inc(STAT_QUIC_CID_LEARNED);
        else if (store_result == QUIC_CID_STORE_UPDATED)
            stat_inc(STAT_QUIC_CID_UPDATE);
        else if (store_result == QUIC_CID_STORE_FAILED)
            stat_inc(STAT_QUIC_CID_STORE_FAILED);
    }

    if (scid_len != 0u) {
        store_result = learn_quic_cid(scid, scid_len, ifindex, PCAPC_QUIC_CID_SOURCE_SCID);
        if (store_result == QUIC_CID_STORE_LEARNED)
            stat_inc(STAT_QUIC_CID_LEARNED);
        else if (store_result == QUIC_CID_STORE_UPDATED)
            stat_inc(STAT_QUIC_CID_UPDATE);
        else if (store_result == QUIC_CID_STORE_FAILED)
            stat_inc(STAT_QUIC_CID_STORE_FAILED);
    }

    return 1;
}

static __always_inline int capture_packet(struct __sk_buff *skb, __u8 direction)
{
    struct event *e;
    struct bpf_packet_meta meta;
    struct pcapc_capture_config cfg;
    __u32 default_snaplen;
    __u32 max_capture_len;
    __u32 pkt_len;
    __u32 parse_limit;
    __u32 cap_len;
    __u32 tls_cap_len;

    cfg = load_capture_config();
    default_snaplen = cfg.default_snaplen;
    max_capture_len = cfg.max_capture_len;
    pkt_len = skb->len;
    stat_inc(STAT_EVENTS_TOTAL);

    if (pkt_len == 0)
        return TC_ACT_OK;

    if (default_snaplen == 0)
        default_snaplen = 1;
    if (max_capture_len == 0)
        max_capture_len = 1;

    parse_limit = pkt_len;
    if (parse_limit > max_capture_len)
        parse_limit = max_capture_len;
    if (parse_limit > MAX_CAPTURE_LEN)
        parse_limit = MAX_CAPTURE_LEN;

    cap_len = pkt_len;
    if (cap_len > default_snaplen)
        cap_len = default_snaplen;
    if (cap_len > max_capture_len)
        cap_len = max_capture_len;
    if (cap_len > MAX_CAPTURE_LEN)
        cap_len = MAX_CAPTURE_LEN;
    if (cap_len > COPY_WINDOW_LEN)
        cap_len = COPY_WINDOW_LEN;

    parse_packet_headers(skb, parse_limit, &meta);
    if (meta.l4_proto == IPPROTO_UDP) {
        if (detect_quic_long_header(skb, &meta, parse_limit, skb->ifindex))
            meta.reason = PCAPC_REASON_QUIC_LONG;
    } else if (detect_simple_tls_app_data(skb, &meta, parse_limit, &tls_cap_len, &cfg)) {
        cap_len = tls_cap_len;
        meta.reason = PCAPC_REASON_TLS_APP_DATA;
    }
    stat_inc(stat_key_for_reason(meta.reason));
    if (meta.l4_proto == IPPROTO_TCP &&
        (meta.src_port == 443u || meta.dst_port == 443u))
        stat_inc(STAT_TCP_443);
    if (meta.l4_proto == IPPROTO_UDP &&
        (meta.src_port == 443u || meta.dst_port == 443u))
        stat_inc(STAT_UDP_443);

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        stat_inc(STAT_RINGBUF_RESERVE_FAILED);
        return TC_ACT_OK;
    }

    /* BPF currently uses only the runtime-configurable default snaplen
     * policy, capped by the compile-time event payload capacity above.
     * Shared L2/L3/L4 parsing and protocol-aware TLS/QUIC policy remain
     * host-only until BPF parsing is added in later steps. Keep
     * conservative metadata defaults here.
     */
    if (cap_len >= MAX_CAPTURE_LEN) {
        cap_len = MAX_CAPTURE_LEN;
        if (bpf_skb_load_bytes(skb, 0, e->data, MAX_CAPTURE_LEN) < 0) {
            stat_inc(STAT_COPY_FAILED);
            bpf_ringbuf_discard(e, 0);
            return TC_ACT_OK;
        }
    } else {
        __u32 bounded_len = cap_len;

        /* Force clang to emit the mask instruction. Keep the mask, zero check,
         * and helper size argument on the same verifier-visible value: adding
         * another barrier after the mask can make clang check one register and
         * pass a different one to bpf_skb_load_bytes(), leaving the helper size
         * range as [0, MAX_CAPTURE_LEN - 1].
         */
        PCAPC_BARRIER_VAR(bounded_len);
        bounded_len &= (MAX_CAPTURE_LEN - 1u);
        if (bounded_len == 0) {
            bpf_ringbuf_discard(e, 0);
            return TC_ACT_OK;
        }

        cap_len = bounded_len;
        if (bpf_skb_load_bytes(skb, 0, e->data, bounded_len) < 0) {
            stat_inc(STAT_COPY_FAILED);
            bpf_ringbuf_discard(e, 0);
            return TC_ACT_OK;
        }
    }

    e->ts_ns = bpf_ktime_get_ns();
    e->ifindex = skb->ifindex;
    e->pkt_len = pkt_len;
    e->cap_len = cap_len;
    e->l3_off = meta.l3_off;
    e->l4_off = meta.l4_off;
    e->payload_off = meta.payload_off;
    e->src_port = meta.src_port;
    e->dst_port = meta.dst_port;
    e->direction = direction;
    e->ip_proto = meta.ip_proto;
    e->l4_proto = meta.l4_proto;
    e->reason = meta.reason;

    stat_inc(STAT_EVENTS_SUBMITTED);
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
