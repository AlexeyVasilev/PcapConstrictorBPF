#pragma once

#include "packet_policy_types.h"

#ifdef PCAPC_BPF
#define PCAPC_INLINE static __always_inline
#else
#define PCAPC_INLINE static inline
#endif

enum {
    PCAPC_ETH_HDR_LEN = 14u,
    PCAPC_VLAN_TAG_LEN = 4u,
    PCAPC_MAX_VLAN_TAGS = 2u,
    PCAPC_IPV4_MIN_HDR_LEN = 20u,
    PCAPC_IPV6_HDR_LEN = 40u,
    PCAPC_TCP_MIN_HDR_LEN = 20u,
    PCAPC_UDP_HDR_LEN = 8u,
    PCAPC_ETHERTYPE_IPV4 = 0x0800u,
    PCAPC_ETHERTYPE_IPV6 = 0x86DDu,
    PCAPC_ETHERTYPE_VLAN = 0x8100u,
    PCAPC_ETHERTYPE_QINQ = 0x88A8u,
    PCAPC_IPPROTO_TCP = 6u,
    PCAPC_IPPROTO_UDP = 17u,
    PCAPC_TLS_RECORD_HDR_LEN = 5u,
    PCAPC_TLS_MAX_RECORD_LEN = 18432u,
    PCAPC_TLS_MAX_RECORDS_SCANNED = 8u,
    PCAPC_TLS_CHANGE_CIPHER_SPEC = 0x14u,
    PCAPC_TLS_ALERT = 0x15u,
    PCAPC_TLS_HANDSHAKE = 0x16u,
    PCAPC_TLS_APPLICATION_DATA = 0x17u
};

PCAPC_INLINE pcapc_u16 pcapc_load_be16(const pcapc_u8 *p)
{
    return (pcapc_u16)(((pcapc_u16)p[0] << 8) | (pcapc_u16)p[1]);
}

PCAPC_INLINE pcapc_u32 pcapc_load_be32(const pcapc_u8 *p)
{
    return ((pcapc_u32)p[0] << 24) |
           ((pcapc_u32)p[1] << 16) |
           ((pcapc_u32)p[2] << 8) |
           (pcapc_u32)p[3];
}

PCAPC_INLINE pcapc_u32 pcapc_min_u32(pcapc_u32 a, pcapc_u32 b)
{
    return a < b ? a : b;
}

PCAPC_INLINE const struct pcapc_capture_config *
pcapc_resolve_capture_config(const struct pcapc_capture_config *cfg)
{
    static const struct pcapc_capture_config default_cfg = {
        256u,
        256u,
        256u,
        0u
    };

    return cfg ? cfg : &default_cfg;
}

PCAPC_INLINE int
pcapc_find_tls_application_data_record_start(const pcapc_u8 *data,
                                             pcapc_u32 len,
                                             pcapc_u32 payload_off,
                                             pcapc_u32 *app_data_off)
{
    pcapc_u32 off;
    pcapc_u32 record_index;

    if (payload_off >= len)
        return 0;

    off = payload_off;

    for (record_index = 0u; record_index < PCAPC_TLS_MAX_RECORDS_SCANNED; record_index++) {
        pcapc_u8 content_type;
        pcapc_u8 major;
        pcapc_u8 minor;
        pcapc_u16 record_len;
        pcapc_u32 next_off;

        if (off >= len)
            return 0;

        if (len - off < PCAPC_TLS_RECORD_HDR_LEN)
            return 0;

        content_type = data[off];
        major = data[off + 1u];
        minor = data[off + 2u];
        record_len = pcapc_load_be16(data + off + 3u);

        if (major != 0x03u || minor < 0x01u || minor > 0x04u)
            return 0;

        if (record_len == 0u || record_len > PCAPC_TLS_MAX_RECORD_LEN)
            return 0;

        if (content_type == PCAPC_TLS_APPLICATION_DATA) {
            *app_data_off = off;
            return 1;
        }

        if (content_type != PCAPC_TLS_CHANGE_CIPHER_SPEC &&
            content_type != PCAPC_TLS_ALERT &&
            content_type != PCAPC_TLS_HANDSHAKE) {
            return 0;
        }

        next_off = off + PCAPC_TLS_RECORD_HDR_LEN + (pcapc_u32)record_len;
        if (next_off > len)
            return 0;

        off = next_off;
    }

    return 0;
}

PCAPC_INLINE struct pcapc_capture_decision
pcapc_decide_l2_packet_impl(const pcapc_u8 *data,
                            pcapc_u32 len,
                            const struct pcapc_capture_config *cfg)
{
    const struct pcapc_capture_config *active_cfg = pcapc_resolve_capture_config(cfg);
    struct pcapc_capture_decision decision = {0};
    pcapc_u32 l3_off;
    pcapc_u16 ether_type;
    pcapc_u32 vlan_count;

    decision.reason = PCAPC_REASON_DEFAULT;

    if (data == 0 || len == 0u)
        return decision;

    decision.cap_len = pcapc_min_u32(len, active_cfg->default_snaplen);
    decision.cap_len = pcapc_min_u32(decision.cap_len, active_cfg->max_capture_len);

    if (len < PCAPC_ETH_HDR_LEN) {
        decision.reason = PCAPC_REASON_PARSE_ERROR;
        return decision;
    }

    l3_off = PCAPC_ETH_HDR_LEN;
    ether_type = pcapc_load_be16(data + 12u);

    for (vlan_count = 0u; vlan_count < PCAPC_MAX_VLAN_TAGS; vlan_count++) {
        if (ether_type != PCAPC_ETHERTYPE_VLAN &&
            ether_type != PCAPC_ETHERTYPE_QINQ) {
            break;
        }

        if (len < l3_off + PCAPC_VLAN_TAG_LEN) {
            decision.reason = PCAPC_REASON_PARSE_ERROR;
            return decision;
        }

        ether_type = pcapc_load_be16(data + l3_off + 2u);
        l3_off += PCAPC_VLAN_TAG_LEN;
    }

    decision.l3_off = (pcapc_u16)l3_off;

    if (ether_type == PCAPC_ETHERTYPE_IPV4) {
        pcapc_u32 ipv4_off = l3_off;
        pcapc_u8 version_ihl;
        pcapc_u32 ipv4_hdr_len;
        pcapc_u8 l4_proto;
        pcapc_u16 frag_field;
        pcapc_u32 l4_off;

        if (len < ipv4_off + PCAPC_IPV4_MIN_HDR_LEN) {
            decision.reason = PCAPC_REASON_PARSE_ERROR;
            return decision;
        }

        version_ihl = data[ipv4_off];
        ipv4_hdr_len = (pcapc_u32)(version_ihl & 0x0Fu) * 4u;
        if ((version_ihl >> 4) != 4u || ipv4_hdr_len < PCAPC_IPV4_MIN_HDR_LEN) {
            decision.reason = PCAPC_REASON_PARSE_ERROR;
            return decision;
        }

        if (len < ipv4_off + ipv4_hdr_len) {
            decision.reason = PCAPC_REASON_PARSE_ERROR;
            return decision;
        }

        decision.reason = PCAPC_REASON_IPV4;
        decision.ip_proto = 4u;

        l4_proto = data[ipv4_off + 9u];
        frag_field = pcapc_load_be16(data + ipv4_off + 6u);
        if ((frag_field & 0x2000u) != 0u || (frag_field & 0x1FFFu) != 0u)
            return decision;

        l4_off = ipv4_off + ipv4_hdr_len;

        if (l4_proto == PCAPC_IPPROTO_TCP) {
            pcapc_u8 data_offset_words;
            pcapc_u32 tcp_hdr_len;
            pcapc_u32 payload_off;

            if (len < l4_off + PCAPC_TCP_MIN_HDR_LEN) {
                decision.reason = PCAPC_REASON_PARSE_ERROR;
                return decision;
            }

            data_offset_words = (pcapc_u8)(data[l4_off + 12u] >> 4);
            tcp_hdr_len = (pcapc_u32)data_offset_words * 4u;
            if (data_offset_words < 5u) {
                decision.reason = PCAPC_REASON_PARSE_ERROR;
                return decision;
            }

            if (len < l4_off + tcp_hdr_len) {
                decision.reason = PCAPC_REASON_PARSE_ERROR;
                return decision;
            }

            decision.reason = PCAPC_REASON_TCP;
            decision.l4_proto = PCAPC_IPPROTO_TCP;
            decision.l4_off = (pcapc_u16)l4_off;
            payload_off = l4_off + tcp_hdr_len;
            decision.payload_off = (pcapc_u16)payload_off;

            if (payload_off < len) {
                pcapc_u32 app_data_off;

                if (pcapc_find_tls_application_data_record_start(data, len, payload_off, &app_data_off)) {
                    pcapc_u32 tls_cap_len;

                    decision.reason = PCAPC_REASON_TLS_APP_DATA;
                    if (active_cfg->encrypted_snaplen > 0xffffffffu - app_data_off)
                        tls_cap_len = 0xffffffffu;
                    else
                        tls_cap_len = app_data_off + active_cfg->encrypted_snaplen;
                    tls_cap_len = pcapc_min_u32(tls_cap_len, len);
                    tls_cap_len = pcapc_min_u32(tls_cap_len, active_cfg->max_capture_len);
                    decision.cap_len = tls_cap_len;
                }
            }
            return decision;
        }

        if (l4_proto == PCAPC_IPPROTO_UDP) {
            if (len < l4_off + PCAPC_UDP_HDR_LEN) {
                decision.reason = PCAPC_REASON_PARSE_ERROR;
                return decision;
            }

            decision.reason = PCAPC_REASON_UDP;
            decision.l4_proto = PCAPC_IPPROTO_UDP;
            decision.l4_off = (pcapc_u16)l4_off;
            decision.payload_off = (pcapc_u16)(l4_off + PCAPC_UDP_HDR_LEN);
            return decision;
        }

        return decision;
    }

    if (ether_type == PCAPC_ETHERTYPE_IPV6) {
        pcapc_u32 ipv6_off = l3_off;
        pcapc_u32 vtc_flow;
        pcapc_u8 next_header;
        pcapc_u32 l4_off;

        if (len < ipv6_off + PCAPC_IPV6_HDR_LEN) {
            decision.reason = PCAPC_REASON_PARSE_ERROR;
            return decision;
        }

        vtc_flow = pcapc_load_be32(data + ipv6_off);
        if ((vtc_flow >> 28) != 6u) {
            decision.reason = PCAPC_REASON_PARSE_ERROR;
            return decision;
        }

        decision.reason = PCAPC_REASON_IPV6;
        decision.ip_proto = 6u;

        next_header = data[ipv6_off + 6u];
        l4_off = ipv6_off + PCAPC_IPV6_HDR_LEN;

        if (next_header == PCAPC_IPPROTO_TCP) {
            pcapc_u8 data_offset_words;
            pcapc_u32 tcp_hdr_len;
            pcapc_u32 payload_off;

            if (len < l4_off + PCAPC_TCP_MIN_HDR_LEN) {
                decision.reason = PCAPC_REASON_PARSE_ERROR;
                return decision;
            }

            data_offset_words = (pcapc_u8)(data[l4_off + 12u] >> 4);
            tcp_hdr_len = (pcapc_u32)data_offset_words * 4u;
            if (data_offset_words < 5u) {
                decision.reason = PCAPC_REASON_PARSE_ERROR;
                return decision;
            }

            if (len < l4_off + tcp_hdr_len) {
                decision.reason = PCAPC_REASON_PARSE_ERROR;
                return decision;
            }

            decision.reason = PCAPC_REASON_TCP;
            decision.l4_proto = PCAPC_IPPROTO_TCP;
            decision.l4_off = (pcapc_u16)l4_off;
            payload_off = l4_off + tcp_hdr_len;
            decision.payload_off = (pcapc_u16)payload_off;

            if (payload_off < len) {
                pcapc_u32 app_data_off;

                if (pcapc_find_tls_application_data_record_start(data, len, payload_off, &app_data_off)) {
                    pcapc_u32 tls_cap_len;

                    decision.reason = PCAPC_REASON_TLS_APP_DATA;
                    if (active_cfg->encrypted_snaplen > 0xffffffffu - app_data_off)
                        tls_cap_len = 0xffffffffu;
                    else
                        tls_cap_len = app_data_off + active_cfg->encrypted_snaplen;
                    tls_cap_len = pcapc_min_u32(tls_cap_len, len);
                    tls_cap_len = pcapc_min_u32(tls_cap_len, active_cfg->max_capture_len);
                    decision.cap_len = tls_cap_len;
                }
            }
            return decision;
        }

        if (next_header == PCAPC_IPPROTO_UDP) {
            if (len < l4_off + PCAPC_UDP_HDR_LEN) {
                decision.reason = PCAPC_REASON_PARSE_ERROR;
                return decision;
            }

            decision.reason = PCAPC_REASON_UDP;
            decision.l4_proto = PCAPC_IPPROTO_UDP;
            decision.l4_off = (pcapc_u16)l4_off;
            decision.payload_off = (pcapc_u16)(l4_off + PCAPC_UDP_HDR_LEN);
            return decision;
        }
    }

    return decision;
}

#undef PCAPC_INLINE
