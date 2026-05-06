#include "packet_policy.h"

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
    PCAPC_IPPROTO_UDP = 17u
};

static uint16_t load_be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static uint32_t load_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) |
           (uint32_t)p[3];
}

static uint32_t min_u32(uint32_t a, uint32_t b)
{
    return a < b ? a : b;
}

static int is_tls_application_data_at_payload_start(const uint8_t *data,
                                                     uint32_t len,
                                                     uint32_t payload_off)
{
    uint8_t major;
    uint8_t minor;
    uint16_t record_len;

    if (payload_off >= len)
        return 0;

    if (len - payload_off < 5u)
        return 0;

    if (data[payload_off] != 0x17u)
        return 0;

    major = data[payload_off + 1u];
    minor = data[payload_off + 2u];
    if (major != 0x03u || minor < 0x01u || minor > 0x04u)
        return 0;

    record_len = load_be16(data + payload_off + 3u);
    if (record_len == 0u || record_len > 18432u)
        return 0;

    return 1;
}

struct pcapc_capture_decision
pcapc_decide_l2_packet(const uint8_t *data,
                       uint32_t len,
                       const struct pcapc_capture_config *cfg)
{
    static const struct pcapc_capture_config default_cfg = {
        256u,
        256u,
        256u,
        0u
    };

    const struct pcapc_capture_config *active_cfg = cfg ? cfg : &default_cfg;
    struct pcapc_capture_decision decision = {0};
    uint32_t l3_off;
    uint16_t ether_type;
    uint32_t vlan_count;

    decision.reason = PCAPC_REASON_DEFAULT;

    if (data == NULL || len == 0u)
        return decision;

    decision.cap_len = min_u32(len, active_cfg->default_snaplen);
    decision.cap_len = min_u32(decision.cap_len, active_cfg->max_capture_len);

    if (len < PCAPC_ETH_HDR_LEN) {
        decision.reason = PCAPC_REASON_PARSE_ERROR;
        return decision;
    }

    l3_off = PCAPC_ETH_HDR_LEN;
    ether_type = load_be16(data + 12u);

    for (vlan_count = 0u; vlan_count < PCAPC_MAX_VLAN_TAGS; vlan_count++) {
        if (ether_type != PCAPC_ETHERTYPE_VLAN &&
            ether_type != PCAPC_ETHERTYPE_QINQ) {
            break;
        }

        if (len < l3_off + PCAPC_VLAN_TAG_LEN) {
            decision.reason = PCAPC_REASON_PARSE_ERROR;
            return decision;
        }

        ether_type = load_be16(data + l3_off + 2u);
        l3_off += PCAPC_VLAN_TAG_LEN;
    }

    decision.l3_off = (uint16_t)l3_off;

    if (ether_type == PCAPC_ETHERTYPE_IPV4) {
        uint32_t ipv4_off = l3_off;
        uint8_t version_ihl;
        uint32_t ipv4_hdr_len;
        uint8_t l4_proto;
        uint16_t frag_field;
        uint32_t l4_off;

        if (len < ipv4_off + PCAPC_IPV4_MIN_HDR_LEN) {
            decision.reason = PCAPC_REASON_PARSE_ERROR;
            return decision;
        }

        version_ihl = data[ipv4_off];
        ipv4_hdr_len = (uint32_t)(version_ihl & 0x0Fu) * 4u;
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
        frag_field = load_be16(data + ipv4_off + 6u);
        if ((frag_field & 0x2000u) != 0u || (frag_field & 0x1FFFu) != 0u)
            return decision;

        l4_off = ipv4_off + ipv4_hdr_len;

        if (l4_proto == PCAPC_IPPROTO_TCP) {
            uint8_t data_offset_words;
            uint32_t tcp_hdr_len;
            uint32_t payload_off;

            if (len < l4_off + PCAPC_TCP_MIN_HDR_LEN) {
                decision.reason = PCAPC_REASON_PARSE_ERROR;
                return decision;
            }

            data_offset_words = (uint8_t)(data[l4_off + 12u] >> 4);
            tcp_hdr_len = (uint32_t)data_offset_words * 4u;
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
            decision.l4_off = (uint16_t)l4_off;
            payload_off = l4_off + tcp_hdr_len;
            decision.payload_off = (uint16_t)payload_off;

            if (is_tls_application_data_at_payload_start(data, len, payload_off)) {
                decision.reason = PCAPC_REASON_TLS_APP_DATA;
                decision.cap_len = min_u32(len, active_cfg->encrypted_snaplen);
                decision.cap_len = min_u32(decision.cap_len, active_cfg->max_capture_len);
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
            decision.l4_off = (uint16_t)l4_off;
            decision.payload_off = (uint16_t)(l4_off + PCAPC_UDP_HDR_LEN);
            return decision;
        }

        return decision;
    }

    if (ether_type == PCAPC_ETHERTYPE_IPV6) {
        uint32_t ipv6_off = l3_off;
        uint32_t vtc_flow;
        uint8_t next_header;
        uint32_t l4_off;

        if (len < ipv6_off + PCAPC_IPV6_HDR_LEN) {
            decision.reason = PCAPC_REASON_PARSE_ERROR;
            return decision;
        }

        vtc_flow = load_be32(data + ipv6_off);
        if ((vtc_flow >> 28) != 6u) {
            decision.reason = PCAPC_REASON_PARSE_ERROR;
            return decision;
        }

        decision.reason = PCAPC_REASON_IPV6;
        decision.ip_proto = 6u;

        next_header = data[ipv6_off + 6u];
        l4_off = ipv6_off + PCAPC_IPV6_HDR_LEN;

        if (next_header == PCAPC_IPPROTO_TCP) {
            uint8_t data_offset_words;
            uint32_t tcp_hdr_len;
            uint32_t payload_off;

            if (len < l4_off + PCAPC_TCP_MIN_HDR_LEN) {
                decision.reason = PCAPC_REASON_PARSE_ERROR;
                return decision;
            }

            data_offset_words = (uint8_t)(data[l4_off + 12u] >> 4);
            tcp_hdr_len = (uint32_t)data_offset_words * 4u;
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
            decision.l4_off = (uint16_t)l4_off;
            payload_off = l4_off + tcp_hdr_len;
            decision.payload_off = (uint16_t)payload_off;

            if (is_tls_application_data_at_payload_start(data, len, payload_off)) {
                decision.reason = PCAPC_REASON_TLS_APP_DATA;
                decision.cap_len = min_u32(len, active_cfg->encrypted_snaplen);
                decision.cap_len = min_u32(decision.cap_len, active_cfg->max_capture_len);
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
            decision.l4_off = (uint16_t)l4_off;
            decision.payload_off = (uint16_t)(l4_off + PCAPC_UDP_HDR_LEN);
            return decision;
        }
    }

    return decision;
}
