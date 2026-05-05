#pragma once

#include <stdint.h>

struct pcapc_capture_config {
    uint32_t default_snaplen;
    uint32_t encrypted_snaplen;
    uint32_t max_capture_len;
    uint32_t flags;
};

enum pcapc_capture_reason {
    PCAPC_REASON_DEFAULT = 0,
    PCAPC_REASON_PARSE_ERROR,
    PCAPC_REASON_IPV4,
    PCAPC_REASON_IPV6,
    PCAPC_REASON_TCP,
    PCAPC_REASON_UDP,
    PCAPC_REASON_TLS_APP_DATA,
    PCAPC_REASON_QUIC_LONG,
    PCAPC_REASON_QUIC_SHORT_CANDIDATE
};

struct pcapc_capture_decision {
    uint32_t cap_len;
    uint16_t l3_off;
    uint16_t l4_off;
    uint16_t payload_off;
    uint8_t ip_proto;
    uint8_t l4_proto;
    uint8_t reason;
    uint8_t flags;
};

struct pcapc_capture_decision
pcapc_decide_l2_packet(const uint8_t *data,
                       uint32_t len,
                       const struct pcapc_capture_config *cfg);
