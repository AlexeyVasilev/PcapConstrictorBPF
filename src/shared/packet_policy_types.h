#pragma once

#ifdef PCAPC_BPF
typedef __u8 pcapc_u8;
typedef __u16 pcapc_u16;
typedef __u32 pcapc_u32;
typedef __u64 pcapc_u64;
#else
#include <stdint.h>
typedef uint8_t pcapc_u8;
typedef uint16_t pcapc_u16;
typedef uint32_t pcapc_u32;
typedef uint64_t pcapc_u64;
#endif

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

struct pcapc_capture_config {
    pcapc_u32 default_snaplen;
    /* For encrypted TLS/QUIC policy decisions, encrypted_snaplen is the
     * number of bytes to keep starting at the first encrypted/protected
     * record or payload, not the total packet cap length.
     */
    pcapc_u32 encrypted_snaplen;
    pcapc_u32 max_capture_len;
    pcapc_u32 flags;
};

struct pcapc_capture_decision {
    pcapc_u32 cap_len;
    pcapc_u16 l3_off;
    pcapc_u16 l4_off;
    pcapc_u16 payload_off;
    pcapc_u8 ip_proto;
    pcapc_u8 l4_proto;
    pcapc_u8 reason;
    pcapc_u8 flags;
};
