#include <stdint.h>
#include <stdio.h>

#include "packet_policy.h"
/* sample_packets.inc is intentionally generated-style; real corpuses can come
 * from the external PcapPacketsToArrays utility, while expected analyzer
 * behavior stays defined here in the tests.
 */
#include "fixtures/generated/sample_packets.inc"
#include "fixtures/generated/tls_data_1_packets.inc"

enum {
    ETH_HDR_LEN = 14u,
    VLAN_TAG_LEN = 4u,
    IPV4_HDR_LEN = 20u,
    IPV6_HDR_LEN = 40u,
    TCP_HDR_LEN = 20u,
    UDP_HDR_LEN = 8u,
    ETHERTYPE_IPV4 = 0x0800u,
    ETHERTYPE_IPV6 = 0x86DDu,
    ETHERTYPE_VLAN = 0x8100u,
    IPPROTO_TCP = 6u,
    IPPROTO_UDP = 17u
};

struct test_state {
    uint32_t total;
    uint32_t failed;
};

typedef struct GeneratedPolicyCase {
    const char *test_name;
    const char *sample_name;
    const PcapPacketSample *samples;
    size_t sample_count;
    struct pcapc_capture_config config;
    uint32_t expected_cap_len;
    uint8_t expected_reason;
    uint8_t expected_ip_proto;
    uint8_t expected_l4_proto;
    uint16_t expected_l3_off;
    uint16_t expected_l4_off;
    uint16_t expected_payload_off;
} GeneratedPolicyCase;

static int string_equals(const char *a, const char *b)
{
    while (*a != '\0' && *b != '\0') {
        if (*a != *b)
            return 0;
        a++;
        b++;
    }

    return *a == *b;
}

static const PcapPacketSample *find_packet_sample_in(const PcapPacketSample *samples,
                                                     size_t sample_count,
                                                     const char *name)
{
    size_t i;

    for (i = 0u; i < sample_count; i++) {
        if (string_equals(samples[i].name, name))
            return &samples[i];
    }

    return NULL;
}

static void store_be16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)(value >> 8);
    p[1] = (uint8_t)(value & 0xffu);
}

static void expect_u32(struct test_state *state,
                       const char *name,
                       uint32_t actual,
                       uint32_t expected)
{
    state->total++;

    if (actual != expected) {
        state->failed++;
        printf("FAIL %s actual=%u expected=%u\n", name, actual, expected);
    }
}

static void expect_reason(struct test_state *state,
                          const char *name,
                          uint8_t actual,
                          uint8_t expected)
{
    state->total++;

    if (actual != expected) {
        state->failed++;
        printf("FAIL %s actual=%u expected=%u\n",
               name,
               (unsigned)actual,
               (unsigned)expected);
    }
}

static void expect_u16(struct test_state *state,
                       const char *name,
                       uint16_t actual,
                       uint16_t expected)
{
    state->total++;

    if (actual != expected) {
        state->failed++;
        printf("FAIL %s actual=%u expected=%u\n",
               name,
               (unsigned)actual,
               (unsigned)expected);
    }
}

static void expect_u8(struct test_state *state,
                      const char *name,
                      uint8_t actual,
                      uint8_t expected)
{
    state->total++;

    if (actual != expected) {
        state->failed++;
        printf("FAIL %s actual=%u expected=%u\n",
               name,
               (unsigned)actual,
               (unsigned)expected);
    }
}

static void fail_generated_missing_sample(struct test_state *state,
                                          const char *test_name,
                                          const char *sample_name)
{
    state->total++;
    state->failed++;
    printf("FAIL %s sample=%s field=exists expected=1 actual=0\n",
           test_name,
           sample_name);
}

static void expect_generated_u32(struct test_state *state,
                                 const char *test_name,
                                 const char *sample_name,
                                 const char *field_name,
                                 uint32_t actual,
                                 uint32_t expected)
{
    state->total++;

    if (actual != expected) {
        state->failed++;
        printf("FAIL %s sample=%s field=%s expected=%u actual=%u\n",
               test_name,
               sample_name,
               field_name,
               expected,
               actual);
    }
}

static void expect_generated_u16(struct test_state *state,
                                 const char *test_name,
                                 const char *sample_name,
                                 const char *field_name,
                                 uint16_t actual,
                                 uint16_t expected)
{
    state->total++;

    if (actual != expected) {
        state->failed++;
        printf("FAIL %s sample=%s field=%s expected=%u actual=%u\n",
               test_name,
               sample_name,
               field_name,
               (unsigned)expected,
               (unsigned)actual);
    }
}

static void expect_generated_u8(struct test_state *state,
                                const char *test_name,
                                const char *sample_name,
                                const char *field_name,
                                uint8_t actual,
                                uint8_t expected)
{
    state->total++;

    if (actual != expected) {
        state->failed++;
        printf("FAIL %s sample=%s field=%s expected=%u actual=%u\n",
               test_name,
               sample_name,
               field_name,
               (unsigned)expected,
               (unsigned)actual);
    }
}

static void expect_generated_ptr_not_null(struct test_state *state,
                                          const char *test_name,
                                          const char *sample_name,
                                          const char *field_name,
                                          const void *actual)
{
    state->total++;

    if (actual == NULL) {
        state->failed++;
        printf("FAIL %s sample=%s field=%s expected=non-null actual=null\n",
               test_name,
               sample_name,
               field_name);
    }
}

static void fill_eth_header(uint8_t *packet, uint16_t ether_type)
{
    uint32_t i;

    for (i = 0u; i < 6u; i++) {
        packet[i] = (uint8_t)(0x10u + i);
        packet[6u + i] = (uint8_t)(0x20u + i);
    }

    store_be16(packet + 12u, ether_type);
}

static void fill_vlan_tag(uint8_t *packet, uint16_t tci, uint16_t inner_type)
{
    store_be16(packet + 14u, tci);
    store_be16(packet + 16u, inner_type);
}

static void fill_ipv4_header(uint8_t *packet,
                             uint32_t l3_off,
                             uint8_t protocol,
                             uint16_t frag_field)
{
    uint32_t i;

    for (i = 0u; i < IPV4_HDR_LEN; i++)
        packet[l3_off + i] = 0u;

    packet[l3_off] = 0x45u;
    packet[l3_off + 8u] = 64u;
    packet[l3_off + 9u] = protocol;
    store_be16(packet + l3_off + 2u, IPV4_HDR_LEN + ((protocol == IPPROTO_UDP) ? UDP_HDR_LEN : TCP_HDR_LEN));
    store_be16(packet + l3_off + 6u, frag_field);
}

static void fill_ipv6_header(uint8_t *packet,
                             uint32_t l3_off,
                             uint8_t next_header)
{
    uint32_t i;
    uint16_t payload_len;

    for (i = 0u; i < IPV6_HDR_LEN; i++)
        packet[l3_off + i] = 0u;

    packet[l3_off] = 0x60u;
    payload_len = (next_header == IPPROTO_UDP) ? UDP_HDR_LEN : TCP_HDR_LEN;
    store_be16(packet + l3_off + 4u, payload_len);
    packet[l3_off + 6u] = next_header;
    packet[l3_off + 7u] = 64u;
}

static void fill_tcp_header(uint8_t *packet, uint32_t l4_off)
{
    uint32_t i;

    for (i = 0u; i < TCP_HDR_LEN; i++)
        packet[l4_off + i] = 0u;

    packet[l4_off + 12u] = 0x50u;
}

static void fill_bytes(uint8_t *packet,
                       uint32_t off,
                       const uint8_t *src,
                       uint32_t count)
{
    uint32_t i;

    for (i = 0u; i < count; i++)
        packet[off + i] = src[i];
}

static void fill_udp_header(uint8_t *packet, uint32_t l4_off)
{
    uint32_t i;

    for (i = 0u; i < UDP_HDR_LEN; i++)
        packet[l4_off + i] = 0u;

    store_be16(packet + l4_off + 4u, UDP_HDR_LEN);
}

static void run_generated_policy_case(struct test_state *state,
                                      const GeneratedPolicyCase *test_case)
{
    const PcapPacketSample *sample;
    struct pcapc_capture_decision decision;

    sample = find_packet_sample_in(test_case->samples,
                                   test_case->sample_count,
                                   test_case->sample_name);
    if (sample == NULL) {
        fail_generated_missing_sample(state, test_case->test_name, test_case->sample_name);
        return;
    }

    expect_generated_ptr_not_null(state,
                                  test_case->test_name,
                                  test_case->sample_name,
                                  "data",
                                  sample->data);
    expect_generated_u32(state,
                         test_case->test_name,
                         test_case->sample_name,
                         "linktype",
                         sample->linktype,
                         1u);
    expect_generated_u32(state,
                         test_case->test_name,
                         test_case->sample_name,
                         "captured_len",
                         sample->captured_len,
                         sample->original_len);
    expect_generated_u32(state,
                         test_case->test_name,
                         test_case->sample_name,
                         "size",
                         (uint32_t)sample->size,
                         sample->captured_len);

    decision = pcapc_decide_l2_packet(sample->data,
                                      (uint32_t)sample->size,
                                      &test_case->config);

    expect_generated_u32(state,
                         test_case->test_name,
                         test_case->sample_name,
                         "cap_len",
                         decision.cap_len,
                         test_case->expected_cap_len);
    expect_generated_u8(state,
                        test_case->test_name,
                        test_case->sample_name,
                        "reason",
                        decision.reason,
                        test_case->expected_reason);
    expect_generated_u8(state,
                        test_case->test_name,
                        test_case->sample_name,
                        "ip_proto",
                        decision.ip_proto,
                        test_case->expected_ip_proto);
    expect_generated_u8(state,
                        test_case->test_name,
                        test_case->sample_name,
                        "l4_proto",
                        decision.l4_proto,
                        test_case->expected_l4_proto);
    expect_generated_u16(state,
                         test_case->test_name,
                         test_case->sample_name,
                         "l3_off",
                         decision.l3_off,
                         test_case->expected_l3_off);
    expect_generated_u16(state,
                         test_case->test_name,
                         test_case->sample_name,
                         "l4_off",
                         decision.l4_off,
                         test_case->expected_l4_off);
    expect_generated_u16(state,
                         test_case->test_name,
                         test_case->sample_name,
                         "payload_off",
                         decision.payload_off,
                         test_case->expected_payload_off);
}

int main(void)
{
    struct test_state state = {0};
    static const GeneratedPolicyCase generated_cases[] = {
        {
            "generated ipv4 tcp",
            "sample_ipv4_tcp",
            pcap_packet_samples,
            pcap_packet_samples_count,
            {256u, 256u, 2048u, 0u},
            ETH_HDR_LEN + IPV4_HDR_LEN + TCP_HDR_LEN,
            PCAPC_REASON_TCP,
            4u,
            IPPROTO_TCP,
            ETH_HDR_LEN,
            ETH_HDR_LEN + IPV4_HDR_LEN,
            ETH_HDR_LEN + IPV4_HDR_LEN + TCP_HDR_LEN
        },
        {
            "generated ipv4 udp",
            "sample_ipv4_udp",
            pcap_packet_samples,
            pcap_packet_samples_count,
            {256u, 256u, 2048u, 0u},
            ETH_HDR_LEN + IPV4_HDR_LEN + UDP_HDR_LEN,
            PCAPC_REASON_UDP,
            4u,
            IPPROTO_UDP,
            ETH_HDR_LEN,
            ETH_HDR_LEN + IPV4_HDR_LEN,
            ETH_HDR_LEN + IPV4_HDR_LEN + UDP_HDR_LEN
        },
        {
            "real tls packet 1 syn",
            "tls_data_1__packet_1",
            tls_data_1_pcap_packet_samples,
            tls_data_1_pcap_packet_samples_count,
            {4096u, 8u, 4096u, 0u},
            66u,
            PCAPC_REASON_TCP,
            4u,
            IPPROTO_TCP,
            ETH_HDR_LEN,
            ETH_HDR_LEN + IPV4_HDR_LEN,
            66u
        },
        {
            "real tls packet 4 clienthello",
            "tls_data_1__packet_4",
            tls_data_1_pcap_packet_samples,
            tls_data_1_pcap_packet_samples_count,
            {4096u, 8u, 4096u, 0u},
            720u,
            PCAPC_REASON_TCP,
            4u,
            IPPROTO_TCP,
            ETH_HDR_LEN,
            ETH_HDR_LEN + IPV4_HDR_LEN,
            ETH_HDR_LEN + IPV4_HDR_LEN + TCP_HDR_LEN
        },
        /* These are active PcapConstrictor-style expectations.
         * The TLS scanner preserves all complete TLS records before the first
         * Application Data record, plus encrypted_snaplen bytes from the
         * first Application Data record.
         *
         * - packet 1  TCP SYN                                      66 / 66
         * - packet 4  TLS ClientHello                              720 / 720
         * - packet 6  ServerHello + ChangeCipherSpec + AppData     199 / 2978
         * - packet 9  ChangeCipherSpec + AppData                   68 / 118
         * - packet 14 TLS Application Data                         66 / 145
         *
         * packet #6 AppData starts at offset 191, encrypted_snaplen is 8,
         * so cap_len is 191 + 8 = 199.
         * packet #9 AppData starts at offset 60, encrypted_snaplen is 8,
         * so cap_len is 60 + 8 = 68.
         * packet #14 AppData starts at offset 58, encrypted_snaplen is 8,
         * so cap_len is 58 + 8 = 66.
         */
        {
            "real tls packet 6 serverhello ccs appdata",
            "tls_data_1__packet_6",
            tls_data_1_pcap_packet_samples,
            tls_data_1_pcap_packet_samples_count,
            {4096u, 8u, 4096u, 0u},
            199u,
            PCAPC_REASON_TLS_APP_DATA,
            4u,
            IPPROTO_TCP,
            ETH_HDR_LEN + VLAN_TAG_LEN,
            ETH_HDR_LEN + VLAN_TAG_LEN + IPV4_HDR_LEN,
            ETH_HDR_LEN + VLAN_TAG_LEN + IPV4_HDR_LEN + TCP_HDR_LEN
        },
        {
            "real tls packet 9 ccs appdata",
            "tls_data_1__packet_9",
            tls_data_1_pcap_packet_samples,
            tls_data_1_pcap_packet_samples_count,
            {4096u, 8u, 4096u, 0u},
            68u,
            PCAPC_REASON_TLS_APP_DATA,
            4u,
            IPPROTO_TCP,
            ETH_HDR_LEN,
            ETH_HDR_LEN + IPV4_HDR_LEN,
            ETH_HDR_LEN + IPV4_HDR_LEN + TCP_HDR_LEN
        },
        {
            "real tls packet 14 appdata",
            "tls_data_1__packet_14",
            tls_data_1_pcap_packet_samples,
            tls_data_1_pcap_packet_samples_count,
            {4096u, 8u, 4096u, 0u},
            66u,
            PCAPC_REASON_TLS_APP_DATA,
            4u,
            IPPROTO_TCP,
            ETH_HDR_LEN + VLAN_TAG_LEN,
            ETH_HDR_LEN + VLAN_TAG_LEN + IPV4_HDR_LEN,
            ETH_HDR_LEN + VLAN_TAG_LEN + IPV4_HDR_LEN + TCP_HDR_LEN
        }
    };
    uint8_t packet_100[100] = {0};
    uint8_t packet_1500[1500] = {0};
    uint8_t packet_4096[4096] = {0};
    uint8_t eth_ipv4_tcp[ETH_HDR_LEN + IPV4_HDR_LEN + TCP_HDR_LEN] = {0};
    uint8_t eth_ipv4_udp[ETH_HDR_LEN + IPV4_HDR_LEN + UDP_HDR_LEN] = {0};
    uint8_t eth_ipv6_tcp[ETH_HDR_LEN + IPV6_HDR_LEN + TCP_HDR_LEN] = {0};
    uint8_t eth_ipv6_udp[ETH_HDR_LEN + IPV6_HDR_LEN + UDP_HDR_LEN] = {0};
    uint8_t vlan_ipv4_tcp[ETH_HDR_LEN + VLAN_TAG_LEN + IPV4_HDR_LEN + TCP_HDR_LEN] = {0};
    uint8_t truncated_eth[10] = {0};
    uint8_t truncated_ipv4[ETH_HDR_LEN + 10] = {0};
    uint8_t ipv4_frag_udp[ETH_HDR_LEN + IPV4_HDR_LEN + UDP_HDR_LEN] = {0};
    uint8_t ipv4_tcp_tls_appdata[ETH_HDR_LEN + IPV4_HDR_LEN + TCP_HDR_LEN + 5 + 16 + 32] = {0};
    uint8_t ipv4_tcp_tls_handshake[ETH_HDR_LEN + IPV4_HDR_LEN + TCP_HDR_LEN + 5 + 16] = {0};
    uint8_t ipv4_tcp_tls_bad_version[ETH_HDR_LEN + IPV4_HDR_LEN + TCP_HDR_LEN + 5 + 16] = {0};
    uint8_t ipv4_tcp_tls_too_short[ETH_HDR_LEN + IPV4_HDR_LEN + TCP_HDR_LEN + 4] = {0};
    uint8_t ipv4_tcp_tls_multi_record[ETH_HDR_LEN + IPV4_HDR_LEN + TCP_HDR_LEN + 10 + 6 + 5 + 16] = {0};
    size_t generated_case_index;
    struct pcapc_capture_decision decision;
    struct pcapc_capture_config cfg;

    decision = pcapc_decide_l2_packet(packet_100, 0u, NULL);
    expect_u32(&state, "empty packet cap_len", decision.cap_len, 0u);
    expect_reason(&state, "empty packet reason", decision.reason, PCAPC_REASON_DEFAULT);

    cfg.default_snaplen = 256u;
    cfg.encrypted_snaplen = 256u;
    cfg.max_capture_len = 256u;
    cfg.flags = 0u;
    decision = pcapc_decide_l2_packet(packet_100, 100u, &cfg);
    expect_u32(&state, "len 100 snaplen 256", decision.cap_len, 100u);

    cfg.default_snaplen = 256u;
    cfg.encrypted_snaplen = 256u;
    cfg.max_capture_len = 2048u;
    cfg.flags = 0u;
    decision = pcapc_decide_l2_packet(packet_1500, 1500u, &cfg);
    expect_u32(&state, "len 1500 snaplen 256 max 2048", decision.cap_len, 256u);

    cfg.default_snaplen = 4096u;
    cfg.encrypted_snaplen = 4096u;
    cfg.max_capture_len = 2048u;
    cfg.flags = 0u;
    decision = pcapc_decide_l2_packet(packet_1500, 1500u, &cfg);
    expect_u32(&state, "len 1500 snaplen 4096 max 2048", decision.cap_len, 1500u);

    cfg.default_snaplen = 4096u;
    cfg.encrypted_snaplen = 4096u;
    cfg.max_capture_len = 2048u;
    cfg.flags = 0u;
    decision = pcapc_decide_l2_packet(packet_4096, 4096u, &cfg);
    expect_u32(&state, "len 4096 snaplen 4096 max 2048", decision.cap_len, 2048u);

    decision = pcapc_decide_l2_packet(packet_1500, 1500u, NULL);
    expect_u32(&state, "null cfg safe defaults", decision.cap_len, 256u);

    cfg.default_snaplen = 256u;
    cfg.encrypted_snaplen = 256u;
    cfg.max_capture_len = 2048u;
    cfg.flags = 0u;

    fill_eth_header(eth_ipv4_tcp, ETHERTYPE_IPV4);
    fill_ipv4_header(eth_ipv4_tcp, ETH_HDR_LEN, IPPROTO_TCP, 0u);
    fill_tcp_header(eth_ipv4_tcp, ETH_HDR_LEN + IPV4_HDR_LEN);
    decision = pcapc_decide_l2_packet(eth_ipv4_tcp, sizeof(eth_ipv4_tcp), &cfg);
    expect_u32(&state, "eth ipv4 tcp cap_len", decision.cap_len, sizeof(eth_ipv4_tcp));
    expect_reason(&state, "eth ipv4 tcp reason", decision.reason, PCAPC_REASON_TCP);
    expect_u8(&state, "eth ipv4 tcp ip_proto", decision.ip_proto, 4u);
    expect_u8(&state, "eth ipv4 tcp l4_proto", decision.l4_proto, IPPROTO_TCP);
    expect_u16(&state, "eth ipv4 tcp l3_off", decision.l3_off, ETH_HDR_LEN);
    expect_u16(&state, "eth ipv4 tcp l4_off", decision.l4_off, ETH_HDR_LEN + IPV4_HDR_LEN);
    expect_u16(&state, "eth ipv4 tcp payload_off", decision.payload_off, ETH_HDR_LEN + IPV4_HDR_LEN + TCP_HDR_LEN);

    fill_eth_header(eth_ipv4_udp, ETHERTYPE_IPV4);
    fill_ipv4_header(eth_ipv4_udp, ETH_HDR_LEN, IPPROTO_UDP, 0u);
    fill_udp_header(eth_ipv4_udp, ETH_HDR_LEN + IPV4_HDR_LEN);
    decision = pcapc_decide_l2_packet(eth_ipv4_udp, sizeof(eth_ipv4_udp), &cfg);
    expect_u32(&state, "eth ipv4 udp cap_len", decision.cap_len, sizeof(eth_ipv4_udp));
    expect_reason(&state, "eth ipv4 udp reason", decision.reason, PCAPC_REASON_UDP);
    expect_u8(&state, "eth ipv4 udp ip_proto", decision.ip_proto, 4u);
    expect_u8(&state, "eth ipv4 udp l4_proto", decision.l4_proto, IPPROTO_UDP);
    expect_u16(&state, "eth ipv4 udp l3_off", decision.l3_off, ETH_HDR_LEN);
    expect_u16(&state, "eth ipv4 udp l4_off", decision.l4_off, ETH_HDR_LEN + IPV4_HDR_LEN);
    expect_u16(&state, "eth ipv4 udp payload_off", decision.payload_off, ETH_HDR_LEN + IPV4_HDR_LEN + UDP_HDR_LEN);

    fill_eth_header(eth_ipv6_tcp, ETHERTYPE_IPV6);
    fill_ipv6_header(eth_ipv6_tcp, ETH_HDR_LEN, IPPROTO_TCP);
    fill_tcp_header(eth_ipv6_tcp, ETH_HDR_LEN + IPV6_HDR_LEN);
    decision = pcapc_decide_l2_packet(eth_ipv6_tcp, sizeof(eth_ipv6_tcp), &cfg);
    expect_u32(&state, "eth ipv6 tcp cap_len", decision.cap_len, sizeof(eth_ipv6_tcp));
    expect_reason(&state, "eth ipv6 tcp reason", decision.reason, PCAPC_REASON_TCP);
    expect_u8(&state, "eth ipv6 tcp ip_proto", decision.ip_proto, 6u);
    expect_u8(&state, "eth ipv6 tcp l4_proto", decision.l4_proto, IPPROTO_TCP);
    expect_u16(&state, "eth ipv6 tcp l3_off", decision.l3_off, ETH_HDR_LEN);
    expect_u16(&state, "eth ipv6 tcp l4_off", decision.l4_off, ETH_HDR_LEN + IPV6_HDR_LEN);
    expect_u16(&state, "eth ipv6 tcp payload_off", decision.payload_off, ETH_HDR_LEN + IPV6_HDR_LEN + TCP_HDR_LEN);

    fill_eth_header(eth_ipv6_udp, ETHERTYPE_IPV6);
    fill_ipv6_header(eth_ipv6_udp, ETH_HDR_LEN, IPPROTO_UDP);
    fill_udp_header(eth_ipv6_udp, ETH_HDR_LEN + IPV6_HDR_LEN);
    decision = pcapc_decide_l2_packet(eth_ipv6_udp, sizeof(eth_ipv6_udp), &cfg);
    expect_u32(&state, "eth ipv6 udp cap_len", decision.cap_len, sizeof(eth_ipv6_udp));
    expect_reason(&state, "eth ipv6 udp reason", decision.reason, PCAPC_REASON_UDP);
    expect_u8(&state, "eth ipv6 udp ip_proto", decision.ip_proto, 6u);
    expect_u8(&state, "eth ipv6 udp l4_proto", decision.l4_proto, IPPROTO_UDP);
    expect_u16(&state, "eth ipv6 udp l3_off", decision.l3_off, ETH_HDR_LEN);
    expect_u16(&state, "eth ipv6 udp l4_off", decision.l4_off, ETH_HDR_LEN + IPV6_HDR_LEN);
    expect_u16(&state, "eth ipv6 udp payload_off", decision.payload_off, ETH_HDR_LEN + IPV6_HDR_LEN + UDP_HDR_LEN);

    fill_eth_header(vlan_ipv4_tcp, ETHERTYPE_VLAN);
    fill_vlan_tag(vlan_ipv4_tcp, 1u, ETHERTYPE_IPV4);
    fill_ipv4_header(vlan_ipv4_tcp, ETH_HDR_LEN + VLAN_TAG_LEN, IPPROTO_TCP, 0u);
    fill_tcp_header(vlan_ipv4_tcp, ETH_HDR_LEN + VLAN_TAG_LEN + IPV4_HDR_LEN);
    decision = pcapc_decide_l2_packet(vlan_ipv4_tcp, sizeof(vlan_ipv4_tcp), &cfg);
    expect_u32(&state, "vlan ipv4 tcp cap_len", decision.cap_len, sizeof(vlan_ipv4_tcp));
    expect_reason(&state, "vlan ipv4 tcp reason", decision.reason, PCAPC_REASON_TCP);
    expect_u8(&state, "vlan ipv4 tcp ip_proto", decision.ip_proto, 4u);
    expect_u8(&state, "vlan ipv4 tcp l4_proto", decision.l4_proto, IPPROTO_TCP);
    expect_u16(&state, "vlan ipv4 tcp l3_off", decision.l3_off, ETH_HDR_LEN + VLAN_TAG_LEN);
    expect_u16(&state, "vlan ipv4 tcp l4_off", decision.l4_off, ETH_HDR_LEN + VLAN_TAG_LEN + IPV4_HDR_LEN);
    expect_u16(&state, "vlan ipv4 tcp payload_off", decision.payload_off, ETH_HDR_LEN + VLAN_TAG_LEN + IPV4_HDR_LEN + TCP_HDR_LEN);

    decision = pcapc_decide_l2_packet(truncated_eth, sizeof(truncated_eth), &cfg);
    expect_u32(&state, "truncated eth cap_len", decision.cap_len, sizeof(truncated_eth));
    expect_reason(&state, "truncated eth reason", decision.reason, PCAPC_REASON_PARSE_ERROR);
    expect_u8(&state, "truncated eth ip_proto", decision.ip_proto, 0u);
    expect_u8(&state, "truncated eth l4_proto", decision.l4_proto, 0u);

    fill_eth_header(truncated_ipv4, ETHERTYPE_IPV4);
    decision = pcapc_decide_l2_packet(truncated_ipv4, sizeof(truncated_ipv4), &cfg);
    expect_u32(&state, "truncated ipv4 cap_len", decision.cap_len, sizeof(truncated_ipv4));
    expect_reason(&state, "truncated ipv4 reason", decision.reason, PCAPC_REASON_PARSE_ERROR);
    expect_u16(&state, "truncated ipv4 l3_off", decision.l3_off, ETH_HDR_LEN);

    fill_eth_header(ipv4_frag_udp, ETHERTYPE_IPV4);
    fill_ipv4_header(ipv4_frag_udp, ETH_HDR_LEN, IPPROTO_UDP, 0x2000u);
    fill_udp_header(ipv4_frag_udp, ETH_HDR_LEN + IPV4_HDR_LEN);
    decision = pcapc_decide_l2_packet(ipv4_frag_udp, sizeof(ipv4_frag_udp), &cfg);
    expect_u32(&state, "ipv4 frag udp cap_len", decision.cap_len, sizeof(ipv4_frag_udp));
    expect_reason(&state, "ipv4 frag udp reason", decision.reason, PCAPC_REASON_IPV4);
    expect_u8(&state, "ipv4 frag udp ip_proto", decision.ip_proto, 4u);
    expect_u8(&state, "ipv4 frag udp l4_proto", decision.l4_proto, 0u);
    expect_u16(&state, "ipv4 frag udp l3_off", decision.l3_off, ETH_HDR_LEN);
    expect_u16(&state, "ipv4 frag udp l4_off", decision.l4_off, 0u);
    expect_u16(&state, "ipv4 frag udp payload_off", decision.payload_off, 0u);

    cfg.default_snaplen = 2048u;
    cfg.encrypted_snaplen = 64u;
    cfg.max_capture_len = 2048u;
    cfg.flags = 0u;

    fill_eth_header( ipv4_tcp_tls_appdata, ETHERTYPE_IPV4);
    fill_ipv4_header(ipv4_tcp_tls_appdata, ETH_HDR_LEN, IPPROTO_TCP, 0u);
    fill_tcp_header(ipv4_tcp_tls_appdata, ETH_HDR_LEN + IPV4_HDR_LEN);
    {
        static const uint8_t tls_appdata_record[] = {
            0x17, 0x03, 0x03, 0x00, 0x10,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
        };
        fill_bytes(ipv4_tcp_tls_appdata,
                   ETH_HDR_LEN + IPV4_HDR_LEN + TCP_HDR_LEN,
                   tls_appdata_record,
                   sizeof(tls_appdata_record));
    }
    decision = pcapc_decide_l2_packet(ipv4_tcp_tls_appdata, sizeof(ipv4_tcp_tls_appdata), &cfg);
    expect_u32(&state, "ipv4 tcp tls appdata cap_len", decision.cap_len, sizeof(ipv4_tcp_tls_appdata));
    expect_reason(&state, "ipv4 tcp tls appdata reason", decision.reason, PCAPC_REASON_TLS_APP_DATA);
    expect_u8(&state, "ipv4 tcp tls appdata ip_proto", decision.ip_proto, 4u);
    expect_u8(&state, "ipv4 tcp tls appdata l4_proto", decision.l4_proto, IPPROTO_TCP);
    expect_u16(&state, "ipv4 tcp tls appdata l3_off", decision.l3_off, ETH_HDR_LEN);
    expect_u16(&state, "ipv4 tcp tls appdata l4_off", decision.l4_off, ETH_HDR_LEN + IPV4_HDR_LEN);
    expect_u16(&state, "ipv4 tcp tls appdata payload_off", decision.payload_off, ETH_HDR_LEN + IPV4_HDR_LEN + TCP_HDR_LEN);

    fill_eth_header(ipv4_tcp_tls_handshake, ETHERTYPE_IPV4);
    fill_ipv4_header(ipv4_tcp_tls_handshake, ETH_HDR_LEN, IPPROTO_TCP, 0u);
    fill_tcp_header(ipv4_tcp_tls_handshake, ETH_HDR_LEN + IPV4_HDR_LEN);
    {
        static const uint8_t tls_handshake_record[] = {
            0x16, 0x03, 0x03, 0x00, 0x10,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
        };
        fill_bytes(ipv4_tcp_tls_handshake,
                   ETH_HDR_LEN + IPV4_HDR_LEN + TCP_HDR_LEN,
                   tls_handshake_record,
                   sizeof(tls_handshake_record));
    }
    decision = pcapc_decide_l2_packet(ipv4_tcp_tls_handshake, sizeof(ipv4_tcp_tls_handshake), &cfg);
    expect_u32(&state, "ipv4 tcp tls handshake cap_len", decision.cap_len, sizeof(ipv4_tcp_tls_handshake));
    expect_reason(&state, "ipv4 tcp tls handshake reason", decision.reason, PCAPC_REASON_TCP);
    expect_u8(&state, "ipv4 tcp tls handshake ip_proto", decision.ip_proto, 4u);
    expect_u8(&state, "ipv4 tcp tls handshake l4_proto", decision.l4_proto, IPPROTO_TCP);
    expect_u16(&state, "ipv4 tcp tls handshake l3_off", decision.l3_off, ETH_HDR_LEN);
    expect_u16(&state, "ipv4 tcp tls handshake l4_off", decision.l4_off, ETH_HDR_LEN + IPV4_HDR_LEN);
    expect_u16(&state, "ipv4 tcp tls handshake payload_off", decision.payload_off, ETH_HDR_LEN + IPV4_HDR_LEN + TCP_HDR_LEN);

    fill_eth_header(ipv4_tcp_tls_bad_version, ETHERTYPE_IPV4);
    fill_ipv4_header(ipv4_tcp_tls_bad_version, ETH_HDR_LEN, IPPROTO_TCP, 0u);
    fill_tcp_header(ipv4_tcp_tls_bad_version, ETH_HDR_LEN + IPV4_HDR_LEN);
    {
        static const uint8_t tls_bad_version_record[] = {
            0x17, 0x02, 0x00, 0x00, 0x10,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
        };
        fill_bytes(ipv4_tcp_tls_bad_version,
                   ETH_HDR_LEN + IPV4_HDR_LEN + TCP_HDR_LEN,
                   tls_bad_version_record,
                   sizeof(tls_bad_version_record));
    }
    decision = pcapc_decide_l2_packet(ipv4_tcp_tls_bad_version, sizeof(ipv4_tcp_tls_bad_version), &cfg);
    expect_u32(&state, "ipv4 tcp tls bad version cap_len", decision.cap_len, sizeof(ipv4_tcp_tls_bad_version));
    expect_reason(&state, "ipv4 tcp tls bad version reason", decision.reason, PCAPC_REASON_TCP);
    expect_u8(&state, "ipv4 tcp tls bad version ip_proto", decision.ip_proto, 4u);
    expect_u8(&state, "ipv4 tcp tls bad version l4_proto", decision.l4_proto, IPPROTO_TCP);
    expect_u16(&state, "ipv4 tcp tls bad version l3_off", decision.l3_off, ETH_HDR_LEN);
    expect_u16(&state, "ipv4 tcp tls bad version l4_off", decision.l4_off, ETH_HDR_LEN + IPV4_HDR_LEN);
    expect_u16(&state, "ipv4 tcp tls bad version payload_off", decision.payload_off, ETH_HDR_LEN + IPV4_HDR_LEN + TCP_HDR_LEN);

    fill_eth_header(ipv4_tcp_tls_too_short, ETHERTYPE_IPV4);
    fill_ipv4_header(ipv4_tcp_tls_too_short, ETH_HDR_LEN, IPPROTO_TCP, 0u);
    fill_tcp_header(ipv4_tcp_tls_too_short, ETH_HDR_LEN + IPV4_HDR_LEN);
    {
        static const uint8_t tls_too_short_record[] = {
            0x17, 0x03, 0x03, 0x00
        };
        fill_bytes(ipv4_tcp_tls_too_short,
                   ETH_HDR_LEN + IPV4_HDR_LEN + TCP_HDR_LEN,
                   tls_too_short_record,
                   sizeof(tls_too_short_record));
    }
    decision = pcapc_decide_l2_packet(ipv4_tcp_tls_too_short, sizeof(ipv4_tcp_tls_too_short), &cfg);
    expect_u32(&state, "ipv4 tcp tls short cap_len", decision.cap_len, sizeof(ipv4_tcp_tls_too_short));
    expect_reason(&state, "ipv4 tcp tls short reason", decision.reason, PCAPC_REASON_TCP);
    expect_u8(&state, "ipv4 tcp tls short ip_proto", decision.ip_proto, 4u);
    expect_u8(&state, "ipv4 tcp tls short l4_proto", decision.l4_proto, IPPROTO_TCP);
    expect_u16(&state, "ipv4 tcp tls short l3_off", decision.l3_off, ETH_HDR_LEN);
    expect_u16(&state, "ipv4 tcp tls short l4_off", decision.l4_off, ETH_HDR_LEN + IPV4_HDR_LEN);
    expect_u16(&state, "ipv4 tcp tls short payload_off", decision.payload_off, ETH_HDR_LEN + IPV4_HDR_LEN + TCP_HDR_LEN);

    cfg.default_snaplen = 2048u;
    cfg.encrypted_snaplen = 8u;
    cfg.max_capture_len = 2048u;
    cfg.flags = 0u;

    fill_eth_header(ipv4_tcp_tls_multi_record, ETHERTYPE_IPV4);
    fill_ipv4_header(ipv4_tcp_tls_multi_record, ETH_HDR_LEN, IPPROTO_TCP, 0u);
    fill_tcp_header(ipv4_tcp_tls_multi_record, ETH_HDR_LEN + IPV4_HDR_LEN);
    {
        static const uint8_t tls_multi_record[] = {
            0x16, 0x03, 0x03, 0x00, 0x05,
            0x01, 0x02, 0x03, 0x04, 0x05,
            0x14, 0x03, 0x03, 0x00, 0x01,
            0x01,
            0x17, 0x03, 0x03, 0x00, 0x10,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
        };
        fill_bytes(ipv4_tcp_tls_multi_record,
                   ETH_HDR_LEN + IPV4_HDR_LEN + TCP_HDR_LEN,
                   tls_multi_record,
                   sizeof(tls_multi_record));
    }
    decision = pcapc_decide_l2_packet(ipv4_tcp_tls_multi_record, sizeof(ipv4_tcp_tls_multi_record), &cfg);
    expect_u32(&state,
               "ipv4 tcp tls multi-record cap_len",
               decision.cap_len,
               ETH_HDR_LEN + IPV4_HDR_LEN + TCP_HDR_LEN + 10u + 6u + 8u);
    expect_reason(&state, "ipv4 tcp tls multi-record reason", decision.reason, PCAPC_REASON_TLS_APP_DATA);
    expect_u8(&state, "ipv4 tcp tls multi-record ip_proto", decision.ip_proto, 4u);
    expect_u8(&state, "ipv4 tcp tls multi-record l4_proto", decision.l4_proto, IPPROTO_TCP);
    expect_u16(&state, "ipv4 tcp tls multi-record l3_off", decision.l3_off, ETH_HDR_LEN);
    expect_u16(&state, "ipv4 tcp tls multi-record l4_off", decision.l4_off, ETH_HDR_LEN + IPV4_HDR_LEN);
    expect_u16(&state, "ipv4 tcp tls multi-record payload_off", decision.payload_off, ETH_HDR_LEN + IPV4_HDR_LEN + TCP_HDR_LEN);

    for (generated_case_index = 0u;
         generated_case_index < sizeof(generated_cases) / sizeof(generated_cases[0]);
         generated_case_index++) {
        run_generated_policy_case(&state, &generated_cases[generated_case_index]);
    }

    if (state.failed != 0u) {
        printf("FAIL %u/%u\n", state.failed, state.total);
        return 1;
    }

    printf("PASS %u\n", state.total);
    return 0;
}
