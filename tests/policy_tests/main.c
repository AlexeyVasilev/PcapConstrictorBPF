#include <stdint.h>
#include <stdio.h>

#include "packet_policy.h"

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

static void fill_udp_header(uint8_t *packet, uint32_t l4_off)
{
    uint32_t i;

    for (i = 0u; i < UDP_HDR_LEN; i++)
        packet[l4_off + i] = 0u;

    store_be16(packet + l4_off + 4u, UDP_HDR_LEN);
}

int main(void)
{
    struct test_state state = {0};
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

    if (state.failed != 0u) {
        printf("FAIL %u/%u\n", state.failed, state.total);
        return 1;
    }

    printf("PASS %u\n", state.total);
    return 0;
}
