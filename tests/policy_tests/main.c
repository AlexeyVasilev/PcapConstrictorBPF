#include <stdint.h>
#include <stdio.h>

#include "packet_policy.h"

struct test_state {
    uint32_t total;
    uint32_t failed;
};

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

int main(void)
{
    struct test_state state = {0};
    uint8_t packet_100[100] = {0};
    uint8_t packet_1500[1500] = {0};
    uint8_t packet_4096[4096] = {0};
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

    if (state.failed != 0u) {
        printf("FAIL %u/%u\n", state.failed, state.total);
        return 1;
    }

    printf("PASS %u\n", state.total);
    return 0;
}
