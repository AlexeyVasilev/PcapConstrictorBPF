#include "packet_policy.h"

static uint32_t pcapc_min_u32(uint32_t a, uint32_t b)
{
    return a < b ? a : b;
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

    decision.reason = PCAPC_REASON_DEFAULT;

    if (data == NULL || len == 0u)
        return decision;

    decision.cap_len = pcapc_min_u32(len, active_cfg->default_snaplen);
    decision.cap_len = pcapc_min_u32(decision.cap_len, active_cfg->max_capture_len);

    return decision;
}
