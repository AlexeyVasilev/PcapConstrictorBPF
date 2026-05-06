#include "packet_policy.h"
#include "packet_policy_impl.h"

struct pcapc_capture_decision
pcapc_decide_l2_packet(const pcapc_u8 *data,
                       pcapc_u32 len,
                       const struct pcapc_capture_config *cfg)
{
    return pcapc_decide_l2_packet_impl(data, len, cfg);
}
