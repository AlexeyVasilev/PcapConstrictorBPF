#pragma once

#include "../shared/packet_policy_types.h"

struct pcapc_capture_decision
pcapc_decide_l2_packet(const pcapc_u8 *data,
                       pcapc_u32 len,
                       const struct pcapc_capture_config *cfg);
