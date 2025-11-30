#ifndef UPF_ACCEL_PFCP_ASSOCIATION_H_
#define UPF_ACCEL_PFCP_ASSOCIATION_H_

#include <stdint.h>
#include <stdbool.h>
#include "upf_accel_pfcp_packet.h"

struct pfcp_association_resp {
    uint8_t req_msg_type;
    uint8_t seq;
    bool s_flag;
    const uint8_t *nodeid;
    uint16_t nodeid_len;
};

struct pfcp_packet newPFCPAssociationResponse(uint8_t req_msg_type, uint8_t seq, bool s_flag,
                                              const uint8_t *nodeid_payload, uint16_t nodeid_len);

#endif /* UPF_ACCEL_PFCP_ASSOCIATION_H_ */
