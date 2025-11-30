#ifndef UPF_ACCEL_PFCP_ASSOCIATION_H_
#define UPF_ACCEL_PFCP_ASSOCIATION_H_

#include <stdint.h>
#include <stdbool.h>
#include "upf_accel_pfcp_packet.h"

struct pfcp_association_resp {
    uint8_t req_msg_type;
    uint32_t seq24; /* 24-bit sequence stored in 32-bit container */
    uint8_t priority;
    bool s_flag;
    const uint8_t *nodeid;
    uint16_t nodeid_len;
};

/* Build an Association Response packet.
 * @req_msg_type: the request message type (response will be req_msg_type+1)
 * @seq24: 24-bit sequence number (lower 24 bits used)
 * @priority: 1-byte message priority value
 * @s_flag: whether SEID field should be present
 * @nodeid_payload/nodeid_len: optional NodeID payload to include (if NULL/0, omitted)
 */
struct pfcp_packet newPFCPAssociationResponse(uint8_t req_msg_type, uint32_t seq24, uint8_t priority, bool s_flag,
                                              const uint8_t *nodeid_payload, uint16_t nodeid_len);

#endif /* UPF_ACCEL_PFCP_ASSOCIATION_H_ */
