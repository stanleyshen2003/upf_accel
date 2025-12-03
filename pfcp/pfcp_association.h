#ifndef UPF_ACCEL_PFCP_ASSOCIATION_H_
#define UPF_ACCEL_PFCP_ASSOCIATION_H_

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include "pfcp_packet.h"

/* Handle Association Messages */
void handle_association_message(uint8_t message_type, uint32_t seq, uint8_t msg_priority, bool s_flag, 
                                const uint8_t *buf, size_t n, size_t hdr_off,
                                const struct sockaddr_in *src, socklen_t src_len);

/* Response Builder (existing) */
struct pfcp_packet newPFCPAssociationResponse(uint8_t req_msg_type, uint32_t seq24, uint8_t priority, bool s_flag,
                                              const uint8_t *nodeid_payload, uint16_t nodeid_len);

#endif /* UPF_ACCEL_PFCP_ASSOCIATION_H_ */
