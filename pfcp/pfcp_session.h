#ifndef UPF_ACCEL_PFCP_SESSION_H_
#define UPF_ACCEL_PFCP_SESSION_H_

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include "pfcp_packet.h"
#include "upf_accel.h" /* for struct upf_accel_config */

/* Handle Session Messages */
void handle_session_establishment_request(uint32_t seq, bool s_flag, uint64_t seid,
                                          const uint8_t *buf, size_t n, size_t hdr_off,
                                          const struct sockaddr_in *src, socklen_t src_len);

void handle_session_modification_request(uint32_t seq, bool s_flag, uint64_t seid,
                                         const struct sockaddr_in *src, socklen_t src_len);

/* Response Builders (existing) */
struct pfcp_packet newPFCPEstablishmentResponse(uint32_t seq, bool s_flag, struct upf_accel_config *cfg,
                                                const uint8_t *nodeid, uint16_t nodeid_len,
                                                uint64_t request_seid);

struct pfcp_packet newPFCPSessionModificationResponse(uint32_t seq, bool s_flag, uint64_t seid);

#endif /* UPF_ACCEL_PFCP_SESSION_H_ */
