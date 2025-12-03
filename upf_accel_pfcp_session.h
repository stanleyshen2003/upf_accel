#ifndef UPF_ACCEL_PFCP_SESSION_H_
#define UPF_ACCEL_PFCP_SESSION_H_

#include "upf_accel_pfcp_packet.h"
#include <stdint.h>
#include <stdbool.h>


struct upf_accel_config; /* forward */

/* seq: 24-bit sequence in low 24 bits of uint32_t
 * s_flag: whether SEID field should be present in the PFCP header
 * cfg: pointer to pending SMF config (used to build Created PDRs)
 * nodeid/nodeid_len: raw NodeID IE payload from request (if present)
 * request_seid: SEID parsed from request's F-SEID IE (or 0 if none)
 */
struct pfcp_packet newPFCPEstablishmentResponse(uint32_t seq, bool s_flag, struct upf_accel_config *cfg,
												const uint8_t *nodeid, uint16_t nodeid_len,
												uint64_t request_seid);

/* Build a PFCP Session Modification Response */
struct pfcp_packet newPFCPSessionModificationResponse(uint32_t seq, bool s_flag, uint64_t seid);

#define PFCP_MSG_SESSION_ESTABLISHMENT_RESPONSE  51
#endif /* UPF_ACCEL_PFCP_SESSION_H_ */
