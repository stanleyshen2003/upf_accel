#ifndef UPF_ACCEL_PFCP_SESSION_H_
#define UPF_ACCEL_PFCP_SESSION_H_

#include "upf_accel_pfcp_packet.h"
#include <stdint.h>
#include <stdbool.h>


struct upf_accel_config; /* forward */

struct pfcp_packet newPFCPEstablishmentResponse(uint8_t seq, bool s_flag, struct upf_accel_config *cfg,
												const uint8_t *nodeid, uint16_t nodeid_len);
#define PFCP_MSG_SESSION_ESTABLISHMENT_RESPONSE  51
#endif /* UPF_ACCEL_PFCP_SESSION_H_ */
