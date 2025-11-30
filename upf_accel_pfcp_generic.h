#ifndef UPF_ACCEL_PFCP_GENERIC_H_
#define UPF_ACCEL_PFCP_GENERIC_H_

#include <stdint.h>
#include <stdbool.h>
#include "upf_accel_pfcp_packet.h"

/* Build a generic PFCP response that contains only a Cause IE.
 * Returns a `pfcp_packet` containing a malloc'd buffer (caller frees it).
 */
struct pfcp_packet newPFCPGenericSimpleResponse(uint8_t req_msg_type, uint8_t seq, bool s_flag);

#endif /* UPF_ACCEL_PFCP_GENERIC_H_ */
