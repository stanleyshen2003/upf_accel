#ifndef UPF_ACCEL_PFCP_GENERIC_H_
#define UPF_ACCEL_PFCP_GENERIC_H_

#include <stdint.h>
#include <stdbool.h>
#include "upf_accel_pfcp_packet.h"

/* Build a generic PFCP response that contains only a Cause IE.
 * Returns a `pfcp_packet` containing a malloc'd buffer (caller frees it).
 */
struct pfcp_packet newPFCPGenericSimpleResponse(uint8_t req_msg_type, uint8_t seq, bool s_flag);

/* Build a Heartbeat Response packet.
 * @req_msg_type: the request message type (response will be req_msg_type+1)
 * @seq: sequence number
 * @s_flag: whether SEID field should be present (usually false for Heartbeat)
 * @recovery_timestamp: timestamp value to include
 */
struct pfcp_packet newPFCPHeartbeatResponse(uint8_t req_msg_type, uint32_t seq, bool s_flag, uint32_t recovery_timestamp);

#endif /* UPF_ACCEL_PFCP_GENERIC_H_ */
