#include "pfcp_generic.h"
#include "pfcp_ie.h"

#include <string.h>
#include <stdlib.h>

struct pfcp_packet newPFCPGenericSimpleResponse(uint8_t req_msg_type, uint8_t seq, bool s_flag)
{
    struct pfcp_packet pkt = { NULL, 0 };
    uint8_t *buf = malloc(256);
    if (!buf) return pkt;

    size_t off = 0;
    uint8_t version = 0x20; /* PFCP version 1 (0x20 in high 3 bits) */

    buf[off++] = version; /* octet 1 */
    buf[off++] = (uint8_t)(req_msg_type + 1); /* response type is request+1 */
    off += 2; /* placeholder for length */

    /* Sequence (3 bytes) and spare */
    buf[off++] = (seq >> 16) & 0xff;
    buf[off++] = (seq >> 8) & 0xff;
    buf[off++] = seq & 0xff;
    buf[off++] = 0; /* priority/spare */

    /* Cause IE */
    buf[off++] = (uint8_t)(PFCP_IE_CAUSE >> 8);
    buf[off++] = (uint8_t)(PFCP_IE_CAUSE & 0xff);
    buf[off++] = 0; buf[off++] = 1;
    buf[off++] = 1; /* request accepted */

    uint16_t payload_len = (uint16_t)(off - 4);
    buf[2] = (payload_len >> 8) & 0xff;
    buf[3] = payload_len & 0xff;

    pkt.buf = buf;
    pkt.len = off;
    return pkt;
}

struct pfcp_packet newPFCPHeartbeatResponse(uint8_t req_msg_type, uint32_t seq, bool s_flag, uint32_t recovery_timestamp)
{
    struct pfcp_packet pkt = { NULL, 0 };
    uint8_t *buf = malloc(256);
    if (!buf) return pkt;

    size_t off = 0;
    uint8_t version = 0x20; /* PFCP version 1 (0x20 in high 3 bits) */

    buf[off++] = version; /* octet 1 */
    buf[off++] = (uint8_t)(req_msg_type + 1); /* response type is request+1 */
    off += 2; /* placeholder for length */

    /* Sequence (3 bytes) and spare */
    buf[off++] = (seq >> 16) & 0xff;
    buf[off++] = (seq >> 8) & 0xff;
    buf[off++] = seq & 0xff;
    buf[off++] = 0; /* priority/spare */

    /* Recovery Time Stamp IE (Type 96) */
    buf[off++] = (uint8_t)(PFCP_IE_RECOVERY_TIME_STAMP >> 8);
    buf[off++] = (uint8_t)(PFCP_IE_RECOVERY_TIME_STAMP & 0xff);
    buf[off++] = 0; buf[off++] = 4; /* Length = 4 */
    buf[off++] = (recovery_timestamp >> 24) & 0xff;
    buf[off++] = (recovery_timestamp >> 16) & 0xff;
    buf[off++] = (recovery_timestamp >> 8) & 0xff;
    buf[off++] = recovery_timestamp & 0xff;

    uint16_t payload_len = (uint16_t)(off - 4);
    buf[2] = (payload_len >> 8) & 0xff;
    buf[3] = payload_len & 0xff;

    pkt.buf = buf;
    pkt.len = off;
    return pkt;
}
