#include "upf_accel_pfcp_association.h"
#include "upf_accel_pfcp_packet.h"
#include "upf_accel_pfcp_ie.h"
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>

struct pfcp_packet newPFCPAssociationResponse(uint8_t req_msg_type, uint32_t seq24, uint8_t priority, bool s_flag,
                                              const uint8_t *nodeid_payload, uint16_t nodeid_len)
{
    struct pfcp_packet pkt = { NULL, 0 };
    /* Build response by composing IE buffers created via helper functions. */
    uint8_t *parts[8]; size_t parts_len[8]; size_t parts_cnt = 0;
    memset(parts, 0, sizeof(parts)); memset(parts_len, 0, sizeof(parts_len));

    /* Optional NodeID IE (use provided payload if any) */
    if (nodeid_payload && nodeid_len > 0) {
        uint8_t *b = NULL; size_t bl = 0;
        if (upf_build_ie(PFCP_IE_NODE_ID, nodeid_payload, nodeid_len, &b, &bl) == 0) {
            parts[parts_cnt] = b; parts_len[parts_cnt] = bl; parts_cnt++;
        }
    }

    /* Cause IE: success (1) */
    {
        uint8_t *b = NULL; size_t bl = 0;
        if (upf_build_cause(1, 0, 0, &b, &bl) == 0) {
            parts[parts_cnt] = b; parts_len[parts_cnt] = bl; parts_cnt++;
        }
    }

    /* Recovery Time Stamp IE (4-byte UNIX time). Use defined IE constant. */
    {
        uint32_t rts = (uint32_t)time(NULL);
        uint8_t rtsb[4];
        rtsb[0] = (uint8_t)((rts >> 24) & 0xff);
        rtsb[1] = (uint8_t)((rts >> 16) & 0xff);
        rtsb[2] = (uint8_t)((rts >> 8) & 0xff);
        rtsb[3] = (uint8_t)(rts & 0xff);
        uint8_t *b = NULL; size_t bl = 0;
        if (upf_build_ie(PFCP_IE_RECOVERY_TIME_STAMP, rtsb, 4, &b, &bl) == 0) {
            parts[parts_cnt] = b; parts_len[parts_cnt] = bl; parts_cnt++;
        }
    }

    /* Compute total size and allocate buffer: header + optional SEID + seq(3)+priority + parts */
    size_t buf_size = 4 + (s_flag ? 8 : 0) + 4; /* header(4) + SEID(if) + seq(3)+priority(1) */
    for (size_t i = 0; i < parts_cnt; ++i) buf_size += parts_len[i];
    uint8_t *rspbuf = malloc(buf_size);
    if (!rspbuf) {
        for (size_t i = 0; i < parts_cnt; ++i) free(parts[i]);
        return pkt;
    }

    size_t ro = 0;
    uint8_t oct1 = (1 << 5) | (s_flag ? 0x10 : 0);
    rspbuf[ro++] = oct1;
    rspbuf[ro++] = (uint8_t)(req_msg_type + 1);
    ro += 2; /* length placeholder */

    if (s_flag) {
        /* include zeroed SEID for now */
        for (int i = 0; i < 8; ++i) rspbuf[ro++] = 0;
    }

    /* Write 3-byte sequence (big-endian) then priority */
    rspbuf[ro++] = (uint8_t)((seq24 >> 16) & 0xff);
    rspbuf[ro++] = (uint8_t)((seq24 >> 8) & 0xff);
    rspbuf[ro++] = (uint8_t)(seq24 & 0xff);
    rspbuf[ro++] = priority;

    /* Append built IEs */
    for (size_t i = 0; i < parts_cnt; ++i) {
        memcpy(&rspbuf[ro], parts[i], parts_len[i]);
        ro += parts_len[i];
        free(parts[i]);
    }

    /* Fill length field (message length excluding first 4 octets) */
    uint16_t total_len = (uint16_t)(ro - 4);
    rspbuf[2] = (uint8_t)((total_len >> 8) & 0xff);
    rspbuf[3] = (uint8_t)(total_len & 0xff);

    pkt.buf = rspbuf;
    pkt.len = ro;
    return pkt;
}
