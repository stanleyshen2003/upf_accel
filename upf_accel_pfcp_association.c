#include "upf_accel_pfcp_association.h"
#include "upf_accel_pfcp_packet.h"
#include "upf_accel_pfcp_ie.h"
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>

struct pfcp_packet newPFCPAssociationResponse(uint8_t req_msg_type, uint8_t seq, bool s_flag,
                                              const uint8_t *nodeid_payload, uint16_t nodeid_len)
{
    struct pfcp_packet pkt = { NULL, 0 };
    uint8_t *rspbuf = malloc(512);
    if (!rspbuf) return pkt;
    size_t ro = 0;
    uint8_t oct1 = (1 << 5) | (s_flag ? 0x10 : 0);
    rspbuf[ro++] = oct1;
    rspbuf[ro++] = (uint8_t)(req_msg_type + 1);
    ro += 2; /* length placeholder */
    if (s_flag) {
        for (int i = 0; i < 8; ++i) rspbuf[ro++] = 0;
    }
    rspbuf[ro++] = seq; rspbuf[ro++] = 0; rspbuf[ro++] = 1;

    if (nodeid_payload && nodeid_len > 0) {
        rspbuf[ro++] = (uint8_t)(PFCP_IE_NODE_ID >> 8);
        rspbuf[ro++] = (uint8_t)(PFCP_IE_NODE_ID & 0xff);
        rspbuf[ro++] = (uint8_t)((nodeid_len >> 8) & 0xff);
        rspbuf[ro++] = (uint8_t)(nodeid_len & 0xff);
        memcpy(&rspbuf[ro], nodeid_payload, nodeid_len);
        ro += nodeid_len;
    }

    rspbuf[ro++] = (uint8_t)(PFCP_IE_CAUSE >> 8);
    rspbuf[ro++] = (uint8_t)(PFCP_IE_CAUSE & 0xff);
    rspbuf[ro++] = 0; rspbuf[ro++] = 1;
    rspbuf[ro++] = 1;

    {
        uint32_t rts = (uint32_t)time(NULL);
        rspbuf[ro++] = 0x00; rspbuf[ro++] = 0x05;
        rspbuf[ro++] = 0x00; rspbuf[ro++] = 0x04;
        rspbuf[ro++] = (uint8_t)((rts >> 24) & 0xff);
        rspbuf[ro++] = (uint8_t)((rts >> 16) & 0xff);
        rspbuf[ro++] = (uint8_t)((rts >> 8) & 0xff);
        rspbuf[ro++] = (uint8_t)(rts & 0xff);
    }

    uint16_t total_len = (uint16_t)(ro - 4);
    rspbuf[2] = (uint8_t)((total_len >> 8) & 0xff);
    rspbuf[3] = (uint8_t)(total_len & 0xff);

    pkt.buf = rspbuf;
    pkt.len = ro;
    return pkt;
}
