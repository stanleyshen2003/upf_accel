#include "pfcp_association.h"
#include "pfcp_packet.h"
#include "pfcp_ie.h"
#include "pfcp_util.h"
#include "pfcp_main.h"
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

void handle_association_message(uint8_t message_type, uint32_t seq, uint8_t msg_priority, bool s_flag, 
                                const uint8_t *buf, size_t n, size_t hdr_off,
                                const struct sockaddr_in *src, socklen_t src_len)
{
    printf("PFCP: Association message type=%u seq=%u\n", message_type, seq);
    /* Parse top-level IEs and capture NodeID payload if present. */
    struct upf_ie *top_ies = NULL; size_t top_n = 0;
    const uint8_t *node_payload = NULL; uint16_t node_payload_len = 0;
    if (upf_parse_ies(buf, n, hdr_off, &top_ies, &top_n) == 0 && top_n > 0) {
        const struct upf_ie *node_ie = upf_find_ie(top_ies, top_n, PFCP_IE_NODE_ID, 0);
        if (node_ie) {
            /* Save pointer/len to the value area (points into `buf`) */
            node_payload = node_ie->value;
            node_payload_len = (uint16_t)node_ie->len;
            char nid[64] = {0};
            if (upf_ie_to_nodeid(node_ie, nid, sizeof(nid)) == 0) {
                if (!find_rnode_by_id(nid)) {
                    /* Cast away const for add_rnode as it copies the address */
                    add_rnode(nid, (struct sockaddr_in *)src);
                    printf("Registered RemoteNode %s -> %s\n", nid, inet_ntoa(src->sin_addr));
                }
            }
        }
        upf_free_ies(top_ies);
        top_ies = NULL;
    }

    /* Build and send Association Response. Prefer NodeID from request; if
     * absent, fall back to the local socket IPv4 address. */
    {
        struct pfcp_packet pkt = { NULL, 0 };
        if (node_payload && node_payload_len > 0) {
            pkt = newPFCPAssociationResponse(message_type, seq, msg_priority, s_flag, node_payload, node_payload_len);
        } else {
            struct sockaddr_in local;
            if (pfcp_get_local_addr(&local) == 0) {
                uint8_t nodebuf[5];
                nodebuf[0] = 0x00; /* type: IPv4 */
                memcpy(&nodebuf[1], &local.sin_addr.s_addr, 4);
                pkt = newPFCPAssociationResponse(message_type, seq, msg_priority, s_flag, nodebuf, 5);
            } else {
                pkt = newPFCPAssociationResponse(message_type, seq, msg_priority, s_flag, NULL, 0);
            }
        }

        if (!pkt.buf || pkt.len == 0) {
            fprintf(stderr, "PFCP: failed to build Association Response\n");
        } else {
            if (pfcp_send_response(pkt.buf, pkt.len, src, src_len) != 0)
                perror("Failed to send Association Response");
            else
                printf("Sent Association Response type=%u\n", message_type + 1);
            free(pkt.buf);
        }
    }
}

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
    uint8_t oct1 = (1 << 5) | (s_flag ? 0x01 : 0);
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
