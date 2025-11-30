#include "upf_accel_pfcp_session.h"
#include "upf_accel_pfcp_ie.h"
#include "upf_accel.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

struct pfcp_packet newPFCPEstablishmentResponse(uint32_t seq, bool s_flag, struct upf_accel_config *cfg,
                                                const uint8_t *nodeid, uint16_t nodeid_len)
{
    struct pfcp_packet pkt = { NULL, 0 };
    uint8_t *rspbuf = malloc(4096);
    if (!rspbuf) return pkt;
    size_t rsp_off = 0;
    uint64_t assigned_seid = ((uint64_t)time(NULL) << 32) | (uint64_t)(rand() & 0xffffffff);
    uint8_t oct1 = (1 << 5) | (s_flag ? 1 : 0);
    rspbuf[rsp_off++] = oct1;
    rspbuf[rsp_off++] = PFCP_MSG_SESSION_ESTABLISHMENT_RESPONSE;
    rsp_off += 2;
    if (s_flag) {
        uint64_t tmp = assigned_seid;
        for (int i = 7; i >= 0; --i) {
            rspbuf[rsp_off + i] = (uint8_t)(tmp & 0xff);
            tmp >>= 8;
        }
        rsp_off += 8;
    }
    /* sequence: 3 bytes (big-endian) */
    rspbuf[rsp_off++] = (uint8_t)((seq >> 16) & 0xff);
    rspbuf[rsp_off++] = (uint8_t)((seq >> 8) & 0xff);
    rspbuf[rsp_off++] = (uint8_t)(seq & 0xff);

    /* First: NodeID, Cause, F-SEID */
    uint32_t local_ip = inet_addr("127.0.0.1");
        /* Build IEs using helper builders and collect them into parts[] */
        uint8_t *parts[16]; size_t parts_len[16]; size_t parts_cnt = 0;
        memset(parts, 0, sizeof(parts)); memset(parts_len, 0, sizeof(parts_len));

        /* NodeID IE: use provided nodeid payload if present, otherwise build IPv4 NodeID */
        if (nodeid && nodeid_len >= 1) {
            uint8_t *b = NULL; size_t bl = 0;
            if (upf_build_ie(PFCP_IE_NODE_ID, nodeid, nodeid_len, &b, &bl) == 0) {
                parts[parts_cnt] = b; parts_len[parts_cnt] = bl; parts_cnt++;
            }
        } else {
            uint32_t local_ip = inet_addr("127.0.0.1");
            uint8_t *b = NULL; size_t bl = 0;
            if (upf_build_nodeid_ipv4(local_ip, &b, &bl) == 0) {
                parts[parts_cnt] = b; parts_len[parts_cnt] = bl; parts_cnt++;
            }
        }

        /* Cause IE: success */
        {
            uint8_t *b = NULL; size_t bl = 0;
            if (upf_build_cause(1, 0, 0, &b, &bl) == 0) {
                parts[parts_cnt] = b; parts_len[parts_cnt] = bl; parts_cnt++;
            }
        }

        /* F-SEID IE: 8-byte SEID + IPv4 (use NodeID IPv4 if provided) */
        {
            uint64_t seid_to_write = ((uint64_t)time(NULL) << 32) | (uint64_t)(rand() & 0xffffffff);
            uint32_t ip_be = 0; int has_ipv4 = 0;
            if (nodeid && nodeid_len >= 5) {
                ip_be = ((uint32_t)nodeid[1] << 24) | ((uint32_t)nodeid[2] << 16) | ((uint32_t)nodeid[3] << 8) | (uint32_t)nodeid[4];
                has_ipv4 = 1;
            } else {
                ip_be = inet_addr("127.0.0.1");
                has_ipv4 = 1;
            }
            uint8_t *b = NULL; size_t bl = 0;
            if (upf_build_fseid(seid_to_write, has_ipv4, ip_be, &b, &bl) == 0) {
                parts[parts_cnt] = b; parts_len[parts_cnt] = bl; parts_cnt++;
            }
        }

        /* Created PDRs */
        if (cfg && cfg->pdrs) {
            for (size_t i = 0; i < cfg->pdrs->num_pdrs; ++i) {
                struct upf_accel_pdr *p = &cfg->pdrs->arr_pdrs[i];
                if (p->pdi_ueip.ip_version == DOCA_FLOW_L3_TYPE_IP4) {
                    uint8_t nested[64]; size_t noff = 0;
                    /* PDR ID IE */
                    nested[noff++] = (uint8_t)(PFCP_IE_PDR_ID >> 8);
                    nested[noff++] = (uint8_t)(PFCP_IE_PDR_ID & 0xff);
                    nested[noff++] = 0; nested[noff++] = 4;
                    nested[noff++] = (uint8_t)((p->id >> 24) & 0xff);
                    nested[noff++] = (uint8_t)((p->id >> 16) & 0xff);
                    nested[noff++] = (uint8_t)((p->id >> 8) & 0xff);
                    nested[noff++] = (uint8_t)(p->id & 0xff);
                    /* UE IP address IE */
                    nested[noff++] = (uint8_t)(PFCP_IE_UE_IP_ADDRESS >> 8);
                    nested[noff++] = (uint8_t)(PFCP_IE_UE_IP_ADDRESS & 0xff);
                    nested[noff++] = 0; nested[noff++] = 4;
                    uint32_t uip = p->pdi_ueip.addr.v4;
                    nested[noff++] = (uint8_t)((uip >> 24) & 0xff);
                    nested[noff++] = (uint8_t)((uip >> 16) & 0xff);
                    nested[noff++] = (uint8_t)((uip >> 8) & 0xff);
                    nested[noff++] = (uint8_t)(uip & 0xff);

                    uint8_t *b = NULL; size_t bl = 0;
                    if (upf_build_ie(PFCP_IE_CREATED_PDR, nested, (uint16_t)noff, &b, &bl) == 0) {
                        parts[parts_cnt] = b; parts_len[parts_cnt] = bl; parts_cnt++;
                    }
                }
            }
        }


    /* Compute total size and allocate buffer: header + optional SEID + seq(3)+priority + parts */
    size_t buf_size = 4 + (s_flag ? 8 : 0) + 4; /* header(4) + SEID(if) + seq(3)+priority(1) */
    for (size_t i = 0; i < parts_cnt; ++i) buf_size += parts_len[i];
    free(rspbuf); /* free temporary linear buffer created earlier */
    uint8_t *out = malloc(buf_size);
    if (!out) {
        for (size_t i = 0; i < parts_cnt; ++i) free(parts[i]);
        return pkt;
    }

    size_t ro = 0;
    uint8_t oct1 = (1 << 5) | (s_flag ? 1 : 0);
    out[ro++] = oct1;
    out[ro++] = PFCP_MSG_SESSION_ESTABLISHMENT_RESPONSE;
    ro += 2; /* length placeholder */
    if (s_flag) {
        /* include zeroed SEID for now */
        for (int i = 0; i < 8; ++i) out[ro++] = 0;
    }
    /* seq (3 bytes) + message priority (0) */
    out[ro++] = (uint8_t)((seq >> 16) & 0xff);
    out[ro++] = (uint8_t)((seq >> 8) & 0xff);
    out[ro++] = (uint8_t)(seq & 0xff);
    out[ro++] = 0; /* priority */

    /* Append parts */
    for (size_t i = 0; i < parts_cnt; ++i) {
        memcpy(&out[ro], parts[i], parts_len[i]);
        ro += parts_len[i];
        free(parts[i]);
    }

    uint16_t total_len = (uint16_t)(ro - 4);
    out[2] = (uint8_t)((total_len >> 8) & 0xff);
    out[3] = (uint8_t)(total_len & 0xff);

    pkt.buf = out;
    pkt.len = ro;
    return pkt;
}
