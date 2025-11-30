#include "upf_accel_pfcp_session.h"
#include "upf_accel_pfcp_ie.h"
#include "upf_accel.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

struct pfcp_packet newPFCPEstablishmentResponse(uint8_t seq, bool s_flag, struct upf_accel_config *cfg)
{
    struct pfcp_packet pkt = { NULL, 0 };
    uint8_t *rspbuf = malloc(4096);
    if (!rspbuf) return pkt;
    size_t rsp_off = 0;
    uint64_t assigned_seid = ((uint64_t)time(NULL) << 32) | (uint64_t)(rand() & 0xffffffff);
    uint8_t oct1 = (1 << 5) | (s_flag ? 0x10 : 0);
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
    rspbuf[rsp_off++] = seq;
    rspbuf[rsp_off++] = 0;
    rspbuf[rsp_off++] = 0;

    if (cfg && cfg->pdrs) {
        for (size_t i = 0; i < cfg->pdrs->num_pdrs; ++i) {
            struct upf_accel_pdr *p = &cfg->pdrs->arr_pdrs[i];
            if (p->pdi_ueip.ip_version == DOCA_FLOW_L3_TYPE_IP4) {
                uint8_t nested[64]; size_t noff = 0;
                nested[noff++] = (uint8_t)(PFCP_IE_PDR_ID >> 8);
                nested[noff++] = (uint8_t)(PFCP_IE_PDR_ID & 0xff);
                nested[noff++] = 0; nested[noff++] = 4;
                nested[noff++] = (uint8_t)((p->id >> 24) & 0xff);
                nested[noff++] = (uint8_t)((p->id >> 16) & 0xff);
                nested[noff++] = (uint8_t)((p->id >> 8) & 0xff);
                nested[noff++] = (uint8_t)(p->id & 0xff);
                nested[noff++] = (uint8_t)(PFCP_IE_UE_IP_ADDRESS >> 8);
                nested[noff++] = (uint8_t)(PFCP_IE_UE_IP_ADDRESS & 0xff);
                nested[noff++] = 0; nested[noff++] = 4;
                uint32_t uip = p->pdi_ueip.addr.v4;
                nested[noff++] = (uint8_t)((uip >> 24) & 0xff);
                nested[noff++] = (uint8_t)((uip >> 16) & 0xff);
                nested[noff++] = (uint8_t)((uip >> 8) & 0xff);
                nested[noff++] = (uint8_t)(uip & 0xff);

                rspbuf[rsp_off++] = (uint8_t)(PFCP_IE_CREATED_PDR >> 8);
                rspbuf[rsp_off++] = (uint8_t)(PFCP_IE_CREATED_PDR & 0xff);
                rspbuf[rsp_off++] = (uint8_t)((noff >> 8) & 0xff);
                rspbuf[rsp_off++] = (uint8_t)(noff & 0xff);
                memcpy(&rspbuf[rsp_off], nested, noff);
                rsp_off += noff;
            }
        }
    }

    uint32_t local_ip = inet_addr("127.0.0.1");
    rspbuf[rsp_off++] = (uint8_t)(PFCP_IE_NODE_ID >> 8);
    rspbuf[rsp_off++] = (uint8_t)(PFCP_IE_NODE_ID & 0xff);
    rspbuf[rsp_off++] = 0; rspbuf[rsp_off++] = 4;
    rspbuf[rsp_off++] = (uint8_t)((local_ip >> 24) & 0xff);
    rspbuf[rsp_off++] = (uint8_t)((local_ip >> 16) & 0xff);
    rspbuf[rsp_off++] = (uint8_t)((local_ip >> 8) & 0xff);
    rspbuf[rsp_off++] = (uint8_t)(local_ip & 0xff);

    rspbuf[rsp_off++] = (uint8_t)(PFCP_IE_CAUSE >> 8);
    rspbuf[rsp_off++] = (uint8_t)(PFCP_IE_CAUSE & 0xff);
    rspbuf[rsp_off++] = 0; rspbuf[rsp_off++] = 1;
    rspbuf[rsp_off++] = 1;

    uint64_t seid_to_write = ((uint64_t)time(NULL) << 32) | (uint64_t)(rand() & 0xffffffff);
    rspbuf[rsp_off++] = (uint8_t)(PFCP_IE_FSEID >> 8);
    rspbuf[rsp_off++] = (uint8_t)(PFCP_IE_FSEID & 0xff);
    rspbuf[rsp_off++] = 0; rspbuf[rsp_off++] = 12;
    for (int i = 7; i >= 0; --i) {
        rspbuf[rsp_off + i] = (uint8_t)(seid_to_write & 0xff);
        seid_to_write >>= 8;
    }
    rsp_off += 8;
    uint32_t ip4 = inet_addr("127.0.0.1");
    rspbuf[rsp_off++] = (uint8_t)((ip4 >> 24) & 0xff);
    rspbuf[rsp_off++] = (uint8_t)((ip4 >> 16) & 0xff);
    rspbuf[rsp_off++] = (uint8_t)((ip4 >> 8) & 0xff);
    rspbuf[rsp_off++] = (uint8_t)(ip4 & 0xff);

    uint16_t total_len = (uint16_t)(rsp_off - 4);
    rspbuf[2] = (uint8_t)((total_len >> 8) & 0xff);
    rspbuf[3] = (uint8_t)(total_len & 0xff);

    pkt.buf = rspbuf;
    pkt.len = rsp_off;
    return pkt;
}
