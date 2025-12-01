#include "upf_accel_pfcp_session.h"
#include "upf_accel_pfcp_ie.h"
#include "upf_accel.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

/* Build a PFCP Session Establishment Response
 * Parameters:
 *  - seq: 24-bit sequence (stored in low 24 bits of uint32_t)
 *  - s_flag: whether SEID is present
 *  - cfg: pointer to the pending SMF config (used to build Created PDRs)
 *  - nodeid/nodeid_len: raw NodeID IE payload from request (if present)
 * Returns a heap-allocated `struct pfcp_packet` (caller frees pkt.buf).
 */
struct pfcp_packet newPFCPEstablishmentResponse(uint32_t seq, bool s_flag, struct upf_accel_config *cfg,
                                                const uint8_t *nodeid, uint16_t nodeid_len,
                                                uint64_t request_seid)
{
    struct pfcp_packet pkt = { NULL, 0 };

    /* Build IE parts: NodeID, Cause, F-SEID and Created PDRs
     * We construct each IE into a separate allocated buffer using the
     * `upf_build_*` helpers and collect them into `parts[]`. This keeps
     * IE encoding centralized and avoids ad-hoc byte fiddling. */
    uint8_t *parts[16]; size_t parts_len[16]; size_t parts_cnt = 0;
    memset(parts, 0, sizeof(parts)); memset(parts_len, 0, sizeof(parts_len));

    uint32_t local_ip = inet_addr("127.0.0.1");

    /* NodeID IE: use provided NodeID payload from request if present,
        * otherwise build an IPv4 NodeID using local loopback (fallback). */
    if (nodeid && nodeid_len >= 5) {
        uint8_t *b = NULL; size_t bl = 0;
        if (upf_build_ie(PFCP_IE_NODE_ID, nodeid, nodeid_len, &b, &bl) == 0) {
            parts[parts_cnt] = b; parts_len[parts_cnt] = bl; parts_cnt++;
        }
    } else {
        uint8_t *b = NULL; size_t bl = 0;
        if (upf_build_nodeid_ipv4(local_ip, &b, &bl) == 0) {
            parts[parts_cnt] = b; parts_len[parts_cnt] = bl; parts_cnt++;
        }
    }

    /* Cause IE: indicate Request Accepted (cause value 1) */
    {
        uint8_t *b = NULL; size_t bl = 0;
        if (upf_build_cause(1, 0, 0, &b, &bl) == 0) {
            parts[parts_cnt] = b; parts_len[parts_cnt] = bl; parts_cnt++;
        }
    }

    /* F-SEID IE: generate local F-SEID and attach IPv4 address.
        * Prefer the IPv4 from request NodeID payload (bytes [1..4]) if present. */
    {
        uint32_t ip_be = 0; int has_ipv4 = 0;
        if (nodeid && nodeid_len >= 5) {
            ip_be = ((uint32_t)nodeid[1] << 24) | ((uint32_t)nodeid[2] << 16) | ((uint32_t)nodeid[3] << 8) | (uint32_t)nodeid[4];
            has_ipv4 = 1;
        } else {
            ip_be = local_ip;
            has_ipv4 = 1;
        }
        uint8_t *b = NULL; size_t bl = 0;
        if (upf_build_fseid(request_seid, has_ipv4, ip_be, &b, &bl) == 0) {
            parts[parts_cnt] = b; parts_len[parts_cnt] = bl; parts_cnt++;
        }
    }

    /* Created PDRs: for each PDR in `cfg` that contains an IPv4 UE IP,
        * create a nested `Created PDR` IE carrying the PDR ID and UE IP. */
    if (cfg && cfg->pdrs) {
        for (size_t i = 0; i < cfg->pdrs->num_pdrs; ++i) {
            struct upf_accel_pdr *p = &cfg->pdrs->arr_pdrs[i];
            if (p->pdi_ueip.ip_version == DOCA_FLOW_L3_TYPE_IP4) {
                uint8_t nested[64]; size_t noff = 0;
                /* PDR ID IE */
                nested[noff++] = (uint8_t)(PFCP_IE_PDR_ID >> 8);
                nested[noff++] = (uint8_t)(PFCP_IE_PDR_ID & 0xff);
                nested[noff++] = 0; nested[noff++] = 2;
                nested[noff++] = (uint8_t)((p->id >> 8) & 0xff);
                nested[noff++] = (uint8_t)(p->id & 0xff);
                printf("Adding Created PDR IE for PDR ID %u with UE IP 0x%08x\n", p->id, p->pdi_ueip.addr.v4);
                /* UE IP address IE */
                nested[noff++] = (uint8_t)(PFCP_IE_UE_IP_ADDRESS >> 8);
                nested[noff++] = (uint8_t)(PFCP_IE_UE_IP_ADDRESS & 0xff);
                nested[noff++] = 0; nested[noff++] = 5;
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


    /* Compute total output size: 4-byte PFCP header (first 4 octets not included
     * in the length field) + optional 8-byte SEID + 4-byte seq+priority + all parts */
    size_t buf_size = 4 + (s_flag ? 8 : 0) + 4;
    for (size_t i = 0; i < parts_cnt; ++i) buf_size += parts_len[i];

    /* Final output buffer with exact size */
    uint8_t *out = malloc(buf_size);
    if (!out) {
        for (size_t i = 0; i < parts_cnt; ++i) free(parts[i]);
        return pkt;
    }

    /* Build final PFCP message: header, optional SEID, 3-byte seq + priority, then IEs */
    size_t ro = 0;
    uint8_t oct1_final = (1 << 5) | (s_flag ? 0x01 : 0);
    out[ro++] = oct1_final;
    out[ro++] = PFCP_MSG_SESSION_ESTABLISHMENT_RESPONSE;
    ro += 2; /* length placeholder */
    if (s_flag) {
        /* If caller provided a request SEID via `request_seid`, echo it into
         * the response SEID field. Otherwise keep zero SEID as before. */
        uint64_t use_seid = request_seid;
        for (int i = 7; i >= 0; --i) {
            out[ro + i] = (uint8_t)(use_seid & 0xff);
            use_seid >>= 8;
        }
        ro += 8;
    }
    /* 3-byte sequence and 1-byte message priority (0) */
    out[ro++] = (uint8_t)((seq >> 16) & 0xff);
    out[ro++] = (uint8_t)((seq >> 8) & 0xff);
    out[ro++] = (uint8_t)(seq & 0xff);
    out[ro++] = 0; /* priority */

    /* Append each built IE part and free its temporary buffer */
    for (size_t i = 0; i < parts_cnt; ++i) {
        memcpy(&out[ro], parts[i], parts_len[i]);
        ro += parts_len[i];
        free(parts[i]);
    }

    /* Write message length (excluding first 4 bytes) */
    uint16_t total_len = (uint16_t)(ro - 4);
    out[2] = (uint8_t)((total_len >> 8) & 0xff);
    out[3] = (uint8_t)(total_len & 0xff);

    pkt.buf = out;
    pkt.len = ro;
    return pkt;
}
