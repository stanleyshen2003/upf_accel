#include "pfcp_session.h"
#include "pfcp_ie.h"
#include "pfcp_main.h"
#include "pfcp_util.h"
#include "upf_accel.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <inttypes.h>
#include <arpa/inet.h>

/* Forward declarations for local parsing helpers */
static void parse_create_pdr(const uint8_t *payload, size_t len, struct upf_accel_pdr *pdr);
static void parse_create_far(const uint8_t *payload, size_t len, struct upf_accel_far *far);
static void parse_create_qer(const uint8_t *payload, size_t len, struct upf_accel_qer *qer);
static void parse_create_urr(const uint8_t *payload, size_t len, struct upf_accel_urr *urr);

void handle_session_establishment_request(uint32_t seq, bool s_flag, uint64_t seid,
                                          const uint8_t *buf, size_t n, size_t hdr_off,
                                          const struct sockaddr_in *src, socklen_t src_len)
{
    printf("PFCP: Session Establishment Request (seq=%u)\n", seq);
    printf("PFCP: Session Establishment Request - preparing SMF config and scheduling apply\n");
    /* Parse top-level IEs once and count Create* entries */
    struct upf_ie *top_ies = NULL; size_t top_n = 0;
    size_t num_pdrs = 0, num_fars = 0, num_qers = 0, num_urrs = 0;
    if (upf_parse_ies(buf, n, hdr_off, &top_ies, &top_n) == 0 && top_n > 0) {
        for (size_t i = 0; i < top_n; ++i) {
            switch (top_ies[i].type) {
            case PFCP_IE_CREATE_PDR: num_pdrs++; break;
            case PFCP_IE_CREATE_FAR: num_fars++; break;
            case PFCP_IE_CREATE_QER: num_qers++; break;
            case PFCP_IE_CREATE_URR: num_urrs++; break;
            default: break;
            }
        }
    }

    // printf("Top-level IEs parsed: %zu\n", top_n);
    // for (size_t i = 0; i < top_n; ++i) {
    //     printf(" IE[%zu]: type=%u len=%zu\n", i, top_ies[i].type, top_ies[i].len);
    // }

    if (num_pdrs == 0 && num_fars == 0 && num_qers == 0 && num_urrs == 0) {
        printf("No Create* IEs found, skipping SMF apply\n");
    } else {
        /* Allocate top-level config container on heap */
        struct upf_accel_config *cfg = (struct upf_accel_config *)calloc(1, sizeof(*cfg));
        if (!cfg) {
            perror("calloc cfg");
        } else {
            /* Allocate arrays with flexible struct wrappers */
            if (num_pdrs) {
                size_t size = sizeof(struct upf_accel_pdrs) + num_pdrs * sizeof(struct upf_accel_pdr);
                cfg->pdrs = (struct upf_accel_pdrs *)calloc(1, size);
                if (cfg->pdrs)
                    cfg->pdrs->num_pdrs = num_pdrs;
            }
            if (num_fars) {
                size_t size = sizeof(struct upf_accel_fars) + num_fars * sizeof(struct upf_accel_far);
                cfg->fars = (struct upf_accel_fars *)calloc(1, size);
                if (cfg->fars)
                    cfg->fars->num_fars = num_fars;
            }
            if (num_qers) {
                size_t size = sizeof(struct upf_accel_qers) + num_qers * sizeof(struct upf_accel_qer);
                cfg->qers = (struct upf_accel_qers *)calloc(1, size);
                if (cfg->qers)
                    cfg->qers->num_qers = num_qers;
            }
            if (num_urrs) {
                size_t size = sizeof(struct upf_accel_urrs) + num_urrs * sizeof(struct upf_accel_urr);
                cfg->urrs = (struct upf_accel_urrs *)calloc(1, size);
                if (cfg->urrs)
                    cfg->urrs->num_urrs = num_urrs;
            }

            /* Second pass: parse Create* IEs using the parsed top-level IE array */
            size_t pdr_idx = 0, far_idx = 0, qer_idx = 0, urr_idx = 0;
            if (top_ies) {
                for (size_t i = 0; i < top_n; ++i) {
                    const struct upf_ie *ie = &top_ies[i];
                    switch (ie->type) {
                    case PFCP_IE_CREATE_PDR:
                        if (cfg->pdrs && pdr_idx < cfg->pdrs->num_pdrs) {
                            parse_create_pdr(ie->value, ie->len, &cfg->pdrs->arr_pdrs[pdr_idx]);
                            pdr_idx++;
                        }
                        break;
                    case PFCP_IE_CREATE_FAR:
                        if (cfg->fars && far_idx < cfg->fars->num_fars) {
                            parse_create_far(ie->value, ie->len, &cfg->fars->arr_fars[far_idx]);
                            far_idx++;
                        }
                        break;
                    case PFCP_IE_CREATE_QER:
                        if (cfg->qers && qer_idx < cfg->qers->num_qers) {
                            parse_create_qer(ie->value, ie->len, &cfg->qers->arr_qers[qer_idx]);
                            qer_idx++;
                        }
                        break;
                    case PFCP_IE_CREATE_URR:
                        if (cfg->urrs && urr_idx < cfg->urrs->num_urrs) {
                            parse_create_urr(ie->value, ie->len, &cfg->urrs->arr_urrs[urr_idx]);
                            urr_idx++;
                        }
                        break;
                    default:
                        break;
                    }
                }
            }

            /* Hand ownership to main thread apply path */
            if (upf_accel_set_pending_smf_config(cfg) != 0) {
                fprintf(stderr, "Failed to set pending SMF config\n");
                if (cfg->pdrs) free(cfg->pdrs);
                if (cfg->fars) free(cfg->fars);
                if (cfg->qers) free(cfg->qers);
                if (cfg->urrs) free(cfg->urrs);
                free(cfg);
                if (top_ies) { upf_free_ies(top_ies); top_ies = NULL; }
            } else {
                printf("Pending SMF config stored (pdrs=%zu fars=%zu qers=%zu urrs=%zu)\n",
                        pdr_idx, far_idx, qer_idx, urr_idx);

                /* Notify main thread to apply the pending config via SIGUSR2. */
                {
                    struct sigaction oldsa;
                    if (sigaction(SIGUSR2, NULL, &oldsa) == 0) {
                        if (oldsa.sa_handler == SIG_DFL) {
                            printf("PFCP: no SIGUSR2 handler installed; skipping signal to avoid termination\n");
                        } else {
                            if (kill(getpid(), SIGUSR2) != 0) {
                                perror("Failed to signal main process for SMF apply");
                            } else {
                                printf("Signalled main to apply pending SMF config\n");
                            }
                        }
                    } else {
                        perror("sigaction");
                        /* Best-effort: try signalling anyway */
                        if (kill(getpid(), SIGUSR2) != 0) {
                            perror("Failed to signal main process for SMF apply");
                        } else {
                            printf("Signalled main to apply pending SMF config\n");
                        }
                    }
                }
                /* Register session (if SEID present) */
                {
                    char nid_str[64] = {0};
                    if (top_ies) {
                        const struct upf_ie *node_ie = upf_find_ie(top_ies, top_n, PFCP_IE_NODE_ID, 0);
                        if (node_ie) {
                            upf_ie_to_nodeid(node_ie, nid_str, sizeof(nid_str));
                        }
                    }
                    if (nid_str[0] == '\0')
                        snprintf(nid_str, sizeof(nid_str), "%s", inet_ntoa(src->sin_addr));
                    struct remote_node *rn = find_rnode_by_id(nid_str);
                    if (!rn)
                        rn = add_rnode(nid_str, (struct sockaddr_in *)src);
                    if (seid != 0) {
                        add_session(seid, rn);
                        printf("Registered session SEID=0x%llx for node %s\n", (unsigned long long)seid, nid_str);
                    }
                }

                /* Use helper to build Session Establishment Response, then send */
                {
                    /* Find NodeID IE in top_ies (if present) and pass its raw payload to response builder */
                    const uint8_t *node_payload = NULL; uint16_t node_payload_len = 0;
                    if (top_ies) {
                        const struct upf_ie *node_ie = upf_find_ie(top_ies, top_n, PFCP_IE_NODE_ID, 0);
                        if (node_ie) {
                            node_payload = node_ie->value;
                            node_payload_len = (uint16_t)node_ie->len;
                        }
                    }
                    /* Parse F-SEID IE from request (if present) and use its SEID in response header */
                    uint64_t request_seid = 0;
                    if (top_ies) {
                        const struct upf_ie *fie = upf_find_ie(top_ies, top_n, PFCP_IE_FSEID, 0);
                        if (fie) {
                            int has_ipv4 = 0; uint32_t ipv4 = 0;
                            if (upf_ie_to_fseid(fie, &request_seid, &has_ipv4, &ipv4) != 0) {
                                request_seid = 0;
                            }
                        }
                    }
                    printf("PFCP: building Session Establishment Response (seq=%u, req_seid=0x%llx)\n",
                           seq, (unsigned long long)request_seid);
                    struct pfcp_packet pkt = newPFCPEstablishmentResponse(seq, s_flag, cfg, node_payload, node_payload_len, request_seid);
                    if (!pkt.buf || pkt.len == 0) {
                        fprintf(stderr, "PFCP: failed to build Session Establishment Response\n");
                    } else {
                        if (pfcp_send_response(pkt.buf, pkt.len, src, src_len) != 0)
                            perror("Failed to send PFCP Session Establishment Response");
                        else
                            printf("Sent PFCP Session Establishment Response\n");
                        free(pkt.buf);
                    }
                    if (top_ies) { upf_free_ies(top_ies); top_ies = NULL; }
                }
            }
        }
    }
}

void handle_session_modification_request(uint32_t seq, bool s_flag, uint64_t seid,
                                         const struct sockaddr_in *src, socklen_t src_len)
{
    printf("PFCP: Session Modification Request seq=%u SEID=%" PRIu64 "\n", seq, seid);
    
    struct pfcp_packet pkt = newPFCPSessionModificationResponse(seq, s_flag, seid);
    if (!pkt.buf || pkt.len == 0) {
        fprintf(stderr, "PFCP: failed to build Session Modification Response\n");
    } else {
        if (pfcp_send_response(pkt.buf, pkt.len, src, src_len) != 0)
            perror("Failed to send Session Modification Response");
        else
            printf("Sent Session Modification Response seq=%u\n", seq);
        free(pkt.buf);
    }
}

/* Local parsing helpers (migrated from upf_accel_pfcp.c) */

static void parse_create_far(const uint8_t *payload, size_t len, struct upf_accel_far *far)
{
    size_t off = 0;
    memset(far, 0, sizeof(*far));

    while (off + PFCP_IE_HDR_LEN <= len) {
        uint16_t t = be16(&payload[off]);
        uint16_t l = be16(&payload[off + 2]);
        size_t po = off + PFCP_IE_HDR_LEN;

        if (po + l > len) break;

        switch (t) {
        case PFCP_IE_FAR_ID:
            if (l >= 4) far->id = be32(&payload[po]);
            break;
        case PFCP_IE_FORWARDING_PARAMETERS: {
            size_t inner_off = po;
            size_t inner_end = po + l;
            while (inner_off + PFCP_IE_HDR_LEN <= inner_end) {
                uint16_t it = be16(&payload[inner_off]);
                uint16_t il = be16(&payload[inner_off + 2]);
                size_t ip = inner_off + PFCP_IE_HDR_LEN;
                if (ip + il > inner_end) break;

                if (it == PFCP_IE_OUTER_HEADER_CREATION) {
                    size_t op_off = ip;
                    size_t op_end = ip + il;
                    while (op_off + PFCP_IE_HDR_LEN <= op_end) {
                        uint16_t ot = be16(&payload[op_off]);
                        uint16_t ol = be16(&payload[op_off + 2]);
                        size_t opp = op_off + PFCP_IE_HDR_LEN;
                        if (opp + ol > op_end) break;

                        if (ot == PFCP_IE_F_TEID && ol >= 8) {
                            uint32_t teid = be32(&payload[opp + ol - 4]);
                            far->fp_oh_teid = teid;
                            if (ol >= 12) {
                                far->fp_oh_ip.addr.v4 = be32(&payload[opp + ol - 8]);
                                far->fp_oh_ip.ip_version = DOCA_FLOW_L3_TYPE_IP4;
                                far->fp_oh_ip.mask.v4 = 0xFFFFFFFF;
                            }
                        }
                        op_off = opp + ol;
                    }
                }
                inner_off = ip + il;
            }
        } break;
        default: break;
        }
        off = po + l;
    }
}

static void parse_create_qer(const uint8_t *payload, size_t len, struct upf_accel_qer *qer)
{
    memset(qer, 0, sizeof(*qer));
    size_t off = 0;
    while (off + PFCP_IE_HDR_LEN <= len) {
        uint16_t t = be16(&payload[off]);
        uint16_t l = be16(&payload[off + 2]);
        size_t po = off + PFCP_IE_HDR_LEN;
        if (po + l > len) break;
        switch (t) {
        case PFCP_IE_QER_ID:
            if (l >= 4) qer->id = be32(&payload[po]);
            break;
        case PFCP_IE_QFI:
            if (l >= 1) qer->qfi = payload[po];
            break;
        case PFCP_IE_MBR:
            if (l >= 8) {
                uint64_t mbr_dl = be64(&payload[po]);
                qer->mbr_dl_mbr = mbr_dl * 1000ULL / 8ULL;
                qer->mbr_ul_mbr = qer->mbr_dl_mbr;
            }
            break;
        default: break;
        }
        off = po + l;
    }
}

static void parse_create_urr(const uint8_t *payload, size_t len, struct upf_accel_urr *urr)
{
    memset(urr, 0, sizeof(*urr));
    size_t off = 0;
    while (off + PFCP_IE_HDR_LEN <= len) {
        uint16_t t = be16(&payload[off]);
        uint16_t l = be16(&payload[off + 2]);
        size_t po = off + PFCP_IE_HDR_LEN;
        if (po + l > len) break;
        switch (t) {
        case PFCP_IE_URR_ID:
            if (l >= 4) urr->id = be32(&payload[po]);
            break;
        case PFCP_IE_VOLUME_QUOTA:
            if (l >= 8) urr->volume_quota_total_volume = be64(&payload[po]);
            break;
        default: break;
        }
        off = po + l;
    }
}

static void parse_create_pdr(const uint8_t *payload, size_t len, struct upf_accel_pdr *pdr)
{
    memset(pdr, 0, sizeof(*pdr));
    pdr->pdi_qfi = 0;
    size_t off = 0;
    while (off + PFCP_IE_HDR_LEN <= len) {
        uint16_t t = be16(&payload[off]);
        uint16_t l = be16(&payload[off + 2]);
        size_t po = off + PFCP_IE_HDR_LEN;
        if (po + l > len) break;
        switch (t) {
        case PFCP_IE_PDR_ID:
            if (l >= 2) pdr->id = be16(&payload[po]);
            break;
        case PFCP_IE_FAR_ID:
            if (l >= 4) pdr->farid = be32(&payload[po]);
            break;
        case PFCP_IE_PDI: {
            size_t ipoff = po;
            size_t ipend = po + l;
            while (ipoff + PFCP_IE_HDR_LEN <= ipend) {
                uint16_t it = be16(&payload[ipoff]);
                uint16_t il = be16(&payload[ipoff + 2]);
                size_t ip = ipoff + PFCP_IE_HDR_LEN;
                if (ip + il > ipend) break;
                switch (it) {
                case PFCP_IE_SOURCE_INTERFACE:
                    if (il >= 1) {
                        uint8_t si = payload[ip];
                        if (si == 0) pdr->pdi_si = UPF_ACCEL_PDR_PDI_SI_UL;
                        else pdr->pdi_si = UPF_ACCEL_PDR_PDI_SI_DL;
                    }
                    break;
                case PFCP_IE_UE_IP_ADDRESS:
                    if (il >= 5) {
                        uint8_t flags = payload[ip];
                        if (flags & 0x02) { /* V4 */
                            pdr->pdi_ueip.addr.v4 = be32(&payload[ip + 1]);
                            pdr->pdi_ueip.mask.v4 = 0xFFFFFFFF;
                            pdr->pdi_ueip.ip_version = DOCA_FLOW_L3_TYPE_IP4;
                        }
                    }
                    break;
                case PFCP_IE_QFI:
                    if (il >= 1) pdr->pdi_qfi = payload[ip];
                    break;
                default: break;
                }
                ipoff = ip + il;
            }
        } break;
        case PFCP_IE_URR_ID:
            if (l >= 4 && pdr->urrids_num < UPF_ACCEL_PDR_URRIDS_LEN)
                pdr->urrids[pdr->urrids_num++] = be32(&payload[po]);
            break;
        case PFCP_IE_QER_ID:
            if (l >= 4 && pdr->qerids_num < UPF_ACCEL_PDR_QERIDS_LEN)
                pdr->qerids[pdr->qerids_num++] = be32(&payload[po]);
            break;
        default: break;
        }
        off = po + l;
    }
}

/* Existing response builders */
struct pfcp_packet newPFCPEstablishmentResponse(uint32_t seq, bool s_flag, struct upf_accel_config *cfg,
                                                const uint8_t *nodeid, uint16_t nodeid_len,
                                                uint64_t request_seid)
{
    struct pfcp_packet pkt = { NULL, 0 };

    /* Build IE parts: NodeID, Cause, F-SEID and Created PDRs */
    uint8_t *parts[16]; size_t parts_len[16]; size_t parts_cnt = 0;
    memset(parts, 0, sizeof(parts)); memset(parts_len, 0, sizeof(parts_len));

    uint32_t local_ip = ntohl(inet_addr("192.168.100.2"));

    /* NodeID IE */
    {
        uint8_t *b = NULL; size_t bl = 0;
        if (upf_build_nodeid_ipv4(local_ip, &b, &bl) == 0) {
            parts[parts_cnt] = b; parts_len[parts_cnt] = bl; parts_cnt++;
        }
    }

    /* Cause IE */
    {
        uint8_t *b = NULL; size_t bl = 0;
        if (upf_build_cause(1, 0, 0, &b, &bl) == 0) {
            parts[parts_cnt] = b; parts_len[parts_cnt] = bl; parts_cnt++;
        }
    }

    /* F-SEID IE */
    {
        uint32_t ip_be = local_ip;
        int has_ipv4 = 1;
        uint8_t *b = NULL; size_t bl = 0;
        if (upf_build_fseid(request_seid, has_ipv4, ip_be, &b, &bl) == 0) {
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
                nested[noff++] = 0; nested[noff++] = 2;
                nested[noff++] = (uint8_t)((p->id >> 8) & 0xff);
                nested[noff++] = (uint8_t)(p->id & 0xff);
                
                /* UE IP address IE */
                nested[noff++] = (uint8_t)(PFCP_IE_UE_IP_ADDRESS >> 8);
                nested[noff++] = (uint8_t)(PFCP_IE_UE_IP_ADDRESS & 0xff);
                nested[noff++] = 0; nested[noff++] = 5;
                nested[noff++] = 0x02; /* Flags: V4=1 */
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

    size_t buf_size = 4 + (s_flag ? 8 : 0) + 4;
    for (size_t i = 0; i < parts_cnt; ++i) buf_size += parts_len[i];

    uint8_t *out = malloc(buf_size);
    if (!out) {
        for (size_t i = 0; i < parts_cnt; ++i) free(parts[i]);
        return pkt;
    }

    size_t ro = 0;
    uint8_t oct1_final = (1 << 5) | (s_flag ? 0x01 : 0);
    out[ro++] = oct1_final;
    out[ro++] = PFCP_MSG_SESSION_ESTABLISHMENT_RESPONSE;
    ro += 2; /* length placeholder */
    if (s_flag) {
        uint64_t use_seid = request_seid;
        for (int i = 7; i >= 0; --i) {
            out[ro + i] = (uint8_t)(use_seid & 0xff);
            use_seid >>= 8;
        }
        ro += 8;
    }
    out[ro++] = (uint8_t)((seq >> 16) & 0xff);
    out[ro++] = (uint8_t)((seq >> 8) & 0xff);
    out[ro++] = (uint8_t)(seq & 0xff);
    out[ro++] = 0; /* priority */

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

struct pfcp_packet newPFCPSessionModificationResponse(uint32_t seq, bool s_flag, uint64_t seid)
{
    struct pfcp_packet pkt = { NULL, 0 };
    uint8_t *parts[16]; size_t parts_len[16]; size_t parts_cnt = 0;
    memset(parts, 0, sizeof(parts)); memset(parts_len, 0, sizeof(parts_len));

    {
        uint8_t *b = NULL; size_t bl = 0;
        if (upf_build_cause(1, 0, 0, &b, &bl) == 0) {
            parts[parts_cnt] = b; parts_len[parts_cnt] = bl; parts_cnt++;
        }
    }

    size_t buf_size = 4 + (s_flag ? 8 : 0) + 4;
    for (size_t i = 0; i < parts_cnt; ++i) buf_size += parts_len[i];

    uint8_t *out = malloc(buf_size);
    if (!out) {
        for (size_t i = 0; i < parts_cnt; ++i) free(parts[i]);
        return pkt;
    }

    size_t ro = 0;
    uint8_t oct1_final = (1 << 5) | (s_flag ? 0x01 : 0);
    out[ro++] = oct1_final;
    out[ro++] = PFCP_MSG_SESSION_MODIFICATION_RESPONSE;
    ro += 2;
    if (s_flag) {
        uint64_t use_seid = seid;
        for (int i = 7; i >= 0; --i) {
            out[ro + i] = (uint8_t)(use_seid & 0xff);
            use_seid >>= 8;
        }
        ro += 8;
    }
    out[ro++] = (uint8_t)((seq >> 16) & 0xff);
    out[ro++] = (uint8_t)((seq >> 8) & 0xff);
    out[ro++] = (uint8_t)(seq & 0xff);
    out[ro++] = 0;

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
