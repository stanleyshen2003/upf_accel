#include "upf_accel_pfcp_ie.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static inline uint16_t be16(const uint8_t *b)
{
    return (uint16_t)((b[0] << 8) | b[1]);
}

static inline uint32_t be32(const uint8_t *b)
{
    return (uint32_t)((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]);
}

static inline uint64_t be64(const uint8_t *b)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i)
        v = (v << 8) | b[i];
    return v;
}

int upf_parse_ies(const uint8_t *buf, size_t buflen, size_t start_off, struct upf_ie **ies_out, size_t *num_out)
{
    if (!buf || !ies_out || !num_out) return -1;
    size_t off = start_off;
    size_t count = 0;

    /* First pass: count */
    while (off + PFCP_IE_HDR_LEN <= buflen) {
        uint16_t t = be16(&buf[off]);
        uint16_t l = be16(&buf[off + 2]);
        size_t po = off + PFCP_IE_HDR_LEN;
        if (po + l > buflen) break;
        count++;
        off = po + l;
    }

    if (count == 0) {
        *ies_out = NULL;
        *num_out = 0;
        return 0;
    }

    struct upf_ie *arr = calloc(count, sizeof(*arr));
    if (!arr) return -1;

    off = start_off;
    size_t idx = 0;
    while (off + PFCP_IE_HDR_LEN <= buflen && idx < count) {
        uint16_t t = be16(&buf[off]);
        uint16_t l = be16(&buf[off + 2]);
        uint8_t inst = buf[off + 4];
        size_t po = off + PFCP_IE_HDR_LEN;
        if (po + l > buflen) break;
        arr[idx].type = t;
        arr[idx].len = l;
        arr[idx].instance = inst;
        arr[idx].value = &buf[po];
        idx++;
        off = po + l;
    }

    *ies_out = arr;
    *num_out = idx;
    return 0;
}

void upf_free_ies(struct upf_ie *ies)
{
    free(ies);
}

const struct upf_ie *upf_find_ie(const struct upf_ie *ies, size_t num, uint16_t ie_type, size_t index)
{
    size_t i, cnt = 0;
    for (i = 0; i < num; ++i) {
        if (ies[i].type == ie_type) {
            if (cnt == index) return &ies[i];
            cnt++;
        }
    }
    return NULL;
}

int upf_ie_to_nodeid(const struct upf_ie *ie, char *out, size_t outlen)
{
    if (!ie || !out) return -1;
    if (ie->len == 4) {
        snprintf(out, outlen, "%u.%u.%u.%u", ie->value[0], ie->value[1], ie->value[2], ie->value[3]);
        return 0;
    }
    /* Hex encode shorter/other NodeID types */
    size_t k; size_t w = 0;
    for (k = 0; k < ie->len && w + 3 < outlen; ++k) {
        int n = snprintf(out + w, outlen - w, "%02x", ie->value[k]);
        if (n < 0) break;
        w += (size_t)n;
    }
    out[w < outlen ? w : outlen - 1] = '\0';
    return 0;
}

int upf_ie_to_uint32(const struct upf_ie *ie, uint32_t *v)
{
    if (!ie || !v) return -1;
    if (ie->len < 4) return -1;
    *v = be32(ie->value);
    return 0;
}

int upf_ie_to_uint64(const struct upf_ie *ie, uint64_t *v)
{
    if (!ie || !v) return -1;
    if (ie->len < 8) return -1;
    *v = be64(ie->value);
    return 0;
}

/* Parse grouped children inside a Create* IE by calling upf_parse_ies on the
 * IE value buffer. Helper returns 0 on success. Caller must call
 * upf_free_ies() for returned array. */
static int parse_children(const struct upf_ie *ie, struct upf_ie **out, size_t *num)
{
    if (!ie || !out || !num) return -1;
    return upf_parse_ies(ie->value, ie->len, 0, out, num);
}

int upf_parse_create_pdr(const struct upf_ie *ie, struct upf_parsed_pdr *out)
{
    if (!ie || !out) return -1;
    memset(out, 0, sizeof(*out));
    struct upf_ie *kids = NULL; size_t nk = 0;
    if (parse_children(ie, &kids, &nk) != 0) return -1;
    size_t i;
    for (i = 0; i < nk; ++i) {
        const struct upf_ie *k = &kids[i];
        switch (k->type) {
        case PFCP_IE_PDR_ID:
            if (k->len >= 4) out->id = be32(k->value);
            break;
        case PFCP_IE_FAR_ID:
            if (k->len >= 4) out->far_id = be32(k->value);
            break;
        case PFCP_IE_URR_ID:
            if (k->len >= 4 && out->urr_count < sizeof(out->urr_ids)/4) out->urr_ids[out->urr_count++] = be32(k->value);
            break;
        case PFCP_IE_QER_ID:
            if (k->len >= 4 && out->qer_count < sizeof(out->qer_ids)/4) out->qer_ids[out->qer_count++] = be32(k->value);
            break;
        case PFCP_IE_PDI: {
            /* parse nested children of PDI */
            struct upf_ie *pdi_k = NULL; size_t pdi_n = 0;
            if (upf_parse_ies(k->value, k->len, 0, &pdi_k, &pdi_n) == 0) {
                size_t j;
                for (j = 0; j < pdi_n; ++j) {
                    const struct upf_ie *pk = &pdi_k[j];
                    switch (pk->type) {
                    case PFCP_IE_SOURCE_INTERFACE:
                        if (pk->len >= 1) out->pdi_si = pk->value[0];
                        break;
                    case PFCP_IE_UE_IP_ADDRESS:
                        if (pk->len >= 4) { out->ue_ip_v4 = be32(pk->value); out->has_ue_ip = 1; }
                        break;
                    case PFCP_IE_QFI:
                        if (pk->len >= 1) { out->qfi = pk->value[0]; out->has_qfi = 1; }
                        break;
                    default:
                        break;
                    }
                }
                upf_free_ies(pdi_k);
            }
        } break;
        default:
            break;
        }
    }
    upf_free_ies(kids);
    return 0;
}

int upf_parse_create_far(const struct upf_ie *ie, struct upf_parsed_far *out)
{
    if (!ie || !out) return -1;
    memset(out, 0, sizeof(*out));
    struct upf_ie *kids = NULL; size_t nk = 0;
    if (parse_children(ie, &kids, &nk) != 0) return -1;
    size_t i;
    for (i = 0; i < nk; ++i) {
        const struct upf_ie *k = &kids[i];
        switch (k->type) {
        case PFCP_IE_FAR_ID:
            if (k->len >= 4) out->id = be32(k->value);
            break;
        case PFCP_IE_FORWARDING_PARAMETERS: {
            struct upf_ie *fp_k = NULL; size_t fp_n = 0;
            if (upf_parse_ies(k->value, k->len, 0, &fp_k, &fp_n) == 0) {
                size_t j;
                for (j = 0; j < fp_n; ++j) {
                    const struct upf_ie *fk = &fp_k[j];
                    if (fk->type == PFCP_IE_OUTER_HEADER_CREATION) {
                        struct upf_ie *oh_k = NULL; size_t oh_n = 0;
                        if (upf_parse_ies(fk->value, fk->len, 0, &oh_k, &oh_n) == 0) {
                            size_t m;
                            for (m = 0; m < oh_n; ++m) {
                                const struct upf_ie *ok = &oh_k[m];
                                if (ok->type == PFCP_IE_F_TEID && ok->len >= 8) {
                                    /* TEID in last 4 bytes */
                                    out->outer_teid = be32(&ok->value[ok->len - 4]);
                                    out->has_outer_teid = 1;
                                    if (ok->len >= 12) {
                                        out->outer_ip_v4 = be32(&ok->value[ok->len - 8]);
                                        out->has_outer_ip = 1;
                                    }
                                }
                            }
                            upf_free_ies(oh_k);
                        }
                    }
                }
                upf_free_ies(fp_k);
            }
        } break;
        default:
            break;
        }
    }
    upf_free_ies(kids);
    return 0;
}

int upf_parse_create_qer(const struct upf_ie *ie, struct upf_parsed_qer *out)
{
    if (!ie || !out) return -1;
    memset(out, 0, sizeof(*out));
    struct upf_ie *kids = NULL; size_t nk = 0;
    if (parse_children(ie, &kids, &nk) != 0) return -1;
    size_t i;
    for (i = 0; i < nk; ++i) {
        const struct upf_ie *k = &kids[i];
        switch (k->type) {
        case PFCP_IE_QER_ID:
            if (k->len >= 4) out->id = be32(k->value);
            break;
        case PFCP_IE_QFI:
            if (k->len >= 1) { out->qfi = k->value[0]; out->has_qfi = 1; }
            break;
        case PFCP_IE_MBR:
            if (k->len >= 8) { out->mbr_dl = be64(k->value); out->has_mbr = 1; }
            break;
        default:
            break;
        }
    }
    upf_free_ies(kids);
    return 0;
}

int upf_parse_create_urr(const struct upf_ie *ie, struct upf_parsed_urr *out)
{
    if (!ie || !out) return -1;
    memset(out, 0, sizeof(*out));
    struct upf_ie *kids = NULL; size_t nk = 0;
    if (parse_children(ie, &kids, &nk) != 0) return -1;
    size_t i;
    for (i = 0; i < nk; ++i) {
        const struct upf_ie *k = &kids[i];
        switch (k->type) {
        case PFCP_IE_URR_ID:
            if (k->len >= 4) out->id = be32(k->value);
            break;
        case PFCP_IE_VOLUME_QUOTA:
            if (k->len >= 8) { out->volume_quota = be64(k->value); out->has_volume = 1; }
            break;
        default:
            break;
        }
    }
    upf_free_ies(kids);
    return 0;
}

/* Generic IE builder: allocate buffer with Type(2) Length(2) Instance(1) Value(len)
 * Returns 0 on success and fills *out_buf/*out_len. Caller must free *out_buf. */
int upf_build_ie(uint16_t ie_type, uint8_t instance, const uint8_t *value, uint16_t vlen, uint8_t **out_buf, size_t *out_len)
{
    if (!out_buf || !out_len) return -1;
    size_t total = PFCP_IE_HDR_LEN + vlen;
    uint8_t *b = malloc(total);
    if (!b) return -1;
    /* Type (big-endian) */
    b[0] = (uint8_t)((ie_type >> 8) & 0xff);
    b[1] = (uint8_t)(ie_type & 0xff);
    /* Length (big-endian) */
    b[2] = (uint8_t)((vlen >> 8) & 0xff);
    b[3] = (uint8_t)(vlen & 0xff);
    /* Instance */
    b[4] = instance;
    if (vlen && value)
        memcpy(&b[PFCP_IE_HDR_LEN], value, vlen);
    *out_buf = b;
    *out_len = total;
    return 0;
}

/* Convenience NodeID builder for IPv4 address.
 * ip_be: IPv4 address in network byte order (big-endian uint32_t).
 * Produces an IE with type PFCP_IE_NODE_ID and payload 4 bytes. */
int upf_build_nodeid_ipv4(uint32_t ip_be, uint8_t **out_buf, size_t *out_len)
{
    uint8_t ipv4[4];
    ipv4[0] = (uint8_t)((ip_be >> 24) & 0xff);
    ipv4[1] = (uint8_t)((ip_be >> 16) & 0xff);
    ipv4[2] = (uint8_t)((ip_be >> 8) & 0xff);
    ipv4[3] = (uint8_t)(ip_be & 0xff);
    return upf_build_ie(PFCP_IE_NODE_ID, 0, ipv4, 4, out_buf, out_len);
}

/* Parse a Cause IE into struct upf_cause */
int upf_ie_to_cause(const struct upf_ie *ie, struct upf_cause *out)
{
    if (!ie || !out) return -1;
    if (ie->len < 1) return -1;
    out->cause = ie->value[0];
    if (ie->len >= 2) {
        out->has_value = 1;
        out->value = ie->value[1];
    } else {
        out->has_value = 0;
        out->value = 0;
    }
    return 0;
}

/* Build Cause IE */
int upf_build_cause(uint8_t cause, int has_value, uint8_t value, uint8_t **out_buf, size_t *out_len)
{
    uint8_t payload[2]; size_t plen = 1;
    payload[0] = cause;
    if (has_value) {
        payload[1] = value;
        plen = 2;
    }
    return upf_build_ie(PFCP_IE_CAUSE, 0, payload, (uint16_t)plen, out_buf, out_len);
}
