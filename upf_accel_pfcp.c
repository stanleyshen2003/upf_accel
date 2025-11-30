/* Minimal PFCP implementation: UDP listener + basic header parsing */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
/* POSIX sockets & threading */
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <errno.h>

#include "upf_accel_pfcp.h"
#include "upf_accel.h"
#include "upf_accel_smf_default_init.h"
#include "upf_accel_pfcp_ie.h"
#include "upf_accel_pfcp_packet.h"
#include "upf_accel_pfcp_session.h"
#include "upf_accel_pfcp_association.h"
#include "upf_accel_pfcp_generic.h"
#include <time.h>

/* PFCP IE header length: Type (2) + Length (2) + Instance (1) */
#define PFCP_IE_HDR_LEN 5

/* Forward declarations for endian helpers (used in parsing before their full definitions) */
static inline uint16_t be16(const uint8_t *b);
static inline uint32_t be32(const uint8_t *b);
static inline uint64_t be64(const uint8_t *b);

/* Simple RemoteNode and Session storage to track association state */
struct remote_node {
    char id[64];
    struct sockaddr_in addr;
    struct remote_node *next;
};

struct pfcp_session {
    uint64_t seid;
    struct remote_node *rnode;
    struct pfcp_session *next;
};

static struct remote_node *rnodes_head = NULL;
static pthread_mutex_t rnodes_lock = PTHREAD_MUTEX_INITIALIZER;

static struct pfcp_session *sess_head = NULL;
static pthread_mutex_t sess_lock = PTHREAD_MUTEX_INITIALIZER;

/* Transactions (simple) - store rx transactions so responses can be correlated */
struct rx_trans {
    char id[128]; /* addr-seq */
    struct sockaddr_in addr;
    uint32_t seq;
    time_t ts;
    struct rx_trans *next;
};

static struct rx_trans *rx_head = NULL;
static pthread_mutex_t rx_lock = PTHREAD_MUTEX_INITIALIZER;

/* Helpers to manage RemoteNodes */
/*
 * find_rnode_by_id - lookup a registered remote PFCP node by its identifier
 * @id: NUL-terminated identifier string (e.g. NodeID hex or IPv4 textual)
 *
 * Returns: pointer to the matching `struct remote_node` if found, or NULL
 *          if no matching node exists.
 * Notes: acquires `rnodes_lock` while searching; caller must not hold lock.
 */
static struct remote_node *find_rnode_by_id(const char *id)
{
    struct remote_node *it;
    pthread_mutex_lock(&rnodes_lock);
    for (it = rnodes_head; it; it = it->next) {
        if (strncmp(it->id, id, sizeof(it->id)) == 0) {
            pthread_mutex_unlock(&rnodes_lock);
            return it;
        }
    }
    pthread_mutex_unlock(&rnodes_lock);
    return NULL;
}

/*
 * add_rnode - register a new remote PFCP node
 * @id: identifier string to store (will be copied)
 * @addr: pointer to the sockaddr_in address from which messages were received
 *
 * Returns: pointer to the newly allocated `struct remote_node` on success,
 *          or NULL on allocation failure.
 * Notes: caller should ensure @id is a valid NUL-terminated string.
 */
static struct remote_node *add_rnode(const char *id, struct sockaddr_in *addr)
{
    struct remote_node *n = calloc(1, sizeof(*n));
    if (!n)
        return NULL;
    strncpy(n->id, id, sizeof(n->id) - 1);
    n->addr = *addr;
    pthread_mutex_lock(&rnodes_lock);
    n->next = rnodes_head;
    rnodes_head = n;
    pthread_mutex_unlock(&rnodes_lock);
    return n;
}

/* Session helpers */
/*
 * find_session - find a PFCP session by SEID
 * @seid: SEID value to search for
 *
 * Returns: pointer to `struct pfcp_session` if found, or NULL otherwise.
 * Notes: acquires `sess_lock` during search; caller must not hold lock.
 */
static struct pfcp_session *find_session(uint64_t seid)
{
    struct pfcp_session *s;
    pthread_mutex_lock(&sess_lock);
    for (s = sess_head; s; s = s->next) {
        if (s->seid == seid) {
            pthread_mutex_unlock(&sess_lock);
            return s;
        }
    }
    pthread_mutex_unlock(&sess_lock);
    return NULL;
}

/*
 * add_session - add a PFCP session record
 * @seid: SEID of the session
 * @rn: pointer to the associated remote_node
 *
 * Returns: pointer to the newly allocated `struct pfcp_session` on success,
 *          or NULL on allocation failure.
 */
static struct pfcp_session *add_session(uint64_t seid, struct remote_node *rn)
{
    struct pfcp_session *s = calloc(1, sizeof(*s));
    if (!s)
        return NULL;
    s->seid = seid;
    s->rnode = rn;
    pthread_mutex_lock(&sess_lock);
    s->next = sess_head;
    sess_head = s;
    pthread_mutex_unlock(&sess_lock);
    return s;
}

/*
 * remove_session - remove and free a PFCP session by SEID
 * @seid: SEID identifying the session to remove
 *
 * Returns: nothing. If the session exists it is removed and freed.
 */
static void remove_session(uint64_t seid)
{
    pthread_mutex_lock(&sess_lock);
    struct pfcp_session **pp = &sess_head;
    while (*pp) {
        if ((*pp)->seid == seid) {
            struct pfcp_session *rm = *pp;
            *pp = rm->next;
            free(rm);
            break;
        }
        pp = &(*pp)->next;
    }
    pthread_mutex_unlock(&sess_lock);
}

/* Rx transaction helpers */
/*
 * rx_trans_add - record a received PFCP transaction for later correlation
 * @addr: source address of the received PFCP packet
 * @seq: PFCP sequence number from the packet
 *
 * Returns: nothing. Allocates and inserts a small tracking record used to
 *          correlate requests and responses.
 */
static void rx_trans_add(const struct sockaddr_in *addr, uint32_t seq)
{
    char id[128];
    snprintf(id, sizeof(id), "%s-%u", inet_ntoa(addr->sin_addr), seq);
    struct rx_trans *r = calloc(1, sizeof(*r));
    if (!r)
        return;
    strncpy(r->id, id, sizeof(r->id) - 1);
    r->addr = *addr;
    r->seq = seq;
    r->ts = time(NULL);
    pthread_mutex_lock(&rx_lock);
    r->next = rx_head;
    rx_head = r;
    pthread_mutex_unlock(&rx_lock);
}

/*
 * rx_trans_find_and_remove - find and remove a recorded rx transaction
 * @addr: source address to match
 * @seq: sequence number to match
 *
 * Returns: pointer to the removed `struct rx_trans` if found (caller must
 *          free it), or NULL if no matching entry exists.
 */
static struct rx_trans *rx_trans_find_and_remove(const struct sockaddr_in *addr, uint32_t seq)
{
    char id[128];
    snprintf(id, sizeof(id), "%s-%u", inet_ntoa(addr->sin_addr), seq);
    pthread_mutex_lock(&rx_lock);
    struct rx_trans **pp = &rx_head;
    while (*pp) {
        if (strncmp((*pp)->id, id, sizeof((*pp)->id)) == 0) {
            struct rx_trans *r = *pp;
            *pp = r->next;
            pthread_mutex_unlock(&rx_lock);
            return r;
        }
        pp = &(*pp)->next;
    }
    pthread_mutex_unlock(&rx_lock);
    return NULL;
}

/* Find first IE of the given type starting at offset hdr_off */
/*
 * find_ie_in_msg - scan PFCP message buffer for first IE of a given type
 * @buf: pointer to PFCP message buffer
 * @buflen: total length of @buf
 * @start_off: offset within @buf to start scanning (typically header end)
 * @ie_type: numeric IE type to search for
 * @payload_out: optional out pointer set to the IE payload (first byte)
 * @len_out: optional out pointer set to the IE payload length
 *
 * Returns: 0 on success and sets outputs, -1 if not found or malformed.
 */
static int find_ie_in_msg(const uint8_t *buf, size_t buflen, size_t start_off, uint16_t ie_type, const uint8_t **payload_out, uint16_t *len_out)
{
    size_t off = start_off;
    while (off + PFCP_IE_HDR_LEN <= buflen) {
        uint16_t t = be16(&buf[off]);
        uint16_t l = be16(&buf[off + 2]);
        size_t po = off + PFCP_IE_HDR_LEN; /* payload offset after type/len/instance */
        /* Debug: log parsed IE header and small payload sample */
        {
            unsigned inst = (unsigned)buf[off + 4];
            printf("PFCP: parsed IE @%zu: type=%u len=%u inst=%u payload_off=%zu\n", off, (unsigned)t, (unsigned)l, inst, po);
            if (l > 0) {
                size_t dlen = l < 8 ? l : 8;
                size_t i;
                printf("PFCP: IE payload sample: ");
                for (i = 0; i < dlen; ++i)
                    printf("%02x", (unsigned)buf[po + i]);
                printf("\n");
            }
        }
        if (po + l > buflen)
            return -1;
        if (t == ie_type) {
            if (payload_out) *payload_out = &buf[po];
            if (len_out) *len_out = l;
            return 0;
        }
        off = po + l;
    }
    return -1;
}

/* Helper: read big-endian u16/u32/u64 from buffer */
/*
 * be16 - read a big-endian 16-bit value from buffer
 * @b: pointer to at least 2 bytes of big-endian data
 *
 * Returns: native-endian uint16_t value
 */
static inline uint16_t be16(const uint8_t *b)
{
    return (uint16_t)((b[0] << 8) | b[1]);
}

/*
 * be32 - read a big-endian 32-bit value from buffer
 * @b: pointer to at least 4 bytes of big-endian data
 *
 * Returns: native-endian uint32_t value
 */
static inline uint32_t be32(const uint8_t *b)
{
    return (uint32_t)((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]);
}

/*
 * be64 - read a big-endian 64-bit value from buffer
 * @b: pointer to at least 8 bytes of big-endian data
 *
 * Returns: native-endian uint64_t value
 */
static inline uint64_t be64(const uint8_t *b)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i)
        v = (v << 8) | b[i];
    return v;
}

/* Parse a CreateFAR IE payload into upf_accel_far */
/*
 * parse_create_far - parse a CreateFAR IE payload into internal FAR structure
 * @payload: pointer to the IE payload (first byte after IE header)
 * @len: length of the IE payload in bytes
 * @far: pointer to `struct upf_accel_far` to populate
 *
 * Returns: nothing. Populates fields of @far (id, outer-header info) where
 *          present. Parsing is tolerant; unknown children are skipped.
 */
static void parse_create_far(const uint8_t *payload, size_t len, struct upf_accel_far *far)
{
    size_t off = 0; /* offset into payload while scanning child IEs */
    memset(far, 0, sizeof(*far));

    /* Iterate over top-level child IEs inside the CreateFAR payload. Each IE
     * has a 2-byte type and 2-byte length followed by `length` bytes of value. */
    while (off + PFCP_IE_HDR_LEN <= len) {
        uint16_t t = be16(&payload[off]);        /* IE type */
        uint16_t l = be16(&payload[off + 2]);    /* IE length */
        size_t po = off + PFCP_IE_HDR_LEN;       /* payload offset of this IE */

        /* Bounds check: ensure the reported length fits inside the overall payload */
        if (po + l > len)
            break;

        switch (t) {
        case PFCP_IE_FAR_ID:
            /* FAR ID is a 4-byte integer identifying the FAR */
            if (l >= 4)
                far->id = be32(&payload[po]);
            break;

        case PFCP_IE_FORWARDING_PARAMETERS: {
            /* ForwardingParameters is a grouped IE. We scan its children for
             * OuterHeaderCreation; inside that we look for an F-TEID which
             * commonly carries TEID and optionally an IPv4 address. */
            size_t inner_off = po;
            size_t inner_end = po + l;

            while (inner_off + PFCP_IE_HDR_LEN <= inner_end) {
                uint16_t it = be16(&payload[inner_off]);
                uint16_t il = be16(&payload[inner_off + 2]);
                size_t ip = inner_off + PFCP_IE_HDR_LEN; /* inner payload offset */
                if (ip + il > inner_end)
                    break;

                if (it == PFCP_IE_OUTER_HEADER_CREATION) {
                    /* Scan children of OuterHeaderCreation for F-TEID */
                    size_t op_off = ip;
                    size_t op_end = ip + il;
                    while (op_off + PFCP_IE_HDR_LEN <= op_end) {
                        uint16_t ot = be16(&payload[op_off]);
                        uint16_t ol = be16(&payload[op_off + 2]);
                        size_t opp = op_off + PFCP_IE_HDR_LEN;
                        if (opp + ol > op_end)
                            break;

                        if (ot == PFCP_IE_F_TEID && ol >= 8) {
                            /* F-TEID format: variable flags + optional IPv4/IPv6 + TEID
                             * We read the TEID from the final 4 bytes of this IE value. */
                            uint32_t teid = be32(&payload[opp + ol - 4]);
                            far->fp_oh_teid = teid;
                            /* If an IPv4 address is present it typically precedes the TEID */
                            if (ol >= 12) {
                                far->fp_oh_ip.addr.v4 = be32(&payload[opp + ol - 8]);
                                far->fp_oh_ip.ip_version = DOCA_FLOW_L3_TYPE_IP4;
                                far->fp_oh_ip.mask.v4 = 0xFFFFFFFF;
                            }
                        }

                        op_off = opp + ol; /* advance to next child of OuterHeaderCreation */
                    }
                }

                inner_off = ip + il; /* advance to next inner child IE */
            }
        } break;

        default:
            /* Unknown IE type inside CreateFAR; skip gracefully */
            break;
        }

        off = po + l; /* advance to next top-level IE inside CreateFAR */
    }
}

/* Parse CreateQER IE into upf_accel_qer */
/*
 * parse_create_qer - parse a CreateQER IE payload into internal QER structure
 * @payload: pointer to the IE payload
 * @len: length of payload
 * @qer: pointer to `struct upf_accel_qer` to populate
 *
 * Returns: nothing. Fills `id`, `qfi` and approximate MBR fields when present.
 */
static void parse_create_qer(const uint8_t *payload, size_t len, struct upf_accel_qer *qer)
{
    memset(qer, 0, sizeof(*qer));
    size_t off = 0;
    while (off + PFCP_IE_HDR_LEN <= len) {
        uint16_t t = be16(&payload[off]);
        uint16_t l = be16(&payload[off + 2]);
        size_t po = off + PFCP_IE_HDR_LEN;
        if (po + l > len)
            break;
        switch (t) {
        case PFCP_IE_QER_ID:
            if (l >= 4)
                qer->id = be32(&payload[po]);
            break;
        case PFCP_IE_QFI:
            if (l >= 1)
                qer->qfi = payload[po];
            break;
        case PFCP_IE_MBR:
            /* MBR contains GBR/MBR DL/UL in nested format; simple approach: read first 8 bytes as DL mbr (kbps) */
            if (l >= 8) {
                uint64_t mbr_dl = be64(&payload[po]);
                /* convert kilobits per second to bytes per second roughly */
                qer->mbr_dl_mbr = mbr_dl * 1000ULL / 8ULL;
                qer->mbr_ul_mbr = qer->mbr_dl_mbr;
            }
            break;
        default:
            break;
        }
        off = po + l;
    }
}

/* Parse CreateURR into upf_accel_urr */
/*
 * parse_create_urr - parse a CreateURR IE payload into internal URR structure
 * @payload: pointer to the IE payload
 * @len: length of payload
 * @urr: pointer to `struct upf_accel_urr` to populate
 *
 * Returns: nothing. Extracts URR id and simple quota fields if present.
 */
static void parse_create_urr(const uint8_t *payload, size_t len, struct upf_accel_urr *urr)
{
    memset(urr, 0, sizeof(*urr));
    size_t off = 0;
    while (off + PFCP_IE_HDR_LEN <= len) {
        uint16_t t = be16(&payload[off]);
        uint16_t l = be16(&payload[off + 2]);
        size_t po = off + PFCP_IE_HDR_LEN;
        if (po + l > len)
            break;
        switch (t) {
        case PFCP_IE_URR_ID:
            if (l >= 4)
                urr->id = be32(&payload[po]);
            break;
        case PFCP_IE_VOLUME_QUOTA:
            if (l >= 8)
                urr->volume_quota_total_volume = be64(&payload[po]);
            break;
        default:
            break;
        }
        off = po + l;
    }
}

/* Parse CreatePDR into upf_accel_pdr (partial) */
/*
 * parse_create_pdr - parse a CreatePDR IE payload into internal PDR structure
 * @payload: pointer to the IE payload
 * @len: length of payload
 * @pdr: pointer to `struct upf_accel_pdr` to populate
 *
 * Returns: nothing. Parses PDR id, FAR id, PDI (UE IP, source interface, QFI),
 *          and collects referenced URR/QER ids in the pdr structure.
 */
static void parse_create_pdr(const uint8_t *payload, size_t len, struct upf_accel_pdr *pdr)
{
    memset(pdr, 0, sizeof(*pdr));
    pdr->pdi_qfi = 0;
    size_t off = 0;
    while (off + PFCP_IE_HDR_LEN <= len) {
        uint16_t t = be16(&payload[off]);
        uint16_t l = be16(&payload[off + 2]);
        size_t po = off + PFCP_IE_HDR_LEN;
        if (po + l > len)
            break;
        switch (t) {
        case PFCP_IE_PDR_ID:
            if (l >= 4)
                pdr->id = be32(&payload[po]);
            break;
        case PFCP_IE_FAR_ID:
            if (l >= 4)
                pdr->farid = be32(&payload[po]);
            break;
        case PFCP_IE_PDI:
            /* PDI is grouped IE, parse children inside payload */
            {
                size_t ipoff = po;
                size_t ipend = po + l;
                while (ipoff + PFCP_IE_HDR_LEN <= ipend) {
                    uint16_t it = be16(&payload[ipoff]);
                    uint16_t il = be16(&payload[ipoff + 2]);
                    size_t ip = ipoff + PFCP_IE_HDR_LEN;
                    if (ip + il > ipend)
                        break;
                    switch (it) {
                    case PFCP_IE_SOURCE_INTERFACE:
                        if (il >= 1) {
                            uint8_t si = payload[ip];
                            if (si == 0) /* access? */
                                pdr->pdi_si = UPF_ACCEL_PDR_PDI_SI_UL;
                            else
                                pdr->pdi_si = UPF_ACCEL_PDR_PDI_SI_DL;
                        }
                        break;
                    case PFCP_IE_UE_IP_ADDRESS:
                        if (il >= 4) {
                            /* assume IPv4 address in first 4 bytes */
                            pdr->pdi_ueip.addr.v4 = be32(&payload[ip]);
                            pdr->pdi_ueip.mask.v4 = 0xFFFFFFFF;
                            pdr->pdi_ueip.ip_version = DOCA_FLOW_L3_TYPE_IP4;
                        }
                        break;
                    case PFCP_IE_SDF_FILTER:
                        /* SDF may include IP addresses and port ranges; skipping detailed parse for now */
                        break;
                    case PFCP_IE_QFI:
                        if (il >= 1)
                            pdr->pdi_qfi = payload[ip];
                        break;
                    default:
                        break;
                    }
                    ipoff = ip + il;
                }
            }
            break;
        case PFCP_IE_URR_ID:
            if (l >= 4 && pdr->urrids_num < UPF_ACCEL_PDR_URRIDS_LEN) {
                pdr->urrids[pdr->urrids_num++] = be32(&payload[po]);
            }
            break;
        case PFCP_IE_QER_ID:
            if (l >= 4 && pdr->qerids_num < UPF_ACCEL_PDR_QERIDS_LEN) {
                pdr->qerids[pdr->qerids_num++] = be32(&payload[po]);
            }
            break;
        default:
            break;
        }
        off = po + l;
    }
}

/* PFCP UDP listener and parser (POSIX sockets) */
static int pfcp_sock = -1;
static pthread_t pfcp_thread = 0;
static volatile bool pfcp_thread_running = false;

/*
 * pfcp_send_response - send PFCP response reliably from PFCP code
 * @buf: pointer to response buffer
 * @len: length of response
 * @dst: destination sockaddr_in
 * @dstlen: length of dst sockaddr
 *
 * Tries to send using the global `pfcp_sock`. If the global socket is
 * invalid (EBADF) or sendto otherwise fails, logs the error and attempts to
 * create a temporary socket to send the packet as a best-effort fallback.
 * This helps in cases where the global socket was closed concurrently or
 * otherwise became invalid.
 *
 * Returns: 0 on success, -1 on failure.
 */
static void print_hex_full(const char *label, const uint8_t *buf, size_t len);
int pfcp_send_response(const uint8_t *buf, size_t len, const struct sockaddr_in *dst, socklen_t dstlen)
{
    ssize_t s = -1;
    if (pfcp_sock >= 0) {
        printf("PFCP: attempting sendto on global socket fd=%d len=%zu\n", pfcp_sock, len);
        /* Log outgoing bytes in hex for debugging */
        print_hex_full("PFCP: outgoing (hex)", buf, len);
        s = sendto(pfcp_sock, (const char *)buf, (int)len, 0, (const struct sockaddr *)dst, dstlen);
        if (s >= 0)
            return 0;
        /* log the error and fall through to fallback attempt */
        fprintf(stderr, "PFCP: sendto on pfcp_sock=%d failed: %s\n", pfcp_sock, strerror(errno));
    } else {
        fprintf(stderr, "PFCP: global pfcp_sock is invalid (pfcp_sock=%d)\n", pfcp_sock);
    }

    /* If we reach here, try a temporary socket as a fallback. */
    int tmp = socket(AF_INET, SOCK_DGRAM, 0);
    if (tmp < 0) {
        fprintf(stderr, "PFCP: fallback socket create failed: %s\n", strerror(errno));
        return -1;
    }
    printf("PFCP: using fallback socket fd=%d to send len=%zu\n", tmp, len);
    /* Log outgoing bytes when using fallback as well */
    print_hex_full("PFCP: fallback outgoing (hex)", buf, len);
    ssize_t st = sendto(tmp, (const char *)buf, (int)len, 0, (const struct sockaddr *)dst, dstlen);
    if (st < 0) {
        fprintf(stderr, "PFCP: fallback sendto failed: %s\n", strerror(errno));
        close(tmp);
        return -1;
    }
    close(tmp);
    fprintf(stdout, "PFCP: fallback sendto succeeded (len=%zu)\n", len);
    return 0;
}

/* Helper to print entire buffer as hex with length prefix.
 * Use this instead of ad-hoc loops that truncate output to 64 bytes.
 */
static void print_hex_full(const char *label, const uint8_t *buf, size_t len)
{
    size_t i;
    if (!label) label = "HEX";
    fprintf(stdout, "%s (len=%zu): ", label, len);
    for (i = 0; i < len; ++i) {
        fprintf(stdout, "%02x", (unsigned char)buf[i]);
    }
    fprintf(stdout, "\n");
}

/* Association/generic response builders are implemented in separate modules
 * (pfcp_association.c / pfcp_generic.c) to keep packet-processing code
 * modular and easier to maintain. */

/* Minimal PFCP header (version + message type) parsing */
struct pfcp_header {
    uint8_t version_s; /* version(3 bits) | message type? keep simple */
    uint8_t message_type;
    uint16_t length;
    uint32_t seid; /* optional; we'll not rely on it for skeleton */
};

static void *pfcp_thread_func(void *arg)
{
    (void)arg;
    char buf[2048];
    struct sockaddr_in src;
    socklen_t src_len = sizeof(src);

    while (pfcp_thread_running) {
        int n = recvfrom(pfcp_sock, buf, (int)sizeof(buf), 0, (struct sockaddr *)&src, &src_len);
        if (n < 0) {
            if (pfcp_thread_running) {
                perror("PFCP recvfrom failed");
            }
            break;
        }
        printf("PFCP: recvfrom returned n=%d on socket fd=%d from %s:%d\n", n, pfcp_sock, inet_ntoa(src.sin_addr), ntohs(src.sin_port));
        /* Dump full received packet for debugging */
        print_hex_full("PFCP: incoming (hex)", (const uint8_t *)buf, (size_t)n);
        if (n < (int)sizeof(struct pfcp_header)) {
            fprintf(stderr, "PFCP packet too small: %d\n", n);
            continue;
        }

        /* If a shutdown was requested while we were blocked in recvfrom(),
         * avoid processing the packet and exit the thread loop. This prevents
         * races where another thread closes the socket while we're still
         * handling the packet. */
        if (!pfcp_thread_running) {
            break;
        }

        /* Parse PFCP header according to TS 29.244 / commonly used layout:
         * Octet 1: Version (3 bits, MSBs), S flag (0x10), MP flag (0x08)
         * Octet 2: Message Type
         * Octet 3-4: Message Length (big-endian)
         * If S set: 8-byte SEID follows
         * Then 3 octets: Sequence number, Message Priority, Spare
         */
        uint8_t octet1 = (uint8_t)buf[0];
        uint8_t version = octet1 >> 5;
        bool s_flag = (octet1 & 0x10) != 0;
        bool mp_flag = (octet1 & 0x08) != 0;
        uint8_t message_type = (uint8_t)buf[1];
        uint16_t msg_len = (uint16_t)((uint8_t)buf[2] << 8 | (uint8_t)buf[3]);

        size_t hdr_off = 4;
        uint64_t seid = 0;
        if (s_flag) {
            if (n < (int)(hdr_off + 8)) {
                fprintf(stderr, "PFCP packet too small for SEID: %d\n", n);
                continue;
            }
            /* SEID is 8 bytes big-endian */
            for (int i = 0; i < 8; ++i)
                seid = (seid << 8) | (uint8_t)buf[hdr_off + i];
            hdr_off += 8;
        }

        /* Sequence number: 3 octets, followed by 1 octet Message Priority.
         * Advance 4 bytes after the (optional) SEID. Capture the 24-bit
         * sequence number (big-endian). */
        uint32_t seq = 0;
        if ((size_t)n > hdr_off) {
            if ((size_t)n >= hdr_off + 4) {
                /* 3-byte sequence number (big-endian) */
                seq = ((uint32_t)(uint8_t)buf[hdr_off] << 16) |
                      ((uint32_t)(uint8_t)buf[hdr_off + 1] << 8) |
                      ((uint32_t)(uint8_t)buf[hdr_off + 2]);
                /* advance past sequence (3) + message-priority (1) */
                hdr_off += 4;
            } else {
                /* packet truncated; read available bytes into seq */
                size_t avail = (size_t)n - hdr_off;
                uint32_t s = 0;
                for (size_t i = 0; i < avail && i < 3; ++i)
                    s = (s << 8) | (uint8_t)buf[hdr_off + i];
                seq = s;
                hdr_off = (size_t)n;
            }
        }

        /* Record rx transaction for this request to correlate responses */
        rx_trans_add(&src, seq);

        /* Handle message types explicitly */

        /* For logging: print basic header info */
        printf("PFCP pkt from %s:%d ver=%u S=%d MP=%d type=%u len=%u SEID=%llu seq=%u\n",
               inet_ntoa(src.sin_addr), ntohs(src.sin_port), version, s_flag, mp_flag, message_type, msg_len,
               (unsigned long long)seid, seq);

        switch (message_type) {
        case PFCP_MSG_HEARTBEAT_REQUEST:
            printf("PFCP: Heartbeat Request\n");
            break;
        case PFCP_MSG_HEARTBEAT_RESPONSE:
            printf("PFCP: Heartbeat Response\n");
            break;
        case PFCP_MSG_ASSOCIATION_SETUP_REQUEST:
        case PFCP_MSG_ASSOCIATION_UPDATE_REQUEST:
        case PFCP_MSG_ASSOCIATION_RELEASE_REQUEST:
            {
                printf("PFCP: Association message type=%u seq=%u\n", message_type, seq);
                /* Try to extract NodeID IE and register remote node */
                const uint8_t *payload = NULL;
                uint16_t plen = 0;
                if (find_ie_in_msg((const uint8_t *)buf, (size_t)n, hdr_off, PFCP_IE_NODE_ID, &payload, &plen) == 0) {
                    /* For simplicity, treat NodeID IE payload as IPv4 bytes when length==4 */
                    char nid[64] = {0};
                    if (plen == 4) {
                        snprintf(nid, sizeof(nid), "%u.%u.%u.%u", payload[0], payload[1], payload[2], payload[3]);
                    } else {
                        /* Hex encode short id */
                        size_t k; char *p = nid;
                        for (k = 0; k < plen && (size_t)(p - nid) < sizeof(nid) - 3; ++k)
                            p += sprintf(p, "%02x", payload[k]);
                    }
                    if (!find_rnode_by_id(nid)) {
                        add_rnode(nid, &src);
                        printf("Registered RemoteNode %s -> %s\n", nid, inet_ntoa(src.sin_addr));
                    }
                }

                /* Build and send Association Response using helper */
                {
                    struct pfcp_packet pkt = newPFCPAssociationResponse(message_type, seq, s_flag, payload, plen);
                    if (!pkt.buf || pkt.len == 0) {
                        fprintf(stderr, "PFCP: failed to build Association Response\n");
                    } else {
                        if (pfcp_send_response(pkt.buf, pkt.len, &src, src_len) != 0)
                            perror("Failed to send Association Response");
                        else
                            printf("Sent Association Response type=%u\n", message_type + 1);
                        free(pkt.buf);
                    }
                }
            }
            break;
        case PFCP_MSG_PFD_MANAGEMENT_REQUEST:
        case PFCP_MSG_NODE_REPORT_REQUEST:
        case PFCP_MSG_SESSION_SET_DELETION_REQUEST:
        case PFCP_MSG_SESSION_REPORT_REQUEST:
            {
                printf("PFCP: Request type %u (simple handler) seq=%u\n", message_type, seq);
                /* Use helper to build & send a simple PFCP response */
                {
                    struct pfcp_packet pkt = newPFCPGenericSimpleResponse(message_type, seq, s_flag);
                    if (!pkt.buf || pkt.len == 0) {
                        fprintf(stderr, "PFCP: failed to build simple response\n");
                    } else {
                        if (pfcp_send_response(pkt.buf, pkt.len, &src, src_len) != 0)
                            perror("Failed to send simple PFCP Response");
                        else
                            printf("Sent simple PFCP Response type=%u\n", message_type + 1);
                        free(pkt.buf);
                    }
                }
            }
            break;
        case PFCP_MSG_SESSION_ESTABLISHMENT_REQUEST:
            /*
             * PFCP Session Establishment Request (Message Type 50)
             * Steps performed below:
             * 1) Log receipt and scan the message for Create* IEs (PDR/FAR/QER/URR)
             *    in a first pass to count how many of each IE type are present.
             * 2) Allocate a heap `struct upf_accel_config` and per-type arrays
             *    sized according to the counts from (1).
             * 3) Second pass: parse each Create* IE into the allocated arrays
             *    (calls out to `parse_create_pdr`, `parse_create_far`, etc.).
             * 4) Hand ownership of the assembled config to the main thread via
             *    `upf_accel_set_pending_smf_config()` and notify the main
             *    thread with `SIGUSR2` to perform the safe dataplane apply.
             * 5) Optionally register the session (if SEID present) and respond
             *    with a Session Establishment Response that includes Created
             *    PDR IEs (for PDRs that carried UE IPv4), NodeID, Cause and F-SEID.
             *
             * The code below implements the two-pass parsing and the response
             * construction. Each logical section is annotated inline.
             */
            printf("PFCP: Session Establishment Request (seq=%u)\n", seq);
            printf("PFCP: Session Establishment Request - preparing SMF config and scheduling apply\n");
            /* First pass: count Create* IEs */
            size_t off = hdr_off;
            size_t num_pdrs = 0, num_fars = 0, num_qers = 0, num_urrs = 0;
            while (off + PFCP_IE_HDR_LEN <= (size_t)n) {
                uint16_t ie_type = be16((uint8_t *)&buf[off]);
                uint16_t ie_lenv = be16((uint8_t *)&buf[off + 2]);
                size_t payload_off = off + PFCP_IE_HDR_LEN;
                if (payload_off + ie_lenv > (size_t)n)
                    break;
                switch (ie_type) {
                case PFCP_IE_CREATE_PDR:
                    num_pdrs++;
                    break;
                case PFCP_IE_CREATE_FAR:
                    num_fars++;
                    break;
                case PFCP_IE_CREATE_QER:
                    num_qers++;
                    break;
                case PFCP_IE_CREATE_URR:
                    num_urrs++;
                    break;
                default:
                    break;
                }
                off = payload_off + ie_lenv;
            }

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

                    /* Second pass: parse and fill */
                    off = hdr_off;
                    size_t pdr_idx = 0, far_idx = 0, qer_idx = 0, urr_idx = 0;
                    while (off + PFCP_IE_HDR_LEN <= (size_t)n) {
                        uint16_t ie_type = be16((uint8_t *)&buf[off]);
                        uint16_t ie_lenv = be16((uint8_t *)&buf[off + 2]);
                        size_t payload_off = off + PFCP_IE_HDR_LEN;
                        if (payload_off + ie_lenv > (size_t)n)
                            break;
                        const uint8_t *ie_payload = (const uint8_t *)&buf[payload_off];
                        size_t ie_len = ie_lenv;
                        switch (ie_type) {
                        case PFCP_IE_CREATE_PDR:
                            if (cfg->pdrs && pdr_idx < cfg->pdrs->num_pdrs) {
                                parse_create_pdr(ie_payload, ie_len, &cfg->pdrs->arr_pdrs[pdr_idx]);
                                pdr_idx++;
                            }
                            break;
                        case PFCP_IE_CREATE_FAR:
                            if (cfg->fars && far_idx < cfg->fars->num_fars) {
                                parse_create_far(ie_payload, ie_len, &cfg->fars->arr_fars[far_idx]);
                                far_idx++;
                            }
                            break;
                        case PFCP_IE_CREATE_QER:
                            if (cfg->qers && qer_idx < cfg->qers->num_qers) {
                                parse_create_qer(ie_payload, ie_len, &cfg->qers->arr_qers[qer_idx]);
                                qer_idx++;
                            }
                            break;
                        case PFCP_IE_CREATE_URR:
                            if (cfg->urrs && urr_idx < cfg->urrs->num_urrs) {
                                parse_create_urr(ie_payload, ie_len, &cfg->urrs->arr_urrs[urr_idx]);
                                urr_idx++;
                            }
                            break;
                        default:
                            break;
                        }
                        off = payload_off + ie_lenv;
                    }

                    /* Hand ownership to main thread apply path */
                    if (upf_accel_set_pending_smf_config(cfg) != 0) {
                        fprintf(stderr, "Failed to set pending SMF config\n");
                        if (cfg->pdrs) free(cfg->pdrs);
                        if (cfg->fars) free(cfg->fars);
                        if (cfg->qers) free(cfg->qers);
                        if (cfg->urrs) free(cfg->urrs);
                        free(cfg);
                    } else {
                        printf("Pending SMF config stored (pdrs=%zu fars=%zu qers=%zu urrs=%zu)\n",
                                pdr_idx, far_idx, qer_idx, urr_idx);
                        /* Notify main thread to apply the pending config via SIGUSR2 */
                        if (kill(getpid(), SIGUSR2) != 0) {
                            perror("Failed to signal main process for SMF apply");
                        } else {
                            printf("Signalled main to apply pending SMF config\n");
                        }
                        /* Register session (if SEID present) */
                        {
                            const uint8_t *nid_pl = NULL; uint16_t nid_len = 0;
                            char nid_str[64] = {0};
                            if (find_ie_in_msg((const uint8_t *)buf, (size_t)n, hdr_off, PFCP_IE_NODE_ID, &nid_pl, &nid_len) == 0) {
                                if (nid_len == 4)
                                    snprintf(nid_str, sizeof(nid_str), "%u.%u.%u.%u", nid_pl[0], nid_pl[1], nid_pl[2], nid_pl[3]);
                                else {
                                    size_t k; char *p = nid_str;
                                    for (k = 0; k < nid_len && (size_t)(p - nid_str) < sizeof(nid_str) - 3; ++k)
                                        p += sprintf(p, "%02x", nid_pl[k]);
                                }
                            } else {
                                snprintf(nid_str, sizeof(nid_str), "%s", inet_ntoa(src.sin_addr));
                            }
                            struct remote_node *rn = find_rnode_by_id(nid_str);
                            if (!rn)
                                rn = add_rnode(nid_str, &src);
                            if (seid != 0) {
                                add_session(seid, rn);
                                printf("Registered session SEID=0x%llx for node %s\n", (unsigned long long)seid, nid_str);
                            }
                        }

                        /* Use helper to build Session Establishment Response, then send */
                        {
                            struct pfcp_packet pkt = newPFCPEstablishmentResponse(seq, s_flag, cfg);
                            if (!pkt.buf || pkt.len == 0) {
                                fprintf(stderr, "PFCP: failed to build Session Establishment Response\n");
                            } else {
                                if (pfcp_send_response(pkt.buf, pkt.len, &src, src_len) != 0)
                                    perror("Failed to send PFCP Session Establishment Response");
                                else
                                    printf("Sent PFCP Session Establishment Response\n");
                                free(pkt.buf);
                            }
                        }
                    }
                }
            }
            break;
        default:
            printf("PFCP: Unknown message type %u\n", message_type);
            break;
        }
    }

    return NULL;
}

int upf_accel_pfcp_init(const struct upf_accel_pfcp_cfg *cfg)
{
    pfcp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (pfcp_sock < 0) {
        perror("Failed to create PFCP socket");
        return -1;
    }
    printf("PFCP: created socket fd=%d\n", pfcp_sock);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(cfg ? cfg->port : UPF_ACCEL_PFCP_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(pfcp_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("Failed to bind PFCP socket");
        close(pfcp_sock);
        pfcp_sock = -1;
        return -1;
    }
    printf("PFCP: bound to port %u\n", cfg ? cfg->port : UPF_ACCEL_PFCP_PORT);

    pfcp_thread_running = true;
    if (pthread_create(&pfcp_thread, NULL, pfcp_thread_func, NULL) != 0) {
        perror("Failed to create PFCP thread");
        pfcp_thread_running = false;
        close(pfcp_sock);
        pfcp_sock = -1;
        return -1;
    }

    printf("PFCP: thread started (tid=%lu)\n", (unsigned long)pfcp_thread);

    printf("PFCP listener started on port %u\n", cfg ? cfg->port : UPF_ACCEL_PFCP_PORT);
    return 0;
}

void upf_accel_pfcp_fini(void)
{
    if (pfcp_thread_running) {
        printf("PFCP: fini requested - signalling thread to stop\n");
        pfcp_thread_running = false;
        /* Close socket to wake thread */
        if (pfcp_sock >= 0) {
            printf("PFCP: closing socket fd=%d\n", pfcp_sock);
            close(pfcp_sock);
            pfcp_sock = -1;
        }
        if (pfcp_thread) {
            pthread_join(pfcp_thread, NULL);
            printf("PFCP: thread joined\n");
            pfcp_thread = 0;
        }
    }
}


