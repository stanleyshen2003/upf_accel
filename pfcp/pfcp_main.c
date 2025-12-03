/* Minimal PFCP implementation: UDP listener + basic header parsing */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <inttypes.h>

#include "pfcp_main.h"
#include "upf_accel.h"
#include "pfcp_ie.h"
#include "pfcp_packet.h"
#include "pfcp_util.h"
#include "pfcp_generic.h"
#include "pfcp_heartbeat.h"
#include "pfcp_association.h"
#include "pfcp_session.h"

/* PFCP UDP listener and parser (POSIX sockets) */
static int pfcp_sock = -1;
static pthread_t pfcp_thread = 0;
static volatile bool pfcp_thread_running = false;

/* Helper to print entire buffer as hex */
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

int pfcp_send_response(const uint8_t *buf, size_t len, const struct sockaddr_in *dst, socklen_t dstlen)
{
    ssize_t s = -1;
    if (pfcp_sock >= 0) {
        printf("PFCP: attempting sendto on global socket fd=%d len=%zu\n", pfcp_sock, len);
        print_hex_full("PFCP: outgoing (hex)", buf, len);
        s = sendto(pfcp_sock, (const char *)buf, (int)len, 0, (const struct sockaddr *)dst, dstlen);
        if (s >= 0)
            return 0;
        fprintf(stderr, "PFCP: sendto on pfcp_sock=%d failed: %s\n", pfcp_sock, strerror(errno));
    } else {
        fprintf(stderr, "PFCP: global pfcp_sock is invalid (pfcp_sock=%d)\n", pfcp_sock);
    }

    /* Fallback */
    int tmp = socket(AF_INET, SOCK_DGRAM, 0);
    if (tmp < 0) {
        fprintf(stderr, "PFCP: fallback socket create failed: %s\n", strerror(errno));
        return -1;
    }
    printf("PFCP: using fallback socket fd=%d to send len=%zu\n", tmp, len);
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

int pfcp_get_local_addr(struct sockaddr_in *addr)
{
    if (pfcp_sock < 0) return -1;
    socklen_t len = sizeof(*addr);
    return getsockname(pfcp_sock, (struct sockaddr *)addr, &len);
}

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
        print_hex_full("PFCP: incoming (hex)", (const uint8_t *)buf, (size_t)n);
        
        /* Basic header check */
        if (n < 4) {
            fprintf(stderr, "PFCP packet too small: %d\n", n);
            continue;
        }

        if (!pfcp_thread_running) break;

        /* Parse Header */
        uint8_t octet1 = (uint8_t)buf[0];
        uint8_t version = octet1 >> 5;
        bool s_flag = (octet1 & 0x01) != 0;
        bool mp_flag = (octet1 & 0x02) != 0;
        uint8_t message_type = (uint8_t)buf[1];
        uint16_t msg_len = (uint16_t)((uint8_t)buf[2] << 8 | (uint8_t)buf[3]);

        size_t hdr_off = 4;
        uint64_t seid = 0;
        if (s_flag) {
            if (n < (int)(hdr_off + 8)) {
                fprintf(stderr, "PFCP packet too small for SEID: %d\n", n);
                continue;
            }
            for (int i = 0; i < 8; ++i)
                seid = (seid << 8) | (uint8_t)buf[hdr_off + i];
            hdr_off += 8;
        }

        uint32_t seq = 0;
        uint8_t msg_priority = 0;
        if ((size_t)n > hdr_off) {
            if ((size_t)n >= hdr_off + 4) {
                seq = ((uint32_t)(uint8_t)buf[hdr_off] << 16) |
                      ((uint32_t)(uint8_t)buf[hdr_off + 1] << 8) |
                      ((uint32_t)(uint8_t)buf[hdr_off + 2]);
                msg_priority = (uint8_t)buf[hdr_off + 3];
                hdr_off += 4;
            } else {
                size_t avail = (size_t)n - hdr_off;
                uint32_t s = 0;
                for (size_t i = 0; i < avail && i < 3; ++i)
                    s = (s << 8) | (uint8_t)buf[hdr_off + i];
                seq = s;
                hdr_off = (size_t)n;
            }
        }

        rx_trans_add(&src, seq);

        printf("PFCP pkt from %s:%d ver=%u S=%d MP=%d type=%u len=%u SEID=%llu seq=%u\n",
               inet_ntoa(src.sin_addr), ntohs(src.sin_port), version, s_flag, mp_flag, message_type, msg_len,
               (unsigned long long)seid, seq);

        switch (message_type) {
        case PFCP_MSG_HEARTBEAT_REQUEST:
            handle_heartbeat_request(seq, s_flag, &src, src_len);
            break;
        case PFCP_MSG_HEARTBEAT_RESPONSE:
            handle_heartbeat_response(seq);
            break;
        case PFCP_MSG_ASSOCIATION_SETUP_REQUEST:
        case PFCP_MSG_ASSOCIATION_UPDATE_REQUEST:
        case PFCP_MSG_ASSOCIATION_RELEASE_REQUEST:
            handle_association_message(message_type, seq, msg_priority, s_flag, (const uint8_t *)buf, (size_t)n, hdr_off, &src, src_len);
            break;
        case PFCP_MSG_SESSION_ESTABLISHMENT_REQUEST:
            handle_session_establishment_request(seq, s_flag, seid, (const uint8_t *)buf, (size_t)n, hdr_off, &src, src_len);
            break;
        case PFCP_MSG_SESSION_MODIFICATION_REQUEST:
            handle_session_modification_request(seq, s_flag, seid, &src, src_len);
            break;
        case PFCP_MSG_PFD_MANAGEMENT_REQUEST:
        case PFCP_MSG_NODE_REPORT_REQUEST:
        case PFCP_MSG_SESSION_SET_DELETION_REQUEST:
        case PFCP_MSG_SESSION_REPORT_REQUEST:
            {
                printf("PFCP: Request type %u (simple handler) seq=%u\n", message_type, seq);
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
            break;
        default:
            if (message_type != 0) {
                 fprintf(stderr, "PFCP: Unknown message type %u\n", message_type);
            }
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
