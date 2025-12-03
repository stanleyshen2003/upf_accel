/*
 * Shared PFCP utilities: endian helpers, session/node/transaction tables.
 */
#ifndef PFCP_UTIL_H
#define PFCP_UTIL_H

#include <stdint.h>
#include <netinet/in.h>
#include <pthread.h>
#include <time.h>

/* Endian helpers */
static inline uint16_t be16(const uint8_t *b) {
    return (uint16_t)((b[0] << 8) | b[1]);
}

static inline uint32_t be32(const uint8_t *b) {
    return (uint32_t)((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]);
}

static inline uint64_t be64(const uint8_t *b) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i)
        v = (v << 8) | b[i];
    return v;
}

/* Remote Node Storage */
struct remote_node {
    char id[64];
    struct sockaddr_in addr;
    struct remote_node *next;
};

struct remote_node *find_rnode_by_id(const char *id);
struct remote_node *add_rnode(const char *id, struct sockaddr_in *addr);

/* Session Storage */
struct pfcp_session {
    uint64_t seid;
    struct remote_node *rnode;
    struct pfcp_session *next;
};

struct pfcp_session *find_session(uint64_t seid);
struct pfcp_session *add_session(uint64_t seid, struct remote_node *rn);
void remove_session(uint64_t seid);

/* Transaction Storage */
struct rx_trans {
    char id[128]; /* addr-seq */
    struct sockaddr_in addr;
    uint32_t seq;
    time_t ts;
    struct rx_trans *next;
};

void rx_trans_add(const struct sockaddr_in *addr, uint32_t seq);
struct rx_trans *rx_trans_find_and_remove(const struct sockaddr_in *addr, uint32_t seq);

#endif /* PFCP_UTIL_H */
