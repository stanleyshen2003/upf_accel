#include "pfcp_util.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>

/* Global state for tables */
static struct remote_node *rnodes_head = NULL;
static pthread_mutex_t rnodes_lock = PTHREAD_MUTEX_INITIALIZER;

static struct pfcp_session *sess_head = NULL;
static pthread_mutex_t sess_lock = PTHREAD_MUTEX_INITIALIZER;

static struct rx_trans *rx_head = NULL;
static pthread_mutex_t rx_lock = PTHREAD_MUTEX_INITIALIZER;

/* Remote Node Implementation */
struct remote_node *find_rnode_by_id(const char *id)
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

struct remote_node *add_rnode(const char *id, struct sockaddr_in *addr)
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

/* Session Implementation */
struct pfcp_session *find_session(uint64_t seid)
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

struct pfcp_session *add_session(uint64_t seid, struct remote_node *rn)
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

void remove_session(uint64_t seid)
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

/* Transaction Implementation */
void rx_trans_add(const struct sockaddr_in *addr, uint32_t seq)
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

struct rx_trans *rx_trans_find_and_remove(const struct sockaddr_in *addr, uint32_t seq)
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
