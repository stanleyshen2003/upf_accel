#ifndef PFCP_HEARTBEAT_H
#define PFCP_HEARTBEAT_H

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>

/* Handle Heartbeat Request */
void handle_heartbeat_request(uint32_t seq, bool s_flag, const struct sockaddr_in *src, socklen_t src_len);

/* Handle Heartbeat Response */
void handle_heartbeat_response(uint32_t seq);

#endif /* PFCP_HEARTBEAT_H */
