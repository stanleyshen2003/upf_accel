/*
 * Minimal PFCP skeleton for N4 control-plane listener.
 * Provides a UDP listener that parses PFCP headers and dispatches handlers.
 */
#ifndef UPF_ACCEL_PFCP_H_
#define UPF_ACCEL_PFCP_H_

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include "upf_accel.h"
#include "upf_accel_pfcp_packet.h"

/* PFCP default port */
#define UPF_ACCEL_PFCP_PORT 8805

/* PFCP message type constants (TS 29.244) */
#define PFCP_MSG_HEARTBEAT_REQUEST                1
#define PFCP_MSG_HEARTBEAT_RESPONSE               2
#define PFCP_MSG_PFD_MANAGEMENT_REQUEST           3
#define PFCP_MSG_ASSOCIATION_SETUP_REQUEST        5
#define PFCP_MSG_ASSOCIATION_SETUP_RESPONSE       6
#define PFCP_MSG_ASSOCIATION_UPDATE_REQUEST       7
#define PFCP_MSG_ASSOCIATION_RELEASE_REQUEST      9
#define PFCP_MSG_NODE_REPORT_REQUEST             12
#define PFCP_MSG_SESSION_SET_DELETION_REQUEST    14
#define PFCP_MSG_SESSION_ESTABLISHMENT_REQUEST   50
#define PFCP_MSG_SESSION_ESTABLISHMENT_RESPONSE  51
#define PFCP_MSG_SESSION_REPORT_REQUEST          56

/* PFCP listener configuration */
struct upf_accel_pfcp_cfg {
    const char *bind_addr; /* e.g. "0.0.0.0" */
    uint16_t port;         /* PFCP port */
};

/* Initialize PFCP listener. Returns 0 on success. */
int upf_accel_pfcp_init(const struct upf_accel_pfcp_cfg *cfg);

/* Stop PFCP listener and cleanup. */
void upf_accel_pfcp_fini(void);

/* Expose pfcp_send_response so packet builders in separate modules can send */
int pfcp_send_response(const uint8_t *buf, size_t len, const struct sockaddr_in *dst, socklen_t dstlen);


/* Runtime config is set via upf_accel_set_pending_smf_config() declared in upf_accel.h */

#endif /* UPF_ACCEL_PFCP_H_ */
