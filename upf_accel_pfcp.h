/*
 * Minimal PFCP skeleton for N4 control-plane listener.
 * Provides a UDP listener that parses PFCP headers and dispatches handlers.
 */
#ifndef UPF_ACCEL_PFCP_H_
#define UPF_ACCEL_PFCP_H_

#include <stdint.h>
#include "upf_accel.h"

/* PFCP default port */
#define UPF_ACCEL_PFCP_PORT 8805

/* PFCP listener configuration */
struct upf_accel_pfcp_cfg {
    const char *bind_addr; /* e.g. "0.0.0.0" */
    uint16_t port;         /* PFCP port */
};

/* Initialize PFCP listener. Returns 0 on success. */
int upf_accel_pfcp_init(const struct upf_accel_pfcp_cfg *cfg);

/* Stop PFCP listener and cleanup. */
void upf_accel_pfcp_fini(void);

/* Runtime config is set via upf_accel_set_pending_smf_config() declared in upf_accel.h */

#endif /* UPF_ACCEL_PFCP_H_ */
