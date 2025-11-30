#ifndef UPF_ACCEL_PFCP_PACKET_H_
#define UPF_ACCEL_PFCP_PACKET_H_

#include <stdint.h>
#include <stddef.h>

/* pfcp_packet: represents a wire-format PFCP packet buffer constructed by
 * helper modules. The buffer is allocated with malloc() by builders and
 * should be freed by the caller after sending. */
struct pfcp_packet {
    uint8_t *buf;
    size_t len;
};

#endif /* UPF_ACCEL_PFCP_PACKET_H_ */
