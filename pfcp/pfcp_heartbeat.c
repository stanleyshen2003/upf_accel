#include "pfcp_heartbeat.h"
#include "pfcp_generic.h"
#include "pfcp_main.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void handle_heartbeat_request(uint32_t seq, bool s_flag, const struct sockaddr_in *src, socklen_t src_len)
{
    printf("PFCP: Heartbeat Request seq=%u\n", seq);
    
    /* Use a static timestamp for simplicity (or current time) */
    static uint32_t recovery_ts = 0;
    if (recovery_ts == 0) recovery_ts = (uint32_t)time(NULL);

    struct pfcp_packet pkt = newPFCPHeartbeatResponse(PFCP_MSG_HEARTBEAT_REQUEST, seq, s_flag, recovery_ts);
    if (!pkt.buf || pkt.len == 0) {
        fprintf(stderr, "PFCP: failed to build Heartbeat Response\n");
    } else {
        if (pfcp_send_response(pkt.buf, pkt.len, src, src_len) != 0)
            perror("Failed to send Heartbeat Response");
        else
            printf("Sent Heartbeat Response seq=%u\n", seq);
        free(pkt.buf);
    }
}

void handle_heartbeat_response(uint32_t seq)
{
    printf("PFCP: Heartbeat Response seq=%u\n", seq);
}
