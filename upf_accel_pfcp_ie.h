/* PFCP IE type numeric constants (extracted from github.com/wmnsk/go-pfcp ie package)
 * These values match go-pfcp's IEType enumeration so our parser can use the same IDs.
 */
#ifndef UPF_ACCEL_PFCP_IE_H_
#define UPF_ACCEL_PFCP_IE_H_

#define PFCP_IE_CREATE_PDR 1
#define PFCP_IE_PDI 2
#define PFCP_IE_CREATE_FAR 3
#define PFCP_IE_FORWARDING_PARAMETERS 4
#define PFCP_IE_CREATE_URR 6
#define PFCP_IE_CREATE_QER 7
#define PFCP_IE_CREATED_PDR 8
#define PFCP_IE_UPDATE_PDR 9

#define PFCP_IE_CAUSE 19
#define PFCP_IE_SOURCE_INTERFACE 20
#define PFCP_IE_F_TEID 21
#define PFCP_IE_NETWORK_INSTANCE 22
#define PFCP_IE_SDF_FILTER 23
#define PFCP_IE_APPLICATION_ID 24
#define PFCP_IE_MBR 26
#define PFCP_IE_GBR 27
#define PFCP_IE_QER_CORRELATION_ID 28
#define PFCP_IE_PRECEDENCE 29
#define PFCP_IE_VOLUME_THRESHOLD 31
#define PFCP_IE_TIME_THRESHOLD 32
#define PFCP_IE_REPORTING_TRIGGERS 37
#define PFCP_IE_REPORT_TYPE 39

#define PFCP_IE_PDR_ID 56
#define PFCP_IE_FSEID 57
#define PFCP_IE_NODE_ID 60
#define PFCP_IE_UE_IP_ADDRESS 93
#define PFCP_IE_OUTER_HEADER_CREATION 84
#define PFCP_IE_PACKET_RATE 94

#define PFCP_IE_URR_ID 81
#define PFCP_IE_VOLUME_QUOTA 73
#define PFCP_IE_TIME_QUOTA 74

#define PFCP_IE_FAR_ID 108
#define PFCP_IE_QER_ID 109
#define PFCP_IE_QFI 124

#endif /* UPF_ACCEL_PFCP_IE_H_ */
