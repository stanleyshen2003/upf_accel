/* PFCP IE type numeric constants (extracted from github.com/wmnsk/go-pfcp ie package)
 * These values match go-pfcp's IEType enumeration so our parser can use the same IDs.
 */
#ifndef UPF_ACCEL_PFCP_IE_H_
#define UPF_ACCEL_PFCP_IE_H_

#include <stdint.h>
#include <stddef.h>

/* IE header length: Type(2) + Length(2) + Instance(1) */
#define PFCP_IE_HDR_LEN 5

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

/* Generic parsed IE item — points into the original buffer for value */
struct upf_ie {
	uint16_t type;
	uint16_t len; /* length of value */
	uint8_t instance;
	const uint8_t *value; /* pointer to start of value */
};

/* Lightweight parsed PDR/FAR/QER/URR summaries used by higher-level code */
struct upf_parsed_pdr {
	uint32_t id;
	uint32_t far_id;
	uint32_t qer_ids[4]; size_t qer_count;
	uint32_t urr_ids[4]; size_t urr_count;
	uint32_t ue_ip_v4; int has_ue_ip;
	uint8_t qfi; int has_qfi;
	int pdi_si; /* source interface */
};

struct upf_parsed_far {
	uint32_t id;
	uint32_t outer_teid; int has_outer_teid;
	uint32_t outer_ip_v4; int has_outer_ip;
};

struct upf_parsed_qer {
	uint32_t id;
	uint8_t qfi; int has_qfi;
	uint64_t mbr_dl; int has_mbr;
};

struct upf_parsed_urr {
	uint32_t id;
	uint64_t volume_quota; int has_volume;
};

/* Parse flat list of IEs starting at `start_off` inside `buf`. The function
 * allocates an array of `struct upf_ie` placed in `*ies_out` (caller must
 * free via `free()`), and sets `*num_out` to the number of entries. Returns
 * 0 on success, -1 on malformed input. */
int upf_parse_ies(const uint8_t *buf, size_t buflen, size_t start_off, struct upf_ie **ies_out, size_t *num_out);

/* Free array returned by upf_parse_ies (simple wrapper) */
void upf_free_ies(struct upf_ie *ies);

/* Helpers to search IE array */
const struct upf_ie *upf_find_ie(const struct upf_ie *ies, size_t num, uint16_t ie_type, size_t index);

/* Convenience parsers for common IE payloads */
int upf_ie_to_nodeid(const struct upf_ie *ie, char *out, size_t outlen);
int upf_ie_to_uint32(const struct upf_ie *ie, uint32_t *v);
int upf_ie_to_uint64(const struct upf_ie *ie, uint64_t *v);

/* Parsers for Create* grouped IEs (summaries) */
int upf_parse_create_pdr(const struct upf_ie *ie, struct upf_parsed_pdr *out);
int upf_parse_create_far(const struct upf_ie *ie, struct upf_parsed_far *out);
int upf_parse_create_qer(const struct upf_ie *ie, struct upf_parsed_qer *out);
int upf_parse_create_urr(const struct upf_ie *ie, struct upf_parsed_urr *out);

/* Common IE types */
struct upf_cause {
	uint8_t cause; /* main cause value */
	int has_value;
	uint8_t value; /* optional additional information */
};

/* Parse Cause IE into upf_cause. Returns 0 on success. */
int upf_ie_to_cause(const struct upf_ie *ie, struct upf_cause *out);

/* Build a Cause IE. If has_value is 0 the IE payload is 1 byte (cause).
 * If has_value is 1 the payload is 2 bytes (cause + value). */
int upf_build_cause(uint8_t cause, int has_value, uint8_t value, uint8_t **out_buf, size_t *out_len);

/* IE builder helpers - allocate a buffer containing a single IE (type+len+instance+value).
 * Caller is responsible for freeing *out_buf via free(). Returns 0 on success. */
int upf_build_ie(uint16_t ie_type, uint8_t instance, const uint8_t *value, uint16_t vlen, uint8_t **out_buf, size_t *out_len);

/* Convenience builder for NodeID IE carrying an IPv4 address (vlen == 4).
 * ip_be should be in network byte order (big-endian) as uint32_t. */
int upf_build_nodeid_ipv4(uint32_t ip_be, uint8_t **out_buf, size_t *out_len);

#endif /* UPF_ACCEL_PFCP_IE_H_ */

