#ifndef RTR_PDU_H_
#define RTR_PDU_H_

#include "common.h"
#include "types/router_key.h"
#include "rtr/rtr.h"

enum rtr_version {
	RTR_V0			= 0,
	RTR_V1			= 1,
};

struct rtr_buffer {
	unsigned char *bytes; /* Raw bytes */
	size_t bytes_len; /* Length of @bytes */
};

enum pdu_type {
	PDU_TYPE_SERIAL_NOTIFY	= 0,
	PDU_TYPE_SERIAL_QUERY	= 1,
	PDU_TYPE_RESET_QUERY	= 2,
	PDU_TYPE_CACHE_RESPONSE	= 3,
	PDU_TYPE_IPV4_PREFIX	= 4,
	PDU_TYPE_IPV6_PREFIX	= 6,
	PDU_TYPE_END_OF_DATA 	= 7,
	PDU_TYPE_CACHE_RESET	= 8,
	PDU_TYPE_ROUTER_KEY	= 9,
	PDU_TYPE_ERROR_REPORT	= 10,
};

char const *pdutype2str(enum pdu_type);

/*
 * Note: It's probably best not to use sizeof for these lengths, because it
 * risks including padding, and this is not the place for it.
 * These numbers are constants from the RFC anyway.
 */

/* Header length field is always 64 bits long */
#define RTR_HDR_LEN			8u

/* Please remember to update the MAX_LENs if you modify this list. */
#define RTRPDU_SERIAL_NOTIFY_LEN	12u
#define RTRPDU_SERIAL_QUERY_LEN		12u
#define RTRPDU_RESET_QUERY_LEN		8u
#define RTRPDU_CACHE_RESPONSE_LEN	8u
#define RTRPDU_IPV4_PREFIX_LEN		20u
#define RTRPDU_IPV6_PREFIX_LEN		32u
#define RTRPDU_END_OF_DATA_V0_LEN	12u
#define RTRPDU_END_OF_DATA_V1_LEN	24u
#define RTRPDU_CACHE_RESET_LEN		8u
#define RTRPDU_ROUTER_KEY_LEN		123u
/* See rtrpdu_error_report_len() for the missing one. */

/* Except for Error Report PDUs. */
#define RTRPDU_MAX_LEN			RTRPDU_ROUTER_KEY_LEN
/*
 * The length field is 32 bits. Error PDUs don't need to be that large.
 * 1024 is arbitrary.
 */
#define RTRPDU_ERROR_REPORT_MAX_LEN	1024u

#define RTRPDU_MAX_LEN2			RTRPDU_ERROR_REPORT_MAX_LEN

struct pdu_header {
	enum rtr_version version;
	enum pdu_type type;
	union {
		uint16_t session_id;
		uint16_t reserved;
		uint16_t error_code;
	} m; /* Note: "m" stands for "meh." I have no idea what to call this. */
	uint32_t length;
};

struct serial_query_pdu {
	struct	pdu_header header;
	uint32_t	serial_number;
};

struct reset_query_pdu {
	struct	pdu_header header;
};

struct error_report_pdu {
	struct	pdu_header header;
	uint32_t	errpdu_len;
	unsigned char	errpdu[RTRPDU_MAX_LEN];
	uint32_t	errmsg_len;
	char		*errmsg;
};

static inline size_t
rtrpdu_error_report_len(uint32_t errpdu_len, uint32_t errmsg_len)
{
	return RTR_HDR_LEN
	    + 4 /* Length of Encapsulated PDU field */
	    + errpdu_len
	    + 4 /* Length of Error Text field */
	    + errmsg_len;
}

#endif /* RTR_PDU_H_ */
