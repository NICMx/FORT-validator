#ifndef RTR_PDU_H_
#define RTR_PDU_H_

#include <sys/socket.h>
#include <netinet/in.h>

#include "common.h"
#include "object/router_key.h"
#include "rtr/primitive_reader.h"

#define RTR_V0	0
#define RTR_V1	1

/** A request from an RTR client. */
struct rtr_request {
	/** Raw bytes. */
	unsigned char *bytes;
	/** Length of @bytes. */
	size_t bytes_len;
	/** Deserialized PDU. One of the *_pdu struct below. */
	void *pdu;
};

enum pdu_type {
	PDU_TYPE_SERIAL_NOTIFY =	0,
	PDU_TYPE_SERIAL_QUERY =		1,
	PDU_TYPE_RESET_QUERY =		2,
	PDU_TYPE_CACHE_RESPONSE =	3,
	PDU_TYPE_IPV4_PREFIX =		4,
	PDU_TYPE_IPV6_PREFIX =		6,
	PDU_TYPE_END_OF_DATA =		7,
	PDU_TYPE_CACHE_RESET =		8,
	PDU_TYPE_ROUTER_KEY =		9,
	PDU_TYPE_ERROR_REPORT =		10,
};

char const *pdutype2str(enum pdu_type);

/*
 * Note: It's probably best not to use sizeof for these lengths, because it
 * risks including padding, and this is not the place for it.
 * These numbers are constants from the RFC anyway.
 */

/* Header length field is always 64 bits long */
#define RTRPDU_HDR_LEN			8

#define RTRPDU_SERIAL_NOTIFY_LEN	12
#define RTRPDU_SERIAL_QUERY_LEN		12
#define RTRPDU_RESET_QUERY_LEN		8
#define RTRPDU_CACHE_RESPONSE_LEN	8
#define RTRPDU_IPV4_PREFIX_LEN		20
#define RTRPDU_IPV6_PREFIX_LEN		32
#define RTRPDU_END_OF_DATA_V0_LEN	12
#define RTRPDU_END_OF_DATA_V1_LEN	24
#define RTRPDU_CACHE_RESET_LEN		8
#define RTRPDU_ROUTER_KEY_LEN		123

/* Ignores Error Report PDUs, which is fine. */
#define RTRPDU_MAX_LEN			RTRPDU_IPV6_PREFIX_LEN
#define RTRPDU_ERR_MAX_LEN		256

struct pdu_header {
	uint8_t	protocol_version;
	uint8_t	pdu_type;
	union {
		uint16_t	session_id;
		uint16_t	reserved;
		uint16_t	error_code;
	} m; /* Note: "m" stands for "meh." I have no idea what to call this. */
	uint32_t	length;
};

struct serial_notify_pdu {
	struct	pdu_header header;
	uint32_t	serial_number;
};

struct serial_query_pdu {
	struct	pdu_header header;
	uint32_t	serial_number;
};

struct reset_query_pdu {
	struct	pdu_header header;
};

struct cache_response_pdu {
	struct pdu_header header;
};

struct ipv4_prefix_pdu {
	struct	pdu_header header;
	uint8_t	flags;
	uint8_t	prefix_length;
	uint8_t	max_length;
	uint8_t	zero;
	struct	in_addr ipv4_prefix;
	uint32_t	asn;
};

struct ipv6_prefix_pdu {
	struct	pdu_header header;
	uint8_t	flags;
	uint8_t	prefix_length;
	uint8_t	max_length;
	uint8_t	zero;
	struct	in6_addr ipv6_prefix;
	uint32_t	asn;
};

struct end_of_data_pdu {
	struct	pdu_header header;
	uint32_t	serial_number;
	uint32_t	refresh_interval;
	uint32_t	retry_interval;
	uint32_t	expire_interval;
};

struct cache_reset_pdu {
	struct	pdu_header header;
};

struct router_key_pdu {
	struct	pdu_header header;
	unsigned char	ski[RK_SKI_LEN];
	size_t		ski_len;
	uint32_t	asn;
	unsigned char	spki[RK_SPKI_LEN];
	size_t		spki_len;
};

struct error_report_pdu {
	struct	pdu_header header;
	uint32_t	error_pdu_length;
	unsigned char	erroneous_pdu[RTRPDU_ERR_MAX_LEN];
	uint32_t	error_message_length;
	rtr_char	*error_message;
};

struct pdu_metadata {
	size_t	length;
	/**
	 * Builds the PDU from @header, and the bytes remaining in the reader.
	 *
	 * Caller assumes that from_stream functions are only allowed to fail
	 * on programming errors. (Because failure results in an internal error
	 * response.)
	 */
	int	(*from_stream)(struct pdu_header *, struct pdu_reader *, void *);
	/**
	 * Handlers must return 0 to maintain the connection, nonzero to close
	 * the socket.
	 * Also, they are supposed to send error PDUs on discretion.
	 */
	int	(*handle)(int, struct rtr_request const *);
	void	(*destructor)(void *);
};

int pdu_load(int, struct sockaddr_storage *, struct rtr_request *,
    struct pdu_metadata const **);
struct pdu_metadata const *pdu_get_metadata(uint8_t);
struct pdu_header *pdu_get_header(void *);

#endif /* RTR_PDU_H_ */
