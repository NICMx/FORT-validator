#ifndef RTR_PDU_H_
#define RTR_PDU_H_

#include <netinet/in.h>

#include "common.h"
#include "rtr/primitive_reader.h"

#define RTR_V0	0
#define RTR_V1	1

#define PDU_TYPE_SERIAL_NOTIFY		0
#define PDU_TYPE_CACHE_RESPONSE		3
#define PDU_TYPE_IPV4_PREFIX		4
#define PDU_TYPE_IPV6_PREFIX		6
#define PDU_TYPE_END_OF_DATA		7
#define PDU_TYPE_CACHE_RESET		8
#define PDU_TYPE_ROUTER_KEY		9
#define PDU_TYPE_ERROR_REPORT		10

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
	unsigned char	*ski;
	size_t		ski_len;
	uint32_t	asn;
	unsigned char	*spki;
	size_t		spki_len;
};

struct error_report_pdu {
	struct	pdu_header header;
	uint32_t	error_pdu_length;
	void		*erroneous_pdu;
	uint32_t	error_message_length;
	rtr_char	*error_message;
};

struct pdu_metadata {
	size_t	length;
	int	(*from_stream)(struct pdu_header *, int, void *);
	int	(*handle)(int, void *);
	void	(*destructor)(void *);
};

int pdu_load(int, void **, struct pdu_metadata const **, uint8_t *);
struct pdu_metadata const *pdu_get_metadata(uint8_t);
struct pdu_header *pdu_get_header(void *);

#endif /* RTR_PDU_H_ */
