#ifndef RTR_PDU_H_
#define RTR_PDU_H_

#include <netinet/in.h>

#include "../common.h"
#include "primitive_reader.h"

#define RTR_V0	0
#define RTR_V1	1

#define PDU_TYPE_SERIAL_NOTIFY		0
#define PDU_TYPE_CACHE_RESPONSE		3
#define PDU_TYPE_IPV4_PREFIX		4
#define PDU_TYPE_IPV6_PREFIX		6
#define PDU_TYPE_END_OF_DATA		7
#define PDU_TYPE_CACHE_RESET		8
#define PDU_TYPE_ERROR_REPORT		10

#define ERR_CORRUPT_DATA			0
#define ERR_INTERNAL_ERROR			1
#define ERR_NO_DATA_AVAILABLE		2
#define ERR_INVALID_REQUEST			3
#define ERR_UNSUP_PROTO_VERSION		4
#define ERR_UNSUP_PDU_TYPE			5
#define ERR_WITHDRAWAL_UNKNOWN		6
#define ERR_DUPLICATE_ANNOUNCE		7
#define UNEXPECTED_PROTO_VERSION	8

struct pdu_header {
	u_int8_t	protocol_version;
	u_int8_t	pdu_type;
	union {
		u_int16_t	session_id;
		u_int16_t	reserved;
		u_int16_t	error_code;
	};
	u_int32_t	length;
};

struct serial_notify_pdu {
	struct	pdu_header header;
	u_int32_t	serial_number;
};

struct serial_query_pdu {
	struct	pdu_header header;
	u_int32_t	serial_number;
};

struct reset_query_pdu {
	struct	pdu_header header;
};

struct cache_response_pdu {
	struct pdu_header header;
};

struct ipv4_prefix_pdu {
	struct	pdu_header header;
	u_int8_t	flags;
	u_int8_t	prefix_length;
	u_int8_t	max_length;
	u_int8_t	zero;
	struct	in_addr ipv4_prefix;
	u_int32_t	asn;
};

struct ipv6_prefix_pdu {
	struct	pdu_header header;
	u_int8_t	flags;
	u_int8_t	prefix_length;
	u_int8_t	max_length;
	u_int8_t	zero;
	struct	in6_addr ipv6_prefix;
	u_int32_t	asn;
};

struct end_of_data_pdu {
	struct	pdu_header header;
	u_int32_t	serial_number;
	u_int32_t	refresh_interval;
	u_int32_t	retry_interval;
	u_int32_t	expire_interval;
};

struct cache_reset_pdu {
	struct	pdu_header header;
};

struct error_report_pdu {
	struct	pdu_header header;
	u_int32_t	error_pdu_length;
	void		*erroneous_pdu;
	u_int32_t	error_message_length;
	rtr_char	*error_message;
};

struct pdu_metadata {
	size_t	length;
	int	(*from_stream)(struct pdu_header *, int, void *);
	int	(*handle)(int, void *);
	void	(*destructor)(void *);
};

__BEGIN_DECLS
int pdu_load(int, void **, struct pdu_metadata const **);
struct pdu_metadata const *pdu_get_metadata(u_int8_t);
struct pdu_header *pdu_get_header(void *);
__END_DECLS

#endif /* RTR_PDU_H_ */
