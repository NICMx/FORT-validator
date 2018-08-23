#ifndef RTR_PDU_H_
#define RTR_PDU_H_

#include <netinet/in.h>

#include "../common.h"
#include "primitive_reader.h"

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
};

struct cache_reset_pdu {
	struct	pdu_header header;
};

struct error_report_pdu {
	struct	pdu_header header;
	void	*erroneous_pdu;
	rtr_char	*error_message;
};

struct pdu_metadata {
	size_t	length;
	int	(*from_stream)(struct pdu_header *, int, void *);
	int	(*handle)(void *);
	void	(*destructor)(void *);
};

__BEGIN_DECLS
int pdu_load(int, void **, struct pdu_metadata const **);
struct pdu_metadata const *pdu_get_metadata(u_int8_t);
struct pdu_header *pdu_get_header(void *);
__END_DECLS

#endif /* RTR_PDU_H_ */
