#ifndef SRC_RTR_PDU_SERIALIZER_H_
#define SRC_RTR_PDU_SERIALIZER_H_

#include "pdu.h"

#define BUFFER_SIZE	512

struct data_buffer {
	size_t len;
	size_t capacity;
	unsigned char *data;
};

__BEGIN_DECLS
void init_buffer(struct data_buffer *);
void free_buffer(struct data_buffer *);

size_t serialize_serial_notify_pdu(struct serial_notify_pdu *,
    unsigned char *);
size_t serialize_cache_response_pdu(struct cache_response_pdu *,
    unsigned char *);
size_t serialize_ipv4_prefix_pdu(struct ipv4_prefix_pdu *, unsigned char *);
size_t serialize_ipv6_prefix_pdu(struct ipv6_prefix_pdu *, unsigned char *);
size_t serialize_end_of_data_pdu(struct end_of_data_pdu *, unsigned char *);
size_t serialize_cache_reset_pdu(struct cache_reset_pdu *, unsigned char *);
size_t serialize_router_key_pdu(struct router_key_pdu *, unsigned char *);
size_t serialize_error_report_pdu(struct error_report_pdu *, unsigned char *);
__END_DECLS

#endif /* SRC_RTR_PDU_SERIALIZER_H_ */
