#ifndef SRC_RTR_PDU_SERIALIZER_H_
#define SRC_RTR_PDU_SERIALIZER_H_

#include "pdu.h"

#define BUFFER_SIZE	128

struct data_buffer {
	size_t len;
	size_t capacity;
	char *data;
};

void init_buffer(struct data_buffer *);
void free_buffer(struct data_buffer *);

size_t serialize_serial_notify_pdu(struct serial_notify_pdu *, char *);
size_t serialize_cache_response_pdu(struct cache_response_pdu *, char *);
size_t serialize_ipv4_prefix_pdu(struct ipv4_prefix_pdu *, char *);
size_t serialize_ipv6_prefix_pdu(struct ipv6_prefix_pdu *, char *);
size_t serialize_end_of_data_pdu(struct end_of_data_pdu *, char *);
size_t serialize_cache_reset_pdu(struct cache_reset_pdu *, char *);
size_t serialize_error_report_pdu(struct error_report_pdu *, char *);

#endif /* SRC_RTR_PDU_SERIALIZER_H_ */
