#ifndef SRC_RTR_PDU_SERIALIZER_H_
#define SRC_RTR_PDU_SERIALIZER_H_

#include "rtr/pdu.h"

size_t serialize_serial_notify_pdu(struct serial_notify_pdu *,
    unsigned char *);
size_t serialize_cache_response_pdu(struct cache_response_pdu *,
    unsigned char *);
size_t serialize_ipv4_prefix_pdu(struct ipv4_prefix_pdu *, unsigned char *);
size_t serialize_ipv6_prefix_pdu(struct ipv6_prefix_pdu *, unsigned char *);
size_t serialize_end_of_data_pdu(struct end_of_data_pdu const *,
    unsigned char *);
size_t serialize_cache_reset_pdu(struct cache_reset_pdu *, unsigned char *);
size_t serialize_router_key_pdu(struct router_key_pdu *, unsigned char *);
size_t serialize_error_report_pdu(struct error_report_pdu *, unsigned char *);

#endif /* SRC_RTR_PDU_SERIALIZER_H_ */
