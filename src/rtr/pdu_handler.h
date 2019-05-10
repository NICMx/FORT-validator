#ifndef RTR_PDU_HANDLER_H_
#define RTR_PDU_HANDLER_H_

#include "rtr/pdu.h"

int handle_serial_notify_pdu(int, struct rtr_request const *);
int handle_serial_query_pdu(int, struct rtr_request const *);
int handle_reset_query_pdu(int, struct rtr_request const *);
int handle_cache_response_pdu(int, struct rtr_request const *);
int handle_ipv4_prefix_pdu(int, struct rtr_request const *);
int handle_ipv6_prefix_pdu(int, struct rtr_request const *);
int handle_end_of_data_pdu(int, struct rtr_request const *);
int handle_cache_reset_pdu(int, struct rtr_request const *);
int handle_router_key_pdu(int, struct rtr_request const *);
int handle_error_report_pdu(int, struct rtr_request const *);

#endif /* RTR_PDU_HANDLER_H_ */
