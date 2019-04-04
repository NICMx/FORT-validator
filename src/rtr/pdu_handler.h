#ifndef RTR_PDU_HANDLER_H_
#define RTR_PDU_HANDLER_H_

#include "../common.h"


int handle_serial_notify_pdu(int, void *);
int handle_serial_query_pdu(int, void *);
int handle_reset_query_pdu(int, void *);
int handle_cache_response_pdu(int, void *);
int handle_ipv4_prefix_pdu(int, void *);
int handle_ipv6_prefix_pdu(int, void *);
int handle_end_of_data_pdu(int, void *);
int handle_cache_reset_pdu(int, void *);
int handle_error_report_pdu(int, void *);

#endif /* RTR_PDU_HANDLER_H_ */
