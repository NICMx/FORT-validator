#ifndef SRC_RTR_PDU_SENDER_H_
#define SRC_RTR_PDU_SENDER_H_

#include "pdu.h"
#include "object/router_key.h"
#include "rtr/db/vrps.h"

void init_sender_common(int, int, uint8_t);

int send_serial_notify_pdu(int, serial_t);
int send_cache_reset_pdu(int);
int send_cache_response_pdu(int);
int send_prefix_pdu(int, struct vrp const *, uint8_t);
int send_router_key_pdu(int, struct router_key const *, uint8_t);
int send_delta_pdus(int, struct deltas_db *);
int send_end_of_data_pdu(int, serial_t);
int send_error_report_pdu(int, uint16_t, struct rtr_request const *, char *);


#endif /* SRC_RTR_PDU_SENDER_H_ */
