#ifndef SRC_RTR_PDU_SENDER_H_
#define SRC_RTR_PDU_SENDER_H_

#include "pdu.h"
#include "types/router_key.h"
#include "rtr/db/vrps.h"

int send_serial_notify_pdu(int, uint8_t, serial_t);
int send_cache_reset_pdu(int, uint8_t);
int send_cache_response_pdu(int, uint8_t);
int send_prefix_pdu(int, uint8_t, struct vrp const *, uint8_t);
int send_router_key_pdu(int, uint8_t, struct router_key const *, uint8_t);
int send_end_of_data_pdu(int, uint8_t, serial_t);
int send_error_report_pdu(int, uint8_t, uint16_t, struct rtr_request const *,
    char *);


#endif /* SRC_RTR_PDU_SENDER_H_ */
