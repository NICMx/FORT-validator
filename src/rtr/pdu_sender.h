#ifndef RTR_PDU_SENDER_H_
#define RTR_PDU_SENDER_H_

#include "common/cache_rtr.h"
#include "common/types/aspa.h"
#include "common/types/router_key.h"
#include "common/types/vrp.h"
#include "rtr/pdu.h"

#define FLAG_WITHDRAWAL		0
#define FLAG_ANNOUNCEMENT	1

int send_serial_notify_pdu(int, uint8_t, struct rtr_metadata *);
int send_cache_reset_pdu(int, uint8_t);
int send_cache_response_pdu(int, uint8_t, uint16_t);
int send_prefix_pdu(int, uint8_t, struct vrp const *, uint8_t);
int send_router_key_pdu(int, uint8_t, struct router_key const *, uint8_t);
int send_aspa_announce_pdu(int, uint8_t, struct aspa const *);
int send_aspa_withdraw_pdu(int, uint8_t, uint32_t);
int send_end_of_data_pdu(int, uint8_t, uint16_t, serial_t);
int send_error_report_pdu(int, uint8_t, uint16_t, struct rtr_buffer const *,
    char *);

#endif /* RTR_PDU_SENDER_H_ */
