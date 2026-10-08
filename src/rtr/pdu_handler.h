#ifndef RTR_PDU_HANDLER_H_
#define RTR_PDU_HANDLER_H_

#include "rtr/pdu_stream.h"

int handle_serial_query_pdu(struct rtr_request *);
int handle_reset_query_pdu(struct rtr_request *);

#endif /* RTR_PDU_HANDLER_H_ */
