#ifndef SRC_RTR_PDU_SENDER_H_
#define SRC_RTR_PDU_SENDER_H_

#include "pdu.h"
#include "rtr/db/vrps.h"

struct sender_common {
	int fd;
	uint8_t version;
	uint16_t session_id;
};

void init_sender_common(struct sender_common *, int, uint8_t);

int send_serial_notify_pdu(struct sender_common *, serial_t);
int send_cache_reset_pdu(struct sender_common *);
int send_cache_response_pdu(struct sender_common *);
int send_prefix_pdu(struct sender_common *, struct vrp const *, uint8_t);
int send_pdus_delta(struct deltas_db *, struct sender_common *);
int send_end_of_data_pdu(struct sender_common *, serial_t);
int send_error_report_pdu(int, uint8_t, uint16_t, struct pdu_header *,
    char const *);


#endif /* SRC_RTR_PDU_SENDER_H_ */
