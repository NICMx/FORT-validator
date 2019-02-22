#ifndef SRC_RTR_PDU_SENDER_H_
#define SRC_RTR_PDU_SENDER_H_

#include <sys/types.h>


int send_cache_reset_pdu(int, u_int8_t);
int send_cache_response_pdu(int, u_int8_t, u_int16_t);
int send_payload_pdus(int, u_int8_t, u_int32_t);
int send_end_of_data_pdu(int, u_int8_t, u_int16_t);


#endif /* SRC_RTR_PDU_SENDER_H_ */
