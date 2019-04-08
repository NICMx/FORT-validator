#ifndef SRC_RTR_ERR_PDU_H_
#define SRC_RTR_ERR_PDU_H_

#include <stdbool.h>
#include <stdint.h>

#define ERR_PDU_CORRUPT_DATA				0
#define ERR_PDU_INTERNAL_ERROR				1
#define ERR_PDU_NO_DATA_AVAILABLE			2
#define ERR_PDU_INVALID_REQUEST				3
#define ERR_PDU_UNSUP_PROTO_VERSION			4
#define ERR_PDU_UNSUP_PDU_TYPE				5
#define ERR_PDU_WITHDRAWAL_UNKNOWN			6
#define ERR_PDU_DUPLICATE_ANNOUNCE			7
#define ERR_PDU_UNEXPECTED_PROTO_VERSION		8


int err_pdu_send(int, uint8_t, uint16_t, void *, char const *);
bool err_pdu_is_fatal(uint16_t);
void err_pdu_log(uint16_t, char *);

#endif /* SRC_RTR_ERR_PDU_H_ */
