#ifndef SRC_RTR_ERR_PDU_H_
#define SRC_RTR_ERR_PDU_H_

#include <stdbool.h>
#include <stdint.h>

#include "rtr/pdu.h"

#define ERR_PDU_CORRUPT_DATA				0
#define ERR_PDU_INTERNAL_ERROR				1
#define ERR_PDU_NO_DATA_AVAILABLE			2
#define ERR_PDU_INVALID_REQUEST				3
#define ERR_PDU_UNSUP_PROTO_VERSION			4
#define ERR_PDU_UNSUP_PDU_TYPE				5
#define ERR_PDU_WITHDRAWAL_UNKNOWN			6
#define ERR_PDU_DUPLICATE_ANNOUNCE			7
#define ERR_PDU_UNEXPECTED_PROTO_VERSION		8

/*
 * Wrappers for err_pdu_send().
 * Mainly, this is for the sake of making it easier to see whether the error is
 * supposed to contain a message and/or the original PDU or not.
 */
int err_pdu_send_corrupt_data(int, struct rtr_request const *, char const *);
int err_pdu_send_internal_error(int);
int err_pdu_send_no_data_available(int);
int err_pdu_send_invalid_request(int, struct rtr_request const *, char const *);
int err_pdu_send_invalid_request_truncated(int, unsigned char *, char const *);
int err_pdu_send_unsupported_pdu_type(int, struct rtr_request const *);

bool err_pdu_is_fatal(uint16_t);
void err_pdu_log(uint16_t, char *);

#endif /* SRC_RTR_ERR_PDU_H_ */
