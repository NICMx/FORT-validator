#ifndef SRC_RTR_ERR_PDU_H_
#define SRC_RTR_ERR_PDU_H_

#include <stdbool.h>
#include <stdint.h>

#include "rtr/pdu.h"

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
int err_pdu_send_unsupported_proto_version(int, unsigned char *, char const *);
int err_pdu_send_unsupported_pdu_type(int, struct rtr_request const *);

char const *err_pdu_to_string(uint16_t);

#endif /* SRC_RTR_ERR_PDU_H_ */
