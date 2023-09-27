#ifndef SRC_RTR_ERR_PDU_H_
#define SRC_RTR_ERR_PDU_H_

#include "rtr/pdu.h"

/*
 * Wrappers for err_pdu_send().
 * Mainly, this is for the sake of making it easier to see whether the error is
 * supposed to contain a message and/or the original PDU or not.
 */
int err_pdu_send_corrupt_data(int, uint8_t, struct rtr_request const *,
    char const *);
int err_pdu_send_internal_error(int, uint8_t);
int err_pdu_send_no_data_available(int, uint8_t);
int err_pdu_send_invalid_request(int, uint8_t, struct rtr_request const *,
    char const *);
int err_pdu_send_invalid_request_truncated(int, uint8_t, unsigned char *,
    char const *);
int err_pdu_send_unsupported_proto_version(int, uint8_t, unsigned char *,
    char const *);
int err_pdu_send_unsupported_pdu_type(int, uint8_t, struct rtr_request const *);
int err_pdu_send_unexpected_proto_version(int, uint8_t, unsigned char *,
    char const *);

char const *err_pdu_to_string(uint16_t);

#endif /* SRC_RTR_ERR_PDU_H_ */
