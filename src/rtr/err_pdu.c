#include "rtr/err_pdu.h"

#include <errno.h>

#include "alloc.h"
#include "rtr/pdu_sender.h"

typedef enum rtr_error_code {
	ERR_PDU_CORRUPT_DATA			= 0,
	ERR_PDU_INTERNAL_ERROR			= 1,
	ERR_PDU_NO_DATA_AVAILABLE		= 2,
	ERR_PDU_INVALID_REQUEST			= 3,
	ERR_PDU_UNSUP_PROTO_VERSION		= 4,
	ERR_PDU_UNSUP_PDU_TYPE			= 5,
	ERR_PDU_WITHDRAWAL_UNKNOWN		= 6,
	ERR_PDU_DUPLICATE_ANNOUNCE		= 7,
	ERR_PDU_UNEXPECTED_PROTO_VERSION	= 8,
} rtr_error_code_t;

static int
err_pdu_send(int fd, uint8_t version, rtr_error_code_t code,
    struct rtr_buffer const *request, char const *msg_const)
{
	char *msg;

	if ((request == NULL) || (request->bytes[1] != PDU_TYPE_ERROR_REPORT)) {
		/* Need a clone to remove the const. */
		msg = (msg_const != NULL) ? pstrdup(msg_const) : NULL;
		send_error_report_pdu(fd, version, code, request, msg);
		free(msg);
	}

	return -EINVAL; /* For propagation */
}

int
err_pdu_send_corrupt_data(int fd, uint8_t version,
    struct rtr_buffer const *request, char const *msg)
{
	return err_pdu_send(fd, version, ERR_PDU_CORRUPT_DATA, request, msg);
}

/*
 * Please note: If you're planning to send this error due to a memory
 * allocation failure, you probably shouldn't; you'd likely only aggravate the
 * problem.
 */
int
err_pdu_send_internal_error(int fd, uint8_t version)
{
	return err_pdu_send(fd, version, ERR_PDU_INTERNAL_ERROR, NULL, NULL);
}

int
err_pdu_send_no_data_available(int fd, uint8_t version)
{
	err_pdu_send(fd, version, ERR_PDU_NO_DATA_AVAILABLE, NULL, NULL);
	/*
	 * The connection should not be terminated because of this error.
	 * So don't panic; client should retry later.
	 */
	return 0;
}

int
err_pdu_send_invalid_request(int fd, uint8_t version,
    struct rtr_buffer const *request, char const *msg)
{
	return err_pdu_send(fd, version, ERR_PDU_INVALID_REQUEST, request, msg);
}

int
err_pdu_send_invalid_request_truncated(int fd, uint8_t version,
    struct rtr_buffer const *request, char const *msg)
{
	return err_pdu_send_invalid_request(fd, version, request, msg);
}

int
err_pdu_send_unsupported_proto_version(int fd, uint8_t version,
    struct rtr_buffer const *request, char const *msg)
{
	return err_pdu_send(fd, version, ERR_PDU_UNSUP_PROTO_VERSION, request,
	    msg);
}

int
err_pdu_send_unsupported_pdu_type(int fd, uint8_t version,
    struct rtr_buffer const *request)
{
	return err_pdu_send(fd, version, ERR_PDU_UNSUP_PDU_TYPE, request, NULL);
}

int
err_pdu_send_unexpected_proto_version(int fd, uint8_t version,
    struct rtr_buffer const *request, char const *msg)
{
	return err_pdu_send(fd, version, ERR_PDU_UNEXPECTED_PROTO_VERSION,
	    request, msg);
}

char const *
err_pdu_to_string(uint16_t code)
{
	switch ((rtr_error_code_t) code) {
	case ERR_PDU_CORRUPT_DATA:
		return "Corrupt Data";
	case ERR_PDU_INTERNAL_ERROR:
		return "Internal Error";
	case ERR_PDU_NO_DATA_AVAILABLE:
		return "No Data Available";
	case ERR_PDU_INVALID_REQUEST:
		return "Invalid Request";
	case ERR_PDU_UNSUP_PROTO_VERSION:
		return "Unsupported Protocol Version";
	case ERR_PDU_UNSUP_PDU_TYPE:
		return "Unsupported PDU Type";
	case ERR_PDU_WITHDRAWAL_UNKNOWN:
		return "Withdrawal of Unknown Record";
	case ERR_PDU_DUPLICATE_ANNOUNCE:
		return "Duplicate Announcement Received";
	case ERR_PDU_UNEXPECTED_PROTO_VERSION:
		return "Unexpected Protocol Version";
	}

	return "Unknown error code";
}
