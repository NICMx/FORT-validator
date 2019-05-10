#include "err_pdu.h"

#include <unistd.h>
#include "pdu_sender.h"
#include "log.h"

/*
 * TODO (urgent) According to the function below, NO_DATA_AVAILABLE is not
 * fatal. However, some callers of this function are terminating the connection
 * regardless of that.
 */
static int
err_pdu_send(int fd, uint16_t code, struct rtr_request const *request,
    char const *message_const)
{
	/*
	 * This function must always return error so callers can interrupt
	 * themselves easily.
	 */

	int error;
	char *message;

	/* TODO (now) Prevent errors to errors */

	message = (message_const != NULL) ? strdup(message_const) : NULL;
	error = send_error_report_pdu(fd, code, request, message);
	free(message);

	if (err_pdu_is_fatal(code)) {
		pr_warn("Fatal error report PDU sent [code %u], closing socket.",
		    code);
		close(fd);
	}

	return error ? error : -EINVAL;
}

int
err_pdu_send_corrupt_data(int fd, struct rtr_request const *request,
    char const *message)
{
	return err_pdu_send(fd, ERR_PDU_CORRUPT_DATA, request, message);
}

int
err_pdu_send_internal_error(int fd)
{
	return err_pdu_send(fd, ERR_PDU_INTERNAL_ERROR, NULL, NULL);
}

int
err_pdu_send_no_data_available(int fd)
{
	return err_pdu_send(fd, ERR_PDU_NO_DATA_AVAILABLE, NULL, NULL);
}

int
err_pdu_send_invalid_request(int fd, struct rtr_request const *request,
    char const *message)
{
	return err_pdu_send(fd, ERR_PDU_INVALID_REQUEST, request, message);
}

/* Caution: @header is supposed to be in serialized form. */
int
err_pdu_send_invalid_request_truncated(int fd, unsigned char *header,
    char const *message)
{
	struct rtr_request request = {
		.bytes = header,
		.bytes_len = RTRPDU_HEADER_LEN,
		.pdu = NULL,
	};
	return err_pdu_send_invalid_request(fd, &request, message);
}

int
err_pdu_send_unsupported_pdu_type(int fd, struct rtr_request const *request)
{
	return err_pdu_send(fd, ERR_PDU_UNSUP_PDU_TYPE, request, NULL);
}

bool
err_pdu_is_fatal(uint16_t code)
{
	/* Only NO_DATA_AVAILABLE error isn't fatal */
	return code != ERR_PDU_NO_DATA_AVAILABLE;
}

void
err_pdu_log(uint16_t code, char *message)
{
	char const *code_title;

	switch (code) {
	case ERR_PDU_CORRUPT_DATA:
		code_title = "Corrupt Data";
		break;
	case ERR_PDU_INTERNAL_ERROR:
		code_title = "Internal Error";
		break;
	case ERR_PDU_NO_DATA_AVAILABLE:
		code_title = "No Data Available";
		break;
	case ERR_PDU_INVALID_REQUEST:
		code_title = "Invalid Request";
		break;
	case ERR_PDU_UNSUP_PROTO_VERSION:
		code_title = "Unsupported Protocol Version";
		break;
	case ERR_PDU_UNSUP_PDU_TYPE:
		code_title = "Unsupported PDU Type";
		break;
	case ERR_PDU_WITHDRAWAL_UNKNOWN:
		code_title = "Withdrawal of Unknown Record";
		break;
	case ERR_PDU_DUPLICATE_ANNOUNCE:
		code_title = "Duplicate Announcement Received";
		break;
	case ERR_PDU_UNEXPECTED_PROTO_VERSION:
		code_title = "Unexpected Protocol Version";
		break;
	default:
		code_title = "Unknown error code";
		break;
	}

	pr_err("Error report PDU info: '%s', message '%s'.",
	    code_title, message == NULL ? "[empty]" : message);
}
