#include "err_pdu.h"

#include <err.h>
#include <unistd.h>
#include "pdu_sender.h"
#include "log.h"

int
err_pdu_send(int fd, uint8_t version, uint16_t code, void *err_pdu_header,
    char const *message)
{
	int error;

	error = send_error_report_pdu(fd, version, code, err_pdu_header,
	    message);
	if (err_pdu_is_fatal(code)) {
		warnx("Fatal error report PDU sent [code %u], closing socket.",
		    code);
		close(fd);
	}

	return error;
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
