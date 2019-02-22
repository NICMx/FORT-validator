#include "pdu_handler.h"

#include <err.h>
#include <errno.h>

#include "pdu.h"
#include "pdu_sender.h"

static int warn_unexpected_pdu(char *);

static int
warn_unexpected_pdu(char *pdu_name)
{
	warnx("RTR servers are not expected to receive %s PDUs, but we got one anyway (Closing socket.)",
	    pdu_name);
	return -EINVAL;
}

int
handle_serial_notify_pdu(int fd, void *pdu)
{
	return warn_unexpected_pdu("Serial Notify");
}

int
handle_serial_query_pdu(int fd, void *pdu)
{
	return -EUNIMPLEMENTED;
}

int
handle_reset_query_pdu(int fd, void *pdu)
{
	struct reset_query_pdu *received = pdu;
	u_int16_t session_id;
	u_int8_t version;
	int error;

	/*
	 * FIXME Complete behaviour:
	 * - Do I have data?
	 *   + NO: Send error
	 *         https://tools.ietf.org/html/rfc8210#section-8.4
	 *   + YES: Send data (cache response -> payloads -> end of data)
	 *          https://tools.ietf.org/html/rfc8210#section-8.1
	 */

	/* FIXME Handle sessions and its ID */
	session_id = 1;
	version = received->header.protocol_version;

	// Send Cache response PDU
	error = send_cache_response_pdu(fd, version, session_id);
	if (error)
		return error;

	// Send Payload PDUs
	// TODO ..and handle Serial Number
	error = send_payload_pdus(fd, version, 1);
	if (error)
		return error;

	// Send End of data PDU
	return send_end_of_data_pdu(fd, version, session_id);
}

int
handle_cache_response_pdu(int fd, void *pdu)
{
	return warn_unexpected_pdu("Cache Response");
}

int
handle_ipv4_prefix_pdu(int fd, void *pdu)
{
	return warn_unexpected_pdu("IPv4 Prefix");
}

int
handle_ipv6_prefix_pdu(int fd, void *pdu)
{
	return warn_unexpected_pdu("IPv6 Prefix");
}

int
handle_end_of_data_pdu(int fd, void *pdu)
{
	return warn_unexpected_pdu("End of Data");
}

int
handle_cache_reset_pdu(int fd, void *pdu)
{
	return warn_unexpected_pdu("Cache Reset");
}

int
handle_error_report_pdu(int fd, void *pdu)
{
	/* TODO */
	return -EUNIMPLEMENTED;
}
