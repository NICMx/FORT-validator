#include "pdu_handler.h"

#include <err.h>
#include <errno.h>
#include <stddef.h>

#include "pdu.h"
#include "pdu_sender.h"
#include "vrps.h"

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

static int
send_commmon_exchange(struct sender_common *common)
{
	int error;

	// Send Cache response PDU
	error = send_cache_response_pdu(common);
	if (error)
		return error;

	// Send Payload PDUs
	error = send_payload_pdus(common);
	if (error)
		return error;

	// Send End of data PDU
	return send_end_of_data_pdu(common);
}

int
handle_serial_query_pdu(int fd, void *pdu)
{
	struct serial_query_pdu *received = pdu;
	struct sender_common common;
	int error, updates;
	u_int32_t current_serial;
	u_int16_t session_id;
	u_int8_t version;

	/*
	 * RFC 6810 and 8210:
	 * "If [...] either the router or the cache finds that the value of the
	 * Session ID is not the same as the other's, the party which detects the
	 * mismatch MUST immediately terminate the session with an Error Report PDU
	 * with code 0 ("Corrupt Data")"
	 */
	version = received->header.protocol_version;
	session_id = current_session_id(version);
	if (received->header.session_id != session_id)
		return send_error_report_pdu(&common, ERR_CORRUPT_DATA, NULL, NULL);

	current_serial = last_serial_number();
	init_sender_common(&common, fd, version, &session_id,
	    &received->serial_number, &current_serial);

	updates = deltas_db_status(common.start_serial);
	switch (updates) {
	case NO_DATA_AVAILABLE:
		/* https://tools.ietf.org/html/rfc8210#section-8.4 */
		return send_error_report_pdu(&common, ERR_NO_DATA_AVAILABLE, NULL, NULL);
	case DIFF_UNDETERMINED:
		/* https://tools.ietf.org/html/rfc8210#section-8.3 */
		return send_cache_reset_pdu(&common);
	case DIFF_AVAILABLE:
		/* https://tools.ietf.org/html/rfc8210#section-8.2 */
		/*
		 * TODO The diff calculation between serials isn't quite ready yet,
		 * so always respond with a cache reset. When the implementation is
		 * ready use:
		 *
		 * return send_commmon_exchange(&common);
		 */
		return send_cache_reset_pdu(&common);
	case NO_DIFF:
		/* Typical exchange with no Payloads */
		error = send_cache_response_pdu(&common);
		if (error)
			return error;
		return send_end_of_data_pdu(&common);
	default:
		error = -EINVAL;
		err(error, "Reached 'unreachable' code");
		return error;
	}
}

int
handle_reset_query_pdu(int fd, void *pdu)
{
	struct reset_query_pdu *received = pdu;
	struct sender_common common;
	u_int32_t current_serial;
	u_int16_t session_id;
	u_int8_t version;
	int error, updates;

	version = received->header.protocol_version;
	session_id = current_session_id(version);
	current_serial = last_serial_number();
	init_sender_common(&common, fd, version, &session_id, NULL,
	    &current_serial);

	updates = deltas_db_status(common.start_serial);
	switch (updates) {
	case NO_DATA_AVAILABLE:
		/* https://tools.ietf.org/html/rfc8210#section-8.4 */
		return send_error_report_pdu(&common, ERR_NO_DATA_AVAILABLE, NULL, NULL);
	case DIFF_AVAILABLE:
		/* https://tools.ietf.org/html/rfc8210#section-8.1 */
		return send_commmon_exchange(&common);
	default:
		error = -EINVAL;
		err(error, "Reached 'unreachable' code");
		return error;
	}
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
	struct error_report_pdu *received = pdu;
	struct sender_common common;

	init_sender_common(&common, fd, received->header.protocol_version,
		NULL, NULL, NULL);

	/* TODO complete handler */
	return 0;
}
