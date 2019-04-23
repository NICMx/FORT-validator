#include "pdu_handler.h"

#include <err.h>
#include <errno.h>
#include <stddef.h>
#include <unistd.h>

#include "err_pdu.h"
#include "pdu.h"
#include "pdu_sender.h"
#include "rtr/db/vrps.h"

static int
warn_unexpected_pdu(int fd, void *pdu, char const *pdu_name)
{
	struct pdu_header *pdu_header = pdu;
	warnx("Unexpected %s PDU received", pdu_name);
	err_pdu_send(fd, pdu_header->protocol_version, ERR_PDU_UNSUP_PDU_TYPE,
	    pdu_header, "Unexpected PDU received");
	return -EINVAL;
}

int
handle_serial_notify_pdu(int fd, void *pdu)
{
	return warn_unexpected_pdu(fd, pdu, "Serial Notify");
}

static int
send_commmon_exchange(struct sender_common *common,
    int (*pdu_sender)(struct sender_common *))
{
	int error;

	/* Send Cache response PDU */
	error = send_cache_response_pdu(common);
	if (error)
		return error;

	/* Send Payload PDUs */
	error = pdu_sender(common);
	if (error)
		return error;

	/* Send End of data PDU */
	return send_end_of_data_pdu(common);
}

/*
 * TODO The semaphoring is bonkers. The code keeps locking, storing a value,
 * unlocking, locking again, and using the old value.
 * It doesn't look like it's a problem for now, but eventually will be, when old
 * delta forgetting is implemented.
 * I'm going to defer this because it shouldn't be done during the merge.
 */
int
handle_serial_query_pdu(int fd, void *pdu)
{
	struct serial_query_pdu *received = pdu;
	struct sender_common common;
	int error;
	enum delta_status updates;
	uint32_t current_serial;
	uint16_t session_id;
	uint8_t version;

	/*
	 * RFC 6810 and 8210:
	 * "If [...] either the router or the cache finds that the value of the
	 * Session ID is not the same as the other's, the party which detects
	 * the mismatch MUST immediately terminate the session with an Error
	 * Report PDU with code 0 ("Corrupt Data")"
	 */
	version = received->header.protocol_version;
	session_id = get_current_session_id(version);
	if (received->header.m.session_id != session_id)
		return err_pdu_send(fd, version, ERR_PDU_CORRUPT_DATA,
		    &received->header, NULL);

	current_serial = get_last_serial_number();
	init_sender_common(&common, fd, version, &session_id,
	    &received->serial_number, &current_serial);

	updates = deltas_db_status(common.start_serial);
	switch (updates) {
	case DS_NO_DATA_AVAILABLE:
		/* https://tools.ietf.org/html/rfc8210#section-8.4 */
		return err_pdu_send(fd, version, ERR_PDU_NO_DATA_AVAILABLE,
		    NULL, NULL);
	case DS_DIFF_UNDETERMINED:
		/* https://tools.ietf.org/html/rfc8210#section-8.3 */
		return send_cache_reset_pdu(&common);
	case DS_DIFF_AVAILABLE:
		/* https://tools.ietf.org/html/rfc8210#section-8.2 */
		return send_commmon_exchange(&common, send_pdus_delta);
	case DS_NO_DIFF:
		/* Typical exchange with no Payloads */
		error = send_cache_response_pdu(&common);
		if (error)
			return error;
		return send_end_of_data_pdu(&common);
	}

	warnx("Reached 'unreachable' code");
	return -EINVAL;
}

int
handle_reset_query_pdu(int fd, void *pdu)
{
	struct reset_query_pdu *received = pdu;
	struct sender_common common;
	uint32_t current_serial;
	uint16_t session_id;
	uint8_t version;
	enum delta_status updates;

	version = received->header.protocol_version;
	session_id = get_current_session_id(version);
	current_serial = get_last_serial_number();
	init_sender_common(&common, fd, version, &session_id, NULL,
	    &current_serial);

	updates = deltas_db_status(NULL);
	switch (updates) {
	case DS_NO_DATA_AVAILABLE:
		/* https://tools.ietf.org/html/rfc8210#section-8.4 */
		return err_pdu_send(fd, version, ERR_PDU_NO_DATA_AVAILABLE,
		    NULL, NULL);
	case DS_DIFF_AVAILABLE:
		/* https://tools.ietf.org/html/rfc8210#section-8.1 */
		return send_commmon_exchange(&common, send_pdus_base);
	case DS_DIFF_UNDETERMINED:
	case DS_NO_DIFF:
		break;
	}

	warnx("Reached 'unreachable' code");
	return -EINVAL;
}

int
handle_cache_response_pdu(int fd, void *pdu)
{
	return warn_unexpected_pdu(fd, pdu, "Cache Response");
}

int
handle_ipv4_prefix_pdu(int fd, void *pdu)
{
	return warn_unexpected_pdu(fd, pdu, "IPv4 Prefix");
}

int
handle_ipv6_prefix_pdu(int fd, void *pdu)
{
	return warn_unexpected_pdu(fd, pdu, "IPv6 Prefix");
}

int
handle_end_of_data_pdu(int fd, void *pdu)
{
	return warn_unexpected_pdu(fd, pdu, "End of Data");
}

int
handle_cache_reset_pdu(int fd, void *pdu)
{
	return warn_unexpected_pdu(fd, pdu, "Cache Reset");
}

int
handle_router_key_pdu(int fd, void *pdu)
{
	return warn_unexpected_pdu(fd, pdu, "Router Key");
}

int
handle_error_report_pdu(int fd, void *pdu)
{
	struct error_report_pdu *received = pdu;

	if (err_pdu_is_fatal(received->header.m.error_code)) {
		warnx("Fatal error report PDU received [code %u], closing socket.",
		    received->header.m.error_code);
		close(fd);
	}
	err_pdu_log(received->header.m.error_code, received->error_message);

	return 0;
}
