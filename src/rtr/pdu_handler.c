#include "pdu_handler.h"

#include <errno.h>
#include <stddef.h>
#include <unistd.h>

#include "err_pdu.h"
#include "log.h"
#include "pdu.h"
#include "pdu_sender.h"
#include "rtr/db/vrps.h"

static int
warn_unexpected_pdu(int fd, void *pdu, char const *pdu_name)
{
	struct pdu_header *pdu_header = pdu;
	pr_warn("Unexpected %s PDU received", pdu_name);
	err_pdu_send(fd, pdu_header->protocol_version, ERR_PDU_UNSUP_PDU_TYPE,
	    pdu_header, "PDU is unexpected or out of order.");
	return -EINVAL;
}

int
handle_serial_notify_pdu(int fd, void *pdu)
{
	return warn_unexpected_pdu(fd, pdu, "Serial Notify");
}

int
handle_serial_query_pdu(int fd, void *pdu)
{
	struct serial_query_pdu *received = pdu;
	struct sender_common common;
	struct deltas_db deltas;
	serial_t final_serial;
	int error;

	init_sender_common(&common, fd, received->header.protocol_version);
	/*
	 * RFC 6810 and 8210:
	 * "If [...] either the router or the cache finds that the value of the
	 * Session ID is not the same as the other's, the party which detects
	 * the mismatch MUST immediately terminate the session with an Error
	 * Report PDU with code 0 ("Corrupt Data")"
	 */
	if (received->header.m.session_id != common.session_id)
		return err_pdu_send(fd, common.version, ERR_PDU_CORRUPT_DATA,
		    &received->header, "Session ID doesn't match.");

	/*
	 * TODO (now) On certain errors, shouldn't we send error PDUs or
	 * something?
	 */

	/*
	 * For the record, there are two reasons why we want to work on a
	 * (shallow) copy of the deltas (as opposed to eg. a foreach):
	 * 1. We need to remove deltas that cancel each other.
	 *    (Which can't be done directly on the DB.)
	 * 2. It's probably best not to hold the VRPS read lock while writing
	 *    PDUs, to minimize writer stagnation.
	 */

	deltas_db_init(&deltas);
	error = vrps_get_deltas_from(received->serial_number, &final_serial,
	    &deltas);
	if (error == -EAGAIN) {
		error = err_pdu_send(fd, common.version,
		    ERR_PDU_NO_DATA_AVAILABLE, NULL, NULL);
		goto end;
	}
	if (error == -ESRCH) {
		/* https://tools.ietf.org/html/rfc6810#section-6.3 */
		error = send_cache_reset_pdu(&common);
		goto end;
	}
	if (error)
		goto end;

	/*
	 * https://tools.ietf.org/html/rfc6810#section-6.2
	 * (Except the end of data PDU.)
	 */

	error = send_cache_response_pdu(&common);
	if (error)
		goto end;
	error = send_pdus_delta(&deltas, &common);
	if (error)
		goto end; /* TODO (now) maybe send something? */
	error = send_end_of_data_pdu(&common, final_serial);

end:
	deltas_db_cleanup(&deltas, deltagroup_cleanup);
	return error;
}

struct base_roa_args {
	bool started;
	struct sender_common common;
	serial_t last_serial;
};

static int
send_base_roa(struct vrp const *vrp, void *arg)
{
	struct base_roa_args *args = arg;
	int error;

	if (!args->started) {
		error = send_cache_response_pdu(&args->common);
		if (error)
			return error;
		args->started = true;
	}

	/* TODO (now) maybe send something on error? */
	return send_prefix_pdu(&args->common, vrp, FLAG_ANNOUNCEMENT);
}

int
handle_reset_query_pdu(int fd, void *pdu)
{
	struct reset_query_pdu *received = pdu;
	struct base_roa_args args;
	serial_t current_serial;
	int error;

	args.started = false;
	init_sender_common(&args.common, fd, received->header.protocol_version);

	/*
	 * It's probably best not to work on a copy, because the tree is large.
	 * Unfortunately, this means we'll have to encourage writer stagnation,
	 * but most clients are supposed to request far more serial queries than
	 * reset queries.
	 */

	error = vrps_foreach_base_roa(send_base_roa, &args, &current_serial);
	if (error == -EAGAIN)
		return err_pdu_send(fd, args.common.version,
		    ERR_PDU_NO_DATA_AVAILABLE, NULL, NULL);
	if (error)
		return error;

	return send_end_of_data_pdu(&args.common, current_serial);
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
		pr_warn("Fatal error report PDU received [code %u], closing socket.",
		    received->header.m.error_code);
		close(fd);
	}
	err_pdu_log(received->header.m.error_code, received->error_message);

	return 0;
}
