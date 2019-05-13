#include "pdu_handler.h"

#include <errno.h>
#include <stddef.h>
#include <unistd.h>

#include "err_pdu.h"
#include "log.h"
#include "pdu.h"
#include "pdu_sender.h"
#include "rtr/db/vrps.h"

#define warn_unexpected_pdu(fd, request, pdu_name)			\
	err_pdu_send_invalid_request(fd, request,			\
	    "Clients are not supposed to send " pdu_name " PDUs.");

int
handle_serial_notify_pdu(int fd, struct rtr_request const *request)
{
	return warn_unexpected_pdu(fd, request, "Serial Notify");
}

int
handle_serial_query_pdu(int fd, struct rtr_request const *request)
{
	struct serial_query_pdu *query = request->pdu;
	struct deltas_db deltas;
	serial_t final_serial;
	int error;

	/*
	 * RFC 6810 and 8210:
	 * "If [...] either the router or the cache finds that the value of the
	 * Session ID is not the same as the other's, the party which detects
	 * the mismatch MUST immediately terminate the session with an Error
	 * Report PDU with code 0 ("Corrupt Data")"
	 */
	if (query->header.m.session_id != get_current_session_id(RTR_V0))
		return err_pdu_send_corrupt_data(fd, request,
		    "Session ID doesn't match.");

	/*
	 * For the record, there are two reasons why we want to work on a
	 * (shallow) copy of the deltas (as opposed to eg. a foreach):
	 * 1. We need to remove deltas that cancel each other.
	 *    (Which can't be done directly on the DB.)
	 * 2. It's probably best not to hold the VRPS read lock while writing
	 *    PDUs, to minimize writer stagnation.
	 */

	deltas_db_init(&deltas);
	error = vrps_get_deltas_from(query->serial_number, &final_serial,
	    &deltas);
	switch (error) {
	case 0:
		break;
	case -EAGAIN: /* Database still under construction */
		err_pdu_send_no_data_available(fd);
		error = 0; /* Don't panic; client should retry later */
		goto end;
	case -ESRCH: /* Invalid serial */
		/* https://tools.ietf.org/html/rfc6810#section-6.3 */
		error = send_cache_reset_pdu(fd);
		goto end;
	case -ENOMEM: /* Memory allocation failure */
		goto end;
	case EAGAIN: /* Too many threads */
		/*
		 * I think this should be more of a "try again" thing, but
		 * RTR does not provide a code for that. Just fall through.
		 */
	default:
		error = err_pdu_send_internal_error(fd);
		goto end;
	}

	/*
	 * https://tools.ietf.org/html/rfc6810#section-6.2
	 *
	 * These functions presently only fail on writes, allocations and
	 * programming errors. Best avoid error PDUs.
	 */

	error = send_cache_response_pdu(fd);
	if (error)
		goto end;
	error = send_delta_pdus(fd, &deltas);
	if (error)
		goto end;
	error = send_end_of_data_pdu(fd, final_serial);

end:
	deltas_db_cleanup(&deltas, deltagroup_cleanup);
	return error;
}

struct base_roa_args {
	bool started;
	int fd;
};

static int
send_base_roa(struct vrp const *vrp, void *arg)
{
	struct base_roa_args *args = arg;
	int error;

	if (!args->started) {
		error = send_cache_response_pdu(args->fd);
		if (error)
			return error;
		args->started = true;
	}

	return send_prefix_pdu(args->fd, vrp, FLAG_ANNOUNCEMENT);
}

int
handle_reset_query_pdu(int fd, struct rtr_request const *request)
{
	struct base_roa_args args;
	serial_t current_serial;
	int error;

	args.started = false;
	args.fd = fd;

	/*
	 * It's probably best not to work on a copy, because the tree is large.
	 * Unfortunately, this means we'll have to encourage writer stagnation,
	 * but thankfully, most clients are supposed to request far more serial
	 * queries than reset queries.
	 */

	error = vrps_foreach_base_roa(send_base_roa, &args, &current_serial);

	/* See handle_serial_query_pdu() for some comments. */
	switch (error) {
	case 0:
		break;
	case -EAGAIN:
		err_pdu_send_no_data_available(fd);
		return 0;
	case EAGAIN:
		err_pdu_send_internal_error(fd);
		return error;
	}

	return send_end_of_data_pdu(fd, current_serial);
}

int
handle_cache_response_pdu(int fd, struct rtr_request const *request)
{
	return warn_unexpected_pdu(fd, request, "Cache Response");
}

int
handle_ipv4_prefix_pdu(int fd, struct rtr_request const *request)
{
	return warn_unexpected_pdu(fd, request, "IPv4 Prefix");
}

int
handle_ipv6_prefix_pdu(int fd, struct rtr_request const *request)
{
	return warn_unexpected_pdu(fd, request, "IPv6 Prefix");
}

int
handle_end_of_data_pdu(int fd, struct rtr_request const *request)
{
	return warn_unexpected_pdu(fd, request, "End of Data");
}

int
handle_cache_reset_pdu(int fd, struct rtr_request const *request)
{
	return warn_unexpected_pdu(fd, request, "Cache Reset");
}

int
handle_router_key_pdu(int fd, struct rtr_request const *request)
{
	return warn_unexpected_pdu(fd, request, "Router Key");
}

int
handle_error_report_pdu(int fd, struct rtr_request const *request)
{
	struct error_report_pdu *received = request->pdu;
	char const *error_name;

	error_name = err_pdu_to_string(received->header.m.error_code);

	if (received->error_message != NULL)
		pr_info("Client responded with error PDU '%s' ('%s'). Closing socket.",
		    error_name, received->error_message);
	else
		pr_info("Client responded with error PDU '%s'. Closing socket.",
		    error_name);

	return -EINVAL;
}
