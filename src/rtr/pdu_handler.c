#include "pdu_handler.h"

#include <errno.h>
#include <stddef.h>
#include <unistd.h>

#include "err_pdu.h"
#include "log.h"
#include "pdu.h"
#include "pdu_sender.h"
#include "rtr/db/vrps.h"

#define WARN_UNEXPECTED_PDU(name, fd, request, pdu_name)		\
	struct name##_pdu *pdu = request->pdu;				\
	return err_pdu_send_invalid_request(fd,				\
	    pdu->header.protocol_version,				\
	    request, "Clients are not supposed to send " pdu_name " PDUs.");

int
handle_serial_notify_pdu(int fd, struct rtr_request const *request)
{
	WARN_UNEXPECTED_PDU(serial_notify, fd, request, "Serial Notify");
}

int
handle_serial_query_pdu(int fd, struct rtr_request const *request)
{
	struct serial_query_pdu *query = request->pdu;
	struct deltas_db deltas;
	serial_t final_serial;
	uint8_t version;
	int error;

	/*
	 * RFC 6810 and 8210:
	 * "If [...] either the router or the cache finds that the value of the
	 * Session ID is not the same as the other's, the party which detects
	 * the mismatch MUST immediately terminate the session with an Error
	 * Report PDU with code 0 ("Corrupt Data")"
	 */
	version = query->header.protocol_version;
	if (query->header.m.session_id !=
	    get_current_session_id(version))
		return err_pdu_send_corrupt_data(fd, version, request,
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
		error = err_pdu_send_no_data_available(fd, version);
		goto end;
	case -ESRCH: /* Invalid serial */
		/* https://tools.ietf.org/html/rfc6810#section-6.3 */
		error = send_cache_reset_pdu(fd, version);
		goto end;
	case -ENOMEM: /* Memory allocation failure */
		goto end;
	case EAGAIN: /* Too many threads */
		/*
		 * I think this should be more of a "try again" thing, but
		 * RTR does not provide a code for that. Just fall through.
		 */
	default:
		error = err_pdu_send_internal_error(fd, version);
		goto end;
	}

	/*
	 * https://tools.ietf.org/html/rfc6810#section-6.2
	 *
	 * These functions presently only fail on writes, allocations and
	 * programming errors. Best avoid error PDUs.
	 */

	error = send_cache_response_pdu(fd, version);
	if (error)
		goto end;
	error = send_delta_pdus(fd, version, &deltas);
	if (error)
		goto end;
	error = send_end_of_data_pdu(fd, version, final_serial);

end:
	deltas_db_cleanup(&deltas, deltagroup_cleanup);
	return error;
}

struct base_roa_args {
	bool started;
	int fd;
	uint8_t version;
};

static int
send_base_roa(struct vrp const *vrp, void *arg)
{
	struct base_roa_args *args = arg;
	int error;

	if (!args->started) {
		error = send_cache_response_pdu(args->fd, args->version);
		if (error)
			return error;
		args->started = true;
	}

	return send_prefix_pdu(args->fd, args->version, vrp, FLAG_ANNOUNCEMENT);
}

int
handle_reset_query_pdu(int fd, struct rtr_request const *request)
{
	struct reset_query_pdu *pdu = request->pdu;
	struct base_roa_args args;
	serial_t current_serial;
	int error;

	args.started = false;
	args.fd = fd;
	args.version = pdu->header.protocol_version;

	error = get_last_serial_number(&current_serial);
	switch (error) {
	case 0:
		break;
	case -EAGAIN:
		return err_pdu_send_no_data_available(fd, args.version);
	default:
		err_pdu_send_internal_error(fd, args.version);
		return error;
	}

	/*
	 * It's probably best not to work on a copy, because the tree is large.
	 * Unfortunately, this means we'll have to encourage writer stagnation,
	 * but thankfully, most clients are supposed to request far more serial
	 * queries than reset queries.
	 */

	/* FIXME Apply to router keys as well */
	error = vrps_foreach_base_roa(send_base_roa, &args);

	/* See handle_serial_query_pdu() for some comments. */
	switch (error) {
	case 0:
		break;
	case -EAGAIN:
		return err_pdu_send_no_data_available(fd, args.version);
	case EAGAIN:
		err_pdu_send_internal_error(fd, args.version);
		return error;
	}

	return send_end_of_data_pdu(fd, args.version, current_serial);
}

int
handle_cache_response_pdu(int fd, struct rtr_request const *request)
{
	WARN_UNEXPECTED_PDU(cache_response, fd, request, "Cache Response");
}

int
handle_ipv4_prefix_pdu(int fd, struct rtr_request const *request)
{
	WARN_UNEXPECTED_PDU(ipv4_prefix, fd, request, "IPv4 Prefix");
}

int
handle_ipv6_prefix_pdu(int fd, struct rtr_request const *request)
{
	WARN_UNEXPECTED_PDU(ipv6_prefix, fd, request, "IPv6 Prefix");
}

int
handle_end_of_data_pdu(int fd, struct rtr_request const *request)
{
	WARN_UNEXPECTED_PDU(end_of_data, fd, request, "End of Data");
}

int
handle_cache_reset_pdu(int fd, struct rtr_request const *request)
{
	WARN_UNEXPECTED_PDU(cache_reset, fd, request, "Cache Reset");
}

int
handle_router_key_pdu(int fd, struct rtr_request const *request)
{
	WARN_UNEXPECTED_PDU(router_key, fd, request, "Router Key");
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
