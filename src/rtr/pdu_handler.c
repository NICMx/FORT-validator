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

struct send_delta_args {
	int fd;
	uint8_t rtr_version;
	bool cache_response_sent;
};

static int
send_cache_response_maybe(struct send_delta_args *args)
{
	int error;

	if (!args->cache_response_sent) {
		error = send_cache_response_pdu(args->fd, args->rtr_version);
		if (error)
			return error;
		args->cache_response_sent = true;
	}

	return 0;
}

static int
send_delta_vrp(struct delta_vrp const *delta, void *arg)
{
	struct send_delta_args *args = arg;
	int error;

	error = send_cache_response_maybe(args);
	if (error)
		return error;

	return send_prefix_pdu(args->fd, args->rtr_version, &delta->vrp,
	    delta->flags);
}

static int
send_delta_rk(struct delta_router_key const *delta, void *arg)
{
	struct send_delta_args *args = arg;
	int error;

	error = send_cache_response_maybe(args);
	if (error)
		return error;

	return send_router_key_pdu(args->fd, args->rtr_version,
	    &delta->router_key, delta->flags);
}

int
handle_serial_query_pdu(int fd, struct rtr_request const *request)
{
	struct serial_query_pdu *query = request->pdu;
	struct send_delta_args args;
	serial_t final_serial;
	int error;

	/*
	 * RFC 6810 and 8210:
	 * "If [...] either the router or the cache finds that the value of the
	 * Session ID is not the same as the other's, the party which detects
	 * the mismatch MUST immediately terminate the session with an Error
	 * Report PDU with code 0 ("Corrupt Data")"
	 */
	args.rtr_version = query->header.protocol_version;
	if (query->header.m.session_id !=
	    get_current_session_id(args.rtr_version))
		return err_pdu_send_corrupt_data(fd, args.rtr_version, request,
		    "Session ID doesn't match.");

	args.fd = fd;
	args.cache_response_sent = false;

	/*
	 * For the record, there are two reasons why we want to work on a
	 * (shallow) copy of the deltas (as opposed to eg. a foreach):
	 * 1. We need to remove deltas that cancel each other.
	 *    (Which can't be done directly on the DB.)
	 * 2. It's probably best not to hold the VRPS read lock while writing
	 *    PDUs, to minimize writer stagnation.
	 */

	error = vrps_foreach_delta_since(query->serial_number, &final_serial,
	    send_delta_vrp, send_delta_rk, &args);
	switch (error) {
	case 0:
		/*
		 * https://tools.ietf.org/html/rfc6810#section-6.2
		 *
		 * These functions presently only fail on writes, allocations
		 * and programming errors. Best avoid error PDUs.
		 */
		if (!args.cache_response_sent) {
			error = send_cache_response_pdu(fd, args.rtr_version);
			if (error)
				return error;
		}
		return send_end_of_data_pdu(fd, args.rtr_version, final_serial);
	case -EAGAIN: /* Database still under construction */
		error = err_pdu_send_no_data_available(fd, args.rtr_version);
		return error;
	case -ESRCH: /* Invalid serial */
		/* https://tools.ietf.org/html/rfc6810#section-6.3 */
		return send_cache_reset_pdu(fd, args.rtr_version);
	case -ENOMEM: /* Memory allocation failure */
		enomem_panic();
	case EAGAIN: /* Too many threads */
		/*
		 * I think this should be more of a "try again" thing, but
		 * RTR does not provide a code for that. Just fall through.
		 */
		break;
	}

	return err_pdu_send_internal_error(fd, args.rtr_version);
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



static int
send_base_router_key(struct router_key const *key, void *arg)
{
	struct base_roa_args *args = arg;
	int error;

	if (!args->started) {
		error = send_cache_response_pdu(args->fd, args->version);
		if (error)
			return error;
		args->started = true;
	}

	return send_router_key_pdu(args->fd, args->version, key,
	    FLAG_ANNOUNCEMENT);
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

	error = vrps_foreach_base(send_base_roa, send_base_router_key, &args);

	/* See handle_serial_query_pdu() for some comments. */
	switch (error) {
	case 0:
		/* Assure that cache response is (or was) sent */
		if (args.started)
			break;
		error = send_cache_response_pdu(fd, args.version);
		if (error)
			return error;
		break;
	case -EAGAIN:
		return err_pdu_send_no_data_available(fd, args.version);
	case EAGAIN:
		err_pdu_send_internal_error(fd, args.version);
		return error;
	default:
		/* Any other error must stop sending more PDUs */
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
		pr_op_info("Client responded with error PDU '%s' ('%s'). Closing socket.",
		    error_name, received->error_message);
	else
		pr_op_info("Client responded with error PDU '%s'. Closing socket.",
		    error_name);

	return -EINVAL;
}
