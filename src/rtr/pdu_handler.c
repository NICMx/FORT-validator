#include "rtr/pdu_handler.h"

#include <errno.h>

#include "log.h"
#include "rtr/db/vrps.h"
#include "rtr/err_pdu.h"
#include "rtr/pdu_sender.h"

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
handle_serial_query_pdu(struct rtr_request *request)
{
	struct send_delta_args args;
	serial_t final_serial;
	enum vrps_foreach_delta_since_result result;
	int error;

	pr_op_debug("Serial Query. Request version/session/serial: %u/%u/%u",
	    request->pdu.rtr_version,
	    request->pdu.obj.sq.session_id,
	    request->pdu.obj.sq.serial_number);

	args.fd = request->fd;
	args.rtr_version = request->pdu.rtr_version;
	args.cache_response_sent = false;

	/*
	 * RFC 6810 and 8210:
	 * "If [...] either the router or the cache finds that the value of the
	 * Session ID is not the same as the other's, the party which detects
	 * the mismatch MUST immediately terminate the session with an Error
	 * Report PDU with code 0 ("Corrupt Data")"
	 */
	if (request->pdu.obj.sq.session_id != get_current_session_id(args.rtr_version))
		return err_pdu_send_corrupt_data(args.fd, args.rtr_version,
			&request->pdu.raw, "Session ID doesn't match.");

	/*
	 * For the record, there are two reasons why we want to work on a
	 * (shallow) copy of the deltas (as opposed to eg. a foreach):
	 * 1. We need to remove deltas that cancel each other.
	 *    (Which can't be done directly on the DB.)
	 * 2. It's probably best not to hold the VRPS read lock while writing
	 *    PDUs, to minimize writer stagnation.
	 */

	result = vrps_foreach_delta_since(request->pdu.obj.sq.serial_number,
	    &final_serial, send_delta_vrp, send_delta_rk, &args);
	switch (result) {
	case VFDSR_OK:
		/*
		 * https://tools.ietf.org/html/rfc6810#section-6.2
		 *
		 * These functions presently only fail on writes, allocations
		 * and programming errors. Best avoid error PDUs.
		 */
		if (!args.cache_response_sent) {
			error = send_cache_response_pdu(args.fd, args.rtr_version);
			if (error)
				return error;
		}
		return send_end_of_data_pdu(args.fd, args.rtr_version, final_serial);

	case VFDSR_UNDER_CONSTRUCTION:
		return err_pdu_send_no_data_available(args.fd, args.rtr_version);

	case VFDSR_INVALID_SERIAL:
		/* https://tools.ietf.org/html/rfc6810#section-6.3 */
		return send_cache_reset_pdu(args.fd, args.rtr_version);

	case VFDSR_CANT_LOCK:
		/*
		 * I think this should be more of a "try again" thing, but
		 * RTR does not provide a code for that.
		 */
		return err_pdu_send_internal_error(args.fd, args.rtr_version);

	case VFDSR_INTR:
		/* Callback errors must halt PDUs */
		break;
	}

	return EINVAL;
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

void
handle_reset_query_pdu(struct rtr_request *request)
{
	struct base_roa_args args;
	serial_t current_serial;

	args.started = false;
	args.fd = request->fd;
	args.version = request->pdu.rtr_version;

	switch (get_last_serial_number(&current_serial)) {
	case GLSNR_OK:
		break;
	case GLSNR_UNDER_CONSTRUCTION:
		err_pdu_send_no_data_available(args.fd, args.version);
		return;
	case GLSNR_CANT_LOCK:
		err_pdu_send_internal_error(args.fd, args.version);
		return;
	}

	/*
	 * It's probably best not to work on a copy, because the tree is large.
	 * Unfortunately, this means we'll have to encourage writer stagnation,
	 * but thankfully, most clients are supposed to request far more serial
	 * queries than reset queries.
	 */

	/* See handle_serial_query_pdu() for some comments. */
	switch (vrps_foreach_base(send_base_roa, send_base_router_key, &args)) {
	case VFBR_OK:
		/* Ensure the cache response is (or was) sent */
		if (!args.started)
			if (send_cache_response_pdu(args.fd, args.version) != 0)
				return;
		send_end_of_data_pdu(args.fd, args.version, current_serial);
		break;

	case VFBR_UNDER_CONSTRUCTION:
		err_pdu_send_no_data_available(args.fd, args.version);
		break;

	case VFBR_CANT_LOCK:
		err_pdu_send_internal_error(args.fd, args.version);
		break;

	case VFBR_CB_INTR:
		/* Callback errors must halt PDUs */
		break;
	}
}
