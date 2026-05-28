#include "rtr/pdu_sender.h"

#include <errno.h>
#include <poll.h>
#include <string.h>
#include <unistd.h>

#include "alloc.h"
#include "config.h"
#include "data_structure/common.h"
#include "log.h"
#include "rtr/primitive_writer.h"

static unsigned char *
serialize_hdr(unsigned char *buf, uint8_t version, uint8_t type,
    uint16_t m, uint32_t length)
{
	buf = write_uint8(buf, version);
	buf = write_uint8(buf, type);
	buf = write_uint16(buf, m);
	buf = write_uint32(buf, length);
	return buf;
}

static int
print_poll_failure(struct pollfd *pfd)
{
	/*
	 * The main polling thread already logs relevant revents in sensible
	 * levels (see apply_pollfds()), so we'll just whine on debug.
	 */

	pr_op_debug("poll() returned revents '0x%02x'. This means", pfd->revents);
	if (pfd->revents & POLLHUP) {
		pr_op_debug("- 0x%02x: Peer hung up.", POLLHUP);
	}
	if (pfd->revents & POLLERR) {
		pr_op_debug("- 0x%02x: Read end was closed, or generic error.",
		    POLLERR);
	}
	if (pfd->revents & POLLNVAL) {
		/*
		 * In our case, this is perfectly normal. The main polling
		 * thread closed it while we were trying to write. Whatever.
		 */
		pr_op_debug("- 0x%02x: File Descriptor not open.", POLLNVAL);
	}

	/* Interrupt handler thread, but no need to raise alarms. */
	return -EINVAL;
}

static int
send_response(int fd, uint8_t pdu_type, unsigned char *data, size_t data_len)
{
	struct pollfd pfd;
	int error;

	pfd.fd = fd;
	pfd.events = POLLOUT;

	/*
	 * We need to poll before writing because the socket has O_NONBLOCK set.
	 * (And it needs O_NONBLOCK because of the main thread's read poll.)
	 */
	do {
		pfd.revents = 0;
		error = poll(&pfd, 1, -1);
		if (error < 0)
			return pr_op_err_st("poll() error: %d", error);
		if (error == 0)
			return pr_op_err_st("poll() returned 0, even though there's no timeout.");
		if (pfd.revents & (POLLHUP | POLLERR | POLLNVAL))
			return print_poll_failure(&pfd);
	} while (!(pfd.revents & POLLOUT));

	if (write(fd, data, data_len) < 0) {
		error = errno;
		pr_op_debug("Error sending %s to client: %s",
		    pdutype2str(pdu_type), strerror(error));
		return error;
	}

	return 0;
}

int
send_serial_notify_pdu(int fd, uint8_t version, struct rtr_metadata *meta)
{
	static const uint8_t type = PDU_TYPE_SERIAL_NOTIFY;
	static const uint32_t len = RTRPDU_SERIAL_NOTIFY_LEN;
	unsigned char data[RTRPDU_SERIAL_NOTIFY_LEN];
	unsigned char *buf;

	pr_op_debug("Sending Serial Notify PDU.");

	buf = serialize_hdr(data, version, type, meta->session, len);
	buf = write_uint32(buf, meta->serial);

	return send_response(fd, type, data, len);
}

int
send_cache_reset_pdu(int fd, uint8_t version)
{
	static const uint8_t type = PDU_TYPE_CACHE_RESET;
	static const uint32_t len = RTRPDU_CACHE_RESET_LEN;
	unsigned char data[RTRPDU_CACHE_RESET_LEN];

	pr_op_debug("Sending Cache Reset PDU.");
	serialize_hdr(data, version, type, 0, len);
	return send_response(fd, type, data, len);
}

int
send_cache_response_pdu(int fd, uint8_t version, uint16_t session)
{
	static const uint8_t type = PDU_TYPE_CACHE_RESPONSE;
	static const uint32_t len = RTRPDU_CACHE_RESPONSE_LEN;
	unsigned char data[RTRPDU_CACHE_RESPONSE_LEN];

	pr_op_debug("Sending Cache Response PDU.");
	serialize_hdr(data, version, type, session, len);
	return send_response(fd, type, data, len);
}

static int
send_ipv4_prefix_pdu(int fd, uint8_t version, struct vrp const *vrp,
    uint8_t flags)
{
	static const uint8_t type = PDU_TYPE_IPV4_PREFIX;
	static const uint32_t len = RTRPDU_IPV4_PREFIX_LEN;
	unsigned char data[RTRPDU_IPV4_PREFIX_LEN];
	unsigned char *buf;

	buf = serialize_hdr(data, version, type, 0, len);
	buf = write_uint8(buf, flags);
	buf = write_uint8(buf, vrp->prefix_length);
	buf = write_uint8(buf, vrp->max_prefix_length);
	buf = write_uint8(buf, 0);
	buf = write_in_addr(buf, vrp->prefix.v4);
	buf = write_uint32(buf, vrp->asn);

	return send_response(fd, type, data, len);
}

static int
send_ipv6_prefix_pdu(int fd, uint8_t version, struct vrp const *vrp,
    uint8_t flags)
{
	static const uint8_t type = PDU_TYPE_IPV6_PREFIX;
	static const uint32_t len = RTRPDU_IPV6_PREFIX_LEN;
	unsigned char data[RTRPDU_IPV6_PREFIX_LEN];
	unsigned char *buf;

	buf = serialize_hdr(data, version, PDU_TYPE_IPV6_PREFIX, 0, len);
	buf = write_uint8(buf, flags);
	buf = write_uint8(buf, vrp->prefix_length);
	buf = write_uint8(buf, vrp->max_prefix_length);
	buf = write_uint8(buf, 0);
	buf = write_in6_addr(buf, &vrp->prefix.v6);
	buf = write_uint32(buf, vrp->asn);

	return send_response(fd, type, data, len);
}

int
send_prefix_pdu(int fd, uint8_t version, struct vrp const *vrp, uint8_t flags)
{
	pr_op_debug("Sending Prefix PDU.");

	switch (vrp->addr_fam) {
	case AF_INET:
		return send_ipv4_prefix_pdu(fd, version, vrp, flags);
	case AF_INET6:
		return send_ipv6_prefix_pdu(fd, version, vrp, flags);
	}

	return -EINVAL;
}

int
send_router_key_pdu(int fd, uint8_t version,
    struct router_key const *router_key, uint8_t flags)
{
	static const uint8_t type = PDU_TYPE_ROUTER_KEY;
	static const uint32_t len = RTRPDU_ROUTER_KEY_LEN;
	unsigned char data[RTRPDU_ROUTER_KEY_LEN];
	unsigned char *buf;

	if (version < RTR_V1)
		return 0;

	pr_op_debug("Sending RK PDU.");

	buf = serialize_hdr(data, version, type, flags << 8, len);
	memcpy(buf, router_key->ski, sizeof(router_key->ski));
	buf += sizeof(router_key->ski);
	buf = write_uint32(buf, router_key->as);
	memcpy(buf, router_key->spk, sizeof(router_key->spk));
	buf += sizeof(router_key->spk);

	return send_response(fd, type, data, len);
}

int
send_aspa_announce_pdu(int fd, uint8_t version, struct aspa const *aspa)
{
	static const uint8_t type = PDU_TYPE_ASPA;
	unsigned char *buf, *loc;
	size_t bufsize;
	array_index i;
	int error = 0;

	if (version < RTR_V2)
		return 0;

	pr_op_debug("Sending ASPA announcement PDU.");

	bufsize = 12 + 4 * aspa->providers.count;
	if (bufsize > 1024)
		bufsize = 1024;
	buf = pmalloc(bufsize);

	loc = serialize_hdr(buf, version, type, FLAG_ANNOUNCEMENT << 8,
	    12 + 4 * aspa->providers.count);
	loc = write_uint32(loc, aspa->customer);

	for (i = 0; i < aspa->providers.count; i++) {
		loc = write_uint32(loc, aspa->providers.asids[i]);

		if (loc >= buf + bufsize) {
			error = send_response(fd, type, buf, loc - buf);
			if (error)
				goto end;
			loc = buf;
		}
	}

	if (loc > buf) {
		error = send_response(fd, type, buf, loc - buf);
		if (error)
			goto end;
	}

end:	free(buf);
	return error;
}

int
send_aspa_withdraw_pdu(int fd, uint8_t version, uint32_t customer)
{
	static const uint8_t type = PDU_TYPE_ASPA;
	unsigned char data[12];
	unsigned char *buf;

	pr_op_debug("Sending ASPA withdraw PDU.");

	buf = serialize_hdr(data, version, type, FLAG_WITHDRAWAL << 8, 12);
	write_uint32(buf, customer);

	return send_response(fd, type, data, 12);
}

#define MAX(a, b) ((a > b) ? a : b)

int
send_end_of_data_pdu(int fd, uint8_t version, uint16_t session, serial_t serial)
{
	static const uint8_t type = PDU_TYPE_END_OF_DATA;
	unsigned char data[
	    MAX(RTRPDU_END_OF_DATA_V1_LEN, RTRPDU_END_OF_DATA_V0_LEN)
	];
	unsigned char *buf;
	uint32_t len;

	pr_op_debug("Sending End of Data PDU.");

	switch (version) {
	case RTR_V0:
		len = RTRPDU_END_OF_DATA_V0_LEN;
		buf = serialize_hdr(data, version, type, session, len);
		buf = write_uint32(buf, serial);
		break;
	case RTR_V1:
	case RTR_V2:
		len = RTRPDU_END_OF_DATA_V1_LEN;
		buf = serialize_hdr(data, version, type, session, len);
		buf = write_uint32(buf, serial);
		buf = write_uint32(buf, config_get_interval_refresh());
		buf = write_uint32(buf, config_get_interval_retry());
		buf = write_uint32(buf, config_get_interval_expire());
		break;
	default:
		return pr_op_err("Unknown RTR version: %u", version);
	}

	return send_response(fd, type, data, len);
}

static size_t
compute_error_pdu_len(struct rtr_buffer const *request)
{
	unsigned int result;

	if (request == NULL || request->bytes_len < RTR_HDR_LEN)
		return 0;

	result = (((unsigned int)(request->bytes[4])) << 24)
	       | (((unsigned int)(request->bytes[5])) << 16)
	       | (((unsigned int)(request->bytes[6])) <<  8)
	       | (((unsigned int)(request->bytes[7]))      );

	result = (result <= request->bytes_len) ? result : request->bytes_len;
	return (result <= RTRPDU_MAX_LEN) ? result : RTRPDU_MAX_LEN;
}

int
send_error_report_pdu(int fd, uint8_t version, uint16_t code,
    struct rtr_buffer const *request, char *message)
{
	static const uint8_t type = PDU_TYPE_ERROR_REPORT;
	unsigned char *data, *buf;
	size_t error_pdu_len;
	size_t error_msg_len;
	size_t len;
	int error;

	pr_op_debug("Sending error PDU: %s", message);

	error_pdu_len = compute_error_pdu_len(request);
	error_msg_len = (message != NULL) ? strlen(message) : 0;
	len = rtrpdu_error_report_len(error_pdu_len, error_msg_len);
	data = pmalloc(len);

	buf = serialize_hdr(data, version, type, code, len);
	buf = write_uint32(buf, error_pdu_len);
	if (error_pdu_len > 0) {
		memcpy(buf, request->bytes, error_pdu_len);
		buf += error_pdu_len;
	}
	buf = write_uint32(buf, error_msg_len);
	if (error_msg_len > 0) {
		memcpy(buf, message, error_msg_len);
		buf += error_msg_len;
	}

	error = send_response(fd, type, data, len);
	free(data);
	return error;
}
