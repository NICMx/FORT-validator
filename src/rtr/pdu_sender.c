#include "rtr/pdu_sender.h"

#include <errno.h>
#include <poll.h>
#include <syslog.h>

#include "alloc.h"
#include "common.h"
#include "config.h"
#include "log.h"
#include "rtr/db/vrps.h"
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
send_response(int fd, uint8_t pdu_type, unsigned char *data, size_t data_len)
{
	struct pollfd pfd;
	int error;

	pr_op_debug("Sending %s to client.", pdutype2str(pdu_type));

	pfd.fd = fd;
	pfd.events = POLLOUT;

	do {
		pfd.revents = 0;
		error = poll(&pfd, 1, -1);
		if (error < 0)
			return pr_op_err_st("poll() error: %d", error);
		if (error == 0)
			return pr_op_err_st("poll() returned 0, even though there's no timeout.");
		if (pfd.revents & (POLLHUP | POLLERR | POLLNVAL))
			return pr_op_err_st("poll() returned revents %u.", pfd.revents);
	} while (!(pfd.revents & POLLOUT));

	if (write(fd, data, data_len) < 0) {
		error = errno;
		pr_op_err_st("Error sending %s to client: %s",
		    pdutype2str(pdu_type), strerror(error));
		return error;
	}

	return 0;
}

int
send_serial_notify_pdu(int fd, uint8_t version, serial_t start_serial)
{
	static const uint8_t type = PDU_TYPE_SERIAL_NOTIFY;
	static const uint32_t len = RTRPDU_SERIAL_NOTIFY_LEN;
	unsigned char data[RTRPDU_SERIAL_NOTIFY_LEN];
	unsigned char *buf;

	buf = serialize_hdr(data, version, type,
	    get_current_session_id(version), len);
	buf = write_uint32(buf, start_serial);

	return send_response(fd, type, data, len);
}

int
send_cache_reset_pdu(int fd, uint8_t version)
{
	static const uint8_t type = PDU_TYPE_CACHE_RESET;
	static const uint32_t len = RTRPDU_CACHE_RESET_LEN;
	unsigned char data[RTRPDU_CACHE_RESET_LEN];

	serialize_hdr(data, version, type, 0, len);

	return send_response(fd, type, data, len);
}

int
send_cache_response_pdu(int fd, uint8_t version)
{
	static const uint8_t type = PDU_TYPE_CACHE_RESPONSE;
	static const uint32_t len = RTRPDU_CACHE_RESPONSE_LEN;
	unsigned char data[RTRPDU_CACHE_RESPONSE_LEN];

	serialize_hdr(data, version, type, get_current_session_id(version), len);

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

	if (version == RTR_V0)
		return 0;

	buf = serialize_hdr(data, version, type, flags << 8, len);
	memcpy(buf, router_key->ski, sizeof(router_key->ski));
	buf += sizeof(router_key->ski);
	buf = write_uint32(buf, router_key->as);
	memcpy(buf, router_key->spk, sizeof(router_key->spk));
	buf += sizeof(router_key->spk);

	return send_response(fd, type, data, len);
}

#define MAX(a, b) ((a > b) ? a : b)

int
send_end_of_data_pdu(int fd, uint8_t version, serial_t end_serial)
{
	static const uint8_t type = PDU_TYPE_ROUTER_KEY;
	unsigned char data[
	    MAX(RTRPDU_END_OF_DATA_V1_LEN, RTRPDU_END_OF_DATA_V0_LEN)
	];
	unsigned char *buf;
	uint32_t len;

	len = (version == RTR_V1)
	    ? RTRPDU_END_OF_DATA_V1_LEN
	    : RTRPDU_END_OF_DATA_V0_LEN;
	buf = serialize_hdr(data, version, type,
	    get_current_session_id(version), len);

	buf = write_uint32(buf, end_serial);
	if (version == RTR_V1) {
		buf = write_uint32(buf, config_get_interval_refresh());
		buf = write_uint32(buf, config_get_interval_retry());
		buf = write_uint32(buf, config_get_interval_expire());
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

	error_pdu_len = compute_error_pdu_len(request);
	error_msg_len = (message != NULL) ? strlen(message) : 0;
	len = rtrpdu_error_report_len(error_pdu_len, error_msg_len);
	data = pmalloc(len);

	buf = serialize_hdr(data, version, type, 0, len);
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
