#include "pdu_sender.h"

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h> /* inet_ntop */
#include <sys/types.h> /* AF_INET, AF_INET6 (needed in OpenBSD) */
#include <sys/socket.h> /* AF_INET, AF_INET6 (needed in OpenBSD) */

#include "clients.h"
#include "config.h"
#include "log.h"
#include "rtr/pdu_serializer.h"
#include "rtr/db/vrps.h"

/*
 * Set all the header values, EXCEPT length field.
 */
static void
set_header_values(struct pdu_header *header, uint8_t version, uint8_t type,
    uint16_t reserved)
{
	header->protocol_version = version;
	header->pdu_type = type;
	header->m.reserved = reserved;
}

static int
send_response(int fd, uint8_t pdu_type, unsigned char *data, size_t data_len)
{
	int error;

	pr_debug("Sending %s PDU to client.", pdutype2str(pdu_type));

	error = write(fd, data, data_len);
	if (error < 0)
		return pr_errno(errno, "Error sending response");

	return 0;
}

int
send_serial_notify_pdu(int fd, uint8_t version, serial_t start_serial)
{
	struct serial_notify_pdu pdu;
	unsigned char data[RTRPDU_SERIAL_NOTIFY_LEN];
	size_t len;

	set_header_values(&pdu.header, version, PDU_TYPE_SERIAL_NOTIFY,
	    get_current_session_id(version));

	pdu.serial_number = start_serial;
	pdu.header.length = RTRPDU_SERIAL_NOTIFY_LEN;

	len = serialize_serial_notify_pdu(&pdu, data);
	if (len != RTRPDU_SERIAL_NOTIFY_LEN)
		pr_crit("Serialized Serial Notify is %zu bytes.", len);

	return send_response(fd, pdu.header.pdu_type, data, len);
}

int
send_cache_reset_pdu(int fd, uint8_t version)
{
	struct cache_reset_pdu pdu;
	unsigned char data[RTRPDU_CACHE_RESET_LEN];
	size_t len;

	/* This PDU has only the header */
	set_header_values(&pdu.header, version, PDU_TYPE_CACHE_RESET, 0);
	pdu.header.length = RTRPDU_CACHE_RESET_LEN;

	len = serialize_cache_reset_pdu(&pdu, data);
	if (len != RTRPDU_CACHE_RESET_LEN)
		pr_crit("Serialized Cache Reset is %zu bytes.", len);

	return send_response(fd, pdu.header.pdu_type, data, len);
}

int
send_cache_response_pdu(int fd, uint8_t version)
{
	struct cache_response_pdu pdu;
	unsigned char data[RTRPDU_CACHE_RESPONSE_LEN];
	size_t len;

	/* This PDU has only the header */
	set_header_values(&pdu.header, version, PDU_TYPE_CACHE_RESPONSE,
	    get_current_session_id(version));
	pdu.header.length = RTRPDU_CACHE_RESPONSE_LEN;

	len = serialize_cache_response_pdu(&pdu, data);
	if (len != RTRPDU_CACHE_RESPONSE_LEN)
		pr_crit("Serialized Cache Response is %zu bytes.", len);

	return send_response(fd, pdu.header.pdu_type, data, len);
}

static void
pr_debug_prefix4(struct ipv4_prefix_pdu *pdu)
{
#ifdef DEBUG
	char buffer[INET_ADDRSTRLEN];
	char const *addr_str;

	addr_str = inet_ntop(AF_INET, &pdu->ipv4_prefix, buffer,
	    INET_ADDRSTRLEN);

	pr_debug("Encoded prefix %s/%u into a PDU.", addr_str,
	    pdu->prefix_length);
#endif
}

static int
send_ipv4_prefix_pdu(int fd, uint8_t version, struct vrp const *vrp,
    uint8_t flags)
{
	struct ipv4_prefix_pdu pdu;
	unsigned char data[RTRPDU_IPV4_PREFIX_LEN];
	size_t len;

	set_header_values(&pdu.header, version, PDU_TYPE_IPV4_PREFIX, 0);
	pdu.header.length = RTRPDU_IPV4_PREFIX_LEN;

	pdu.flags = flags;
	pdu.prefix_length = vrp->prefix_length;
	pdu.max_length = vrp->max_prefix_length;
	pdu.zero = 0;
	pdu.ipv4_prefix = vrp->prefix.v4;
	pdu.asn = vrp->asn;

	len = serialize_ipv4_prefix_pdu(&pdu, data);
	if (len != RTRPDU_IPV4_PREFIX_LEN)
		pr_crit("Serialized IPv4 Prefix is %zu bytes.", len);
	pr_debug_prefix4(&pdu);

	return send_response(fd, pdu.header.pdu_type, data, len);
}

static void
pr_debug_prefix6(struct ipv6_prefix_pdu *pdu)
{
#ifdef DEBUG
	char buffer[INET6_ADDRSTRLEN];
	char const *addr_str;

	addr_str = inet_ntop(AF_INET6, &pdu->ipv6_prefix, buffer,
	    INET6_ADDRSTRLEN);

	pr_debug("Encoded prefix %s/%u into a PDU.", addr_str,
	    pdu->prefix_length);
#endif
}

static int
send_ipv6_prefix_pdu(int fd, uint8_t version, struct vrp const *vrp,
    uint8_t flags)
{
	struct ipv6_prefix_pdu pdu;
	unsigned char data[RTRPDU_IPV6_PREFIX_LEN];
	size_t len;

	set_header_values(&pdu.header, version, PDU_TYPE_IPV6_PREFIX, 0);
	pdu.header.length = RTRPDU_IPV6_PREFIX_LEN;

	pdu.flags = flags;
	pdu.prefix_length = vrp->prefix_length;
	pdu.max_length = vrp->max_prefix_length;
	pdu.zero = 0;
	pdu.ipv6_prefix = vrp->prefix.v6;
	pdu.asn = vrp->asn;

	len = serialize_ipv6_prefix_pdu(&pdu, data);
	if (len != RTRPDU_IPV6_PREFIX_LEN)
		pr_crit("Serialized IPv6 Prefix is %zu bytes.", len);
	pr_debug_prefix6(&pdu);

	return send_response(fd, pdu.header.pdu_type, data, len);
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
	struct router_key_pdu pdu;
	unsigned char data[RTRPDU_ROUTER_KEY_LEN];
	size_t len;
	uint16_t reserved;

	/* Sanity check: this can't be sent on RTRv0 */
	if (version == RTR_V0)
		return 0;

	reserved = 0;
	/* Set the flags at the first 8 bits of reserved field */
	reserved += (flags << 8);
	set_header_values(&pdu.header, version, PDU_TYPE_ROUTER_KEY, reserved);
	pdu.header.length = RTRPDU_ROUTER_KEY_LEN;

	memcpy(pdu.ski, router_key->ski, RK_SKI_LEN);
	pdu.ski_len = RK_SKI_LEN;
	pdu.asn = router_key->as;
	memcpy(pdu.spki, router_key->spk, RK_SPKI_LEN);
	pdu.spki_len = RK_SPKI_LEN;

	len = serialize_router_key_pdu(&pdu, data);
	if (len != RTRPDU_ROUTER_KEY_LEN)
		pr_crit("Serialized Router Key PDU is %zu bytes, not the expected %u.",
		    len, pdu.header.length);

	return send_response(fd, pdu.header.pdu_type, data, len);
}

struct simple_param {
	int	fd;
	uint8_t	version;
};

static int
vrp_simply_send(struct delta_vrp const *delta, void *arg)
{
	struct simple_param *param = arg;

	return send_prefix_pdu(param->fd, param->version, &delta->vrp,
	    delta->flags);
}

static int
router_key_simply_send(struct delta_router_key const *delta, void *arg)
{
	struct simple_param *param = arg;

	return send_router_key_pdu(param->fd, param->version,
	    &delta->router_key, delta->flags);
}

int
send_delta_pdus(int fd, uint8_t version, struct deltas_db *deltas)
{
	struct delta_group *group;
	struct simple_param param;

	param.fd = fd;
	param.version = version;

	/*
	 * Short circuit: Entries that share serial are already guaranteed to
	 * not contradict each other, so no filtering required.
	 */
	if (deltas->len == 1) {
		group = &deltas->array[0];
		return deltas_foreach(group->serial, group->deltas,
		    vrp_simply_send, router_key_simply_send, &param);
	}

	return vrps_foreach_filtered_delta(deltas, vrp_simply_send,
	    router_key_simply_send, &param);
}

#define GET_END_OF_DATA_LENGTH(version)					\
	((version == RTR_V1) ?						\
	    RTRPDU_END_OF_DATA_V1_LEN : RTRPDU_END_OF_DATA_V0_LEN)

int
send_end_of_data_pdu(int fd, uint8_t version, serial_t end_serial)
{
	struct end_of_data_pdu pdu;
	unsigned char data[GET_END_OF_DATA_LENGTH(version)];
	size_t len;
	int error;

	set_header_values(&pdu.header, version, PDU_TYPE_END_OF_DATA,
	    get_current_session_id(version));
	pdu.header.length = GET_END_OF_DATA_LENGTH(version);

	pdu.serial_number = end_serial;
	if (version == RTR_V1) {
		pdu.refresh_interval = config_get_interval_refresh();
		pdu.retry_interval = config_get_interval_retry();
		pdu.expire_interval = config_get_interval_expire();
	}

	len = serialize_end_of_data_pdu(&pdu, data);
	if (len != GET_END_OF_DATA_LENGTH(version))
		pr_crit("Serialized End of Data is %zu bytes.", len);

	error = send_response(fd, pdu.header.pdu_type, data, len);
	if (error)
		return error;

	clients_update_serial(fd, pdu.serial_number);
	return 0;
}

int
send_error_report_pdu(int fd, uint8_t version, uint16_t code,
    struct rtr_request const *request, char *message)
{
	struct error_report_pdu pdu;
	unsigned char *data;
	size_t len;
	int error;

	set_header_values(&pdu.header, version, PDU_TYPE_ERROR_REPORT, code);

	if (request != NULL) {
		pdu.error_pdu_length = (request->bytes_len > RTRPDU_MAX_LEN)
		    ? RTRPDU_MAX_LEN
		    : request->bytes_len;
		memcpy(pdu.erroneous_pdu, request->bytes, pdu.error_pdu_length);
	} else {
		pdu.error_pdu_length = 0;
	}

	pdu.error_message_length = (message != NULL) ? strlen(message) : 0;
	pdu.error_message = message;

	pdu.header.length = RTRPDU_HDR_LEN
	    + 4 /* Length of Encapsulated PDU field */
	    + pdu.error_pdu_length
	    + 4 /* Length of Error Text field */
	    + pdu.error_message_length;

	data = malloc(pdu.header.length);
	if (data == NULL)
		return pr_enomem();

	len = serialize_error_report_pdu(&pdu, data);
	if (len != pdu.header.length)
		pr_crit("Serialized Error Report PDU is %zu bytes, not the expected %u.",
		    len, pdu.header.length);

	error = send_response(fd, pdu.header.pdu_type, data, len);

	free(data);
	return error;
}
