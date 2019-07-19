#include "pdu_sender.h"

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "clients.h"
#include "config.h"
#include "log.h"
#include "rtr/pdu_serializer.h"
#include "rtr/db/vrps.h"

/*
 * Set all the header values, EXCEPT length field.
 */
static void
set_header_values(struct pdu_header *header, uint8_t type, uint16_t reserved)
{
	/* FIXME Remove to support RTR_V1 */
	header->protocol_version = RTR_V0;
	header->pdu_type = type;
	header->m.reserved = reserved;
}

static int
send_response(int fd, unsigned char *data, size_t data_len)
{
	int error;

	error = write(fd, data, data_len);
	if (error < 0)
		return pr_errno(errno, "Error sending response");

	return 0;
}

int
send_serial_notify_pdu(int fd, serial_t start_serial)
{
	struct serial_notify_pdu pdu;
	unsigned char data[RTRPDU_SERIAL_NOTIFY_LEN];
	size_t len;

	set_header_values(&pdu.header, PDU_TYPE_SERIAL_NOTIFY,
	    get_current_session_id(RTR_V0));

	pdu.serial_number = start_serial;
	pdu.header.length = RTRPDU_SERIAL_NOTIFY_LEN;

	len = serialize_serial_notify_pdu(&pdu, data);
	if (len != RTRPDU_SERIAL_NOTIFY_LEN)
		pr_crit("Serialized Serial Notify is %zu bytes.", len);

	return send_response(fd, data, len);
}

int
send_cache_reset_pdu(int fd)
{
	struct cache_reset_pdu pdu;
	unsigned char data[RTRPDU_CACHE_RESET_LEN];
	size_t len;

	/* This PDU has only the header */
	set_header_values(&pdu.header, PDU_TYPE_CACHE_RESET, 0);
	pdu.header.length = RTRPDU_CACHE_RESET_LEN;

	len = serialize_cache_reset_pdu(&pdu, data);
	if (len != RTRPDU_CACHE_RESET_LEN)
		pr_crit("Serialized Cache Reset is %zu bytes.", len);

	return send_response(fd, data, len);
}

int
send_cache_response_pdu(int fd)
{
	struct cache_response_pdu pdu;
	unsigned char data[RTRPDU_CACHE_RESPONSE_LEN];
	size_t len;

	/* This PDU has only the header */
	set_header_values(&pdu.header, PDU_TYPE_CACHE_RESPONSE,
	    get_current_session_id(RTR_V0));
	pdu.header.length = RTRPDU_CACHE_RESPONSE_LEN;

	len = serialize_cache_response_pdu(&pdu, data);
	if (len != RTRPDU_CACHE_RESPONSE_LEN)
		pr_crit("Serialized Cache Response is %zu bytes.", len);

	return send_response(fd, data, len);
}

static int
send_ipv4_prefix_pdu(int fd, struct vrp const *vrp, uint8_t flags)
{
	struct ipv4_prefix_pdu pdu;
	unsigned char data[RTRPDU_IPV4_PREFIX_LEN];
	size_t len;

	set_header_values(&pdu.header, PDU_TYPE_IPV4_PREFIX, 0);
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

	return send_response(fd, data, len);
}

static int
send_ipv6_prefix_pdu(int fd, struct vrp const *vrp, uint8_t flags)
{
	struct ipv6_prefix_pdu pdu;
	unsigned char data[RTRPDU_IPV6_PREFIX_LEN];
	size_t len;

	set_header_values(&pdu.header, PDU_TYPE_IPV6_PREFIX, 0);
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

	return send_response(fd, data, len);
}

int
send_prefix_pdu(int fd, struct vrp const *vrp, uint8_t flags)
{
	switch (vrp->addr_fam) {
	case AF_INET:
		return send_ipv4_prefix_pdu(fd, vrp, flags);
	case AF_INET6:
		return send_ipv6_prefix_pdu(fd, vrp, flags);
	}

	return -EINVAL;
}

int
send_router_key_pdu(int fd, struct router_key const *router_key, uint8_t flags)
{
	struct router_key_pdu pdu;
	unsigned char *data;
	size_t len;
	uint16_t reserved;
	int error;

	/* TODO Sanity check: this can't be sent on RTRv0 */

	reserved = 0;
	/* Set the flags at the first 8 bits of reserved field */
	reserved += (flags << 8);
	set_header_values(&pdu.header, PDU_TYPE_ROUTER_KEY, reserved);

	pdu.ski = sk_info_get_ski(router_key->sk);
	pdu.ski_len = RK_SKI_LEN;
	pdu.asn = router_key->as;
	pdu.spki = sk_info_get_spk(router_key->sk);
	pdu.spki_len = sk_info_get_spk_len(router_key->sk);
	pdu.header.length = RTRPDU_HDR_LEN
	    + RK_SKI_LEN
	    + sizeof(router_key->as)
	    + pdu.spki_len;
	sk_info_refget(router_key->sk);

	data = malloc(pdu.header.length);
	if (data == NULL) {
		error = pr_enomem();
		goto release_sk;
	}

	len = serialize_router_key_pdu(&pdu, data);
	if (len != pdu.header.length) {
		sk_info_refput(router_key->sk);
		free(data);
		pr_crit("Serialized Router Key PDU is %zu bytes, not the expected %u.",
		    len, pdu.header.length);
	}

	error = send_response(fd, data, len);
	free(data);

release_sk:
	sk_info_refput(router_key->sk);
	return error;
}

static int
vrp_simply_send(struct delta_vrp const *delta, void *arg)
{
	int *fd = arg;

	return send_prefix_pdu(*fd, &delta->vrp, delta->flags);
}

static int
router_key_simply_send(struct delta_bgpsec const *delta, void *arg)
{
	int *fd = arg;

	return send_router_key_pdu(*fd, &delta->router_key,
	    delta->flags);
}

int
send_delta_pdus(int fd, struct deltas_db *deltas)
{
	struct delta_group *group;

	/*
	 * Short circuit: Entries that share serial are already guaranteed to
	 * not contradict each other, so no filtering required.
	 */
	if (deltas->len == 1) {
		group = &deltas->array[0];
		return deltas_foreach(group->serial, group->deltas,
		    vrp_simply_send, router_key_simply_send, &fd);
	}

	/* FIXME Apply to router keys as well */
	return vrps_foreach_filtered_delta(deltas, vrp_simply_send, &fd);
}

int
send_end_of_data_pdu(int fd, serial_t end_serial)
{
	struct end_of_data_pdu pdu;
	unsigned char data[RTRPDU_END_OF_DATA_LEN];
	size_t len;
	int error;

	set_header_values(&pdu.header, PDU_TYPE_END_OF_DATA,
	    get_current_session_id(RTR_V0));
	pdu.header.length = RTRPDU_END_OF_DATA_LEN;

	pdu.serial_number = end_serial;
	/* FIXME WRONG!! Check for the real version */
	if (pdu.header.protocol_version == RTR_V1) {
		pdu.refresh_interval = config_get_interval_refresh();
		pdu.retry_interval = config_get_interval_retry();
		pdu.expire_interval = config_get_interval_expire();
	}

	len = serialize_end_of_data_pdu(&pdu, data);
	if (len != RTRPDU_END_OF_DATA_LEN)
		pr_crit("Serialized End of Data is %zu bytes.", len);

	error = send_response(fd, data, len);
	if (error)
		return error;

	clients_update_serial(fd, pdu.serial_number);
	return 0;
}

int
send_error_report_pdu(int fd, uint16_t code, struct rtr_request const *request,
    char *message)
{
	struct error_report_pdu pdu;
	unsigned char *data;
	size_t len;
	int error;

	set_header_values(&pdu.header, PDU_TYPE_ERROR_REPORT, code);

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

	error = send_response(fd, data, len);

	free(data);
	return error;
}
