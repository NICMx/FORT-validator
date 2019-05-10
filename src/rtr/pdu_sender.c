#include "pdu_sender.h"

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/queue.h>

#include "clients.h"
#include "config.h"
#include "log.h"
#include "rtr/pdu_serializer.h"
#include "rtr/db/vrps.h"

/* IPvN PDUs length without header */
#define IPV4_PREFIX_LENGTH	12
#define IPV6_PREFIX_LENGTH	24


struct vrp_node {
	struct delta delta;
	SLIST_ENTRY(vrp_node) next;
};

/** Sorted list to filter deltas */
SLIST_HEAD(vrp_slist, vrp_node);

/*
 * Set all the header values, EXCEPT length field.
 */
static void
set_header_values(struct pdu_header *header, uint8_t type, uint16_t reserved)
{
	header->protocol_version = RTR_V0;
	header->pdu_type = type;
	header->m.reserved = reserved;
}

/* TODO Include Router Key PDU serials */
/**
 * static uint32_t
 * length_router_key_pdu(struct router_key_pdu *pdu)
 * {
 * 	return HEADER_LENGTH +
 * 	    pdu->ski_len + sizeof(pdu->asn) + pdu->spki_len;
 * }
 */

/*
 * TODO Needs some testing, this is just a beta version
 */
static int
send_large_response(int fd, struct data_buffer *buffer)
{
	unsigned char *tmp_buffer, *ptr;
	size_t buf_size, pending;
	int written;

	buf_size = buffer->capacity;
	pending = buffer->len;
	ptr = buffer->data;
	while (pending > 0) {
		tmp_buffer = calloc(pending, sizeof(unsigned char));
		if (tmp_buffer == NULL)
			return pr_enomem();

		memcpy(tmp_buffer, ptr, buf_size);

		written = write(fd, tmp_buffer, buf_size);
		free(tmp_buffer);
		if (written < 0)
			return pr_err("Error sending response");

		pending -= buf_size;
		ptr += buf_size;
		buf_size = pending > buffer->capacity ? buffer->capacity :
		    pending;
	}

	return 0;
}

static int
send_response(int fd, unsigned char *data, size_t data_len)
{
	struct data_buffer buffer;
	int error;

	init_buffer(&buffer);
	memcpy(buffer.data, data, data_len);
	buffer.len = data_len;

	/* Check for buffer overflow */
	if (data_len <= buffer.capacity) {
		error = write(fd, buffer.data, buffer.len);
		free_buffer(&buffer);
		if (error < 0)
			return pr_err("Error sending response");

		return 0;
	}

	error = send_large_response(fd, &buffer);
	free_buffer(&buffer);
	if (error)
		return error;

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
		return pr_crit("Serialized Serial Notify is %zu bytes.", len);

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
		return pr_crit("Serialized Cache Reset is %zu bytes.", len);

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
		return pr_crit("Serialized Cache Response is %zu bytes.", len);

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
		return pr_crit("Serialized IPv4 Prefix is %zu bytes.", len);

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
		return pr_crit("Serialized IPv6 Prefix is %zu bytes.", len);

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

static bool
vrp_equals(struct vrp const *left, struct vrp const *right)
{
	return left->asn == right->asn
	    && left->addr_fam == right->addr_fam
	    && left->prefix_length == right->prefix_length
	    && left->max_prefix_length == right->max_prefix_length
	    && ((left->addr_fam == AF_INET
	        && left->prefix.v4.s_addr == right->prefix.v4.s_addr)
	    || (left->addr_fam == AF_INET6
	    && IN6_ARE_ADDR_EQUAL(left->prefix.v6.s6_addr32,
	        right->prefix.v6.s6_addr32)));
}

static int
vrp_simply_send(struct delta const *delta, void *arg)
{
	int *fd = arg;
	return send_prefix_pdu(*fd, &delta->vrp, delta->flags);
}

/**
 * Remove the announcements/withdrawals that override each other.
 *
 * (Note: We're assuming the array is already duplicateless enough thanks to the
 * hash table.)
 */
static int
vrp_ovrd_remove(struct delta const *delta, void *arg)
{
	struct vrp_node *ptr;
	struct vrp_slist *filtered_vrps = arg;

	SLIST_FOREACH(ptr, filtered_vrps, next)
		if (vrp_equals(&delta->vrp, &ptr->delta.vrp) &&
		    delta->flags != ptr->delta.flags) {
			SLIST_REMOVE(filtered_vrps, ptr, vrp_node, next);
			free(ptr);
			return 0;
		}

	ptr = malloc(sizeof(struct vrp_node));
	if (ptr == NULL)
		return pr_enomem();

	ptr->delta = *delta;
	SLIST_INSERT_HEAD(filtered_vrps, ptr, next);
	return 0;
}

int
send_delta_pdus(int fd, struct deltas_db *deltas)
{
	struct vrp_slist filtered_vrps;
	struct delta_group *group;
	struct vrp_node *ptr;
	int error;

	/*
	 * Short circuit: Entries that share serial are already guaranteed to
	 * not contradict each other, so no filtering required.
	 */
	if (deltas->len == 1) {
		group = &deltas->array[0];
		return deltas_foreach(group->serial, group->deltas,
		    vrp_simply_send, &fd);
	}

	/*
	 * Filter: Remove entries that cancel each other.
	 * (We'll have to build a separate list because the database nodes
	 * are immutable.)
	 */
	SLIST_INIT(&filtered_vrps);
	ARRAYLIST_FOREACH(deltas, group) {
		error = deltas_foreach(group->serial, group->deltas,
		    vrp_ovrd_remove, &filtered_vrps);
		if (error)
			goto release_list;
	}

	/* Now send the filtered deltas */
	SLIST_FOREACH(ptr, &filtered_vrps, next) {
		error = send_prefix_pdu(fd, &ptr->delta.vrp, ptr->delta.flags);
		if (error)
			break;
	}

release_list:
	while (!SLIST_EMPTY(&filtered_vrps)) {
		ptr = filtered_vrps.slh_first;
		SLIST_REMOVE_HEAD(&filtered_vrps, next);
		free(ptr);
	}

	return error;
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
	if (pdu.header.protocol_version == RTR_V1) {
		pdu.refresh_interval = config_get_refresh_interval();
		pdu.retry_interval = config_get_retry_interval();
		pdu.expire_interval = config_get_expire_interval();
	}

	len = serialize_end_of_data_pdu(&pdu, data);
	if (len != RTRPDU_END_OF_DATA_LEN)
		return pr_crit("Serialized End of Data is %zu bytes.", len);

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

	pdu.header.length = RTRPDU_HEADER_LEN
	    + 4 /* Length of Encapsulated PDU field */
	    + pdu.error_pdu_length
	    + 4 /* Length of Error Text field */
	    + pdu.error_message_length;

	data = malloc(pdu.header.length);
	if (data == NULL)
		return pr_enomem();

	len = serialize_error_report_pdu(&pdu, data);
	if (len != pdu.header.length) {
		error = pr_crit("Serialized Error Report PDU is %zu bytes, not the expected %u.",
		    len, pdu.header.length);
		goto end;
	}

	error = send_response(fd, data, len);

end:
	free(data);
	return error;
}
