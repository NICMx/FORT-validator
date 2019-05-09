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

/* Header length field is always 64 bits long */
#define HEADER_LENGTH		8
/* IPvN PDUs length without header */
#define IPV4_PREFIX_LENGTH	12
#define IPV6_PREFIX_LENGTH	24


struct vrp_node {
	struct delta delta;
	SLIST_ENTRY(vrp_node) next;
};

/** Sorted list to filter deltas */
SLIST_HEAD(vrp_slist, vrp_node);

void
init_sender_common(struct sender_common *common, int fd, uint8_t version)
{
	common->fd = fd;
	common->version = version;
	common->session_id = get_current_session_id(version);
}
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

static uint32_t
length_serial_notify_pdu(struct serial_notify_pdu *pdu)
{
	return HEADER_LENGTH + sizeof(pdu->serial_number);
}

static uint32_t
length_ipvx_prefix_pdu(bool isv4)
{
	return HEADER_LENGTH +
	    (isv4 ? IPV4_PREFIX_LENGTH : IPV6_PREFIX_LENGTH);
}

static uint32_t
length_end_of_data_pdu(struct end_of_data_pdu *pdu)
{
	uint32_t len;

	len = HEADER_LENGTH;
	len += sizeof(pdu->serial_number);
	if (pdu->header.protocol_version == RTR_V1) {
		len += sizeof(pdu->refresh_interval);
		len += sizeof(pdu->retry_interval);
		len += sizeof(pdu->expire_interval);
	}

	return len;
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

static uint32_t
length_error_report_pdu(struct error_report_pdu *pdu)
{
	return HEADER_LENGTH +
	    pdu->error_pdu_length + sizeof(pdu->error_pdu_length) +
	    pdu->error_message_length + sizeof(pdu->error_message_length);
}

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
send_serial_notify_pdu(struct sender_common *common, serial_t start_serial)
{
	struct serial_notify_pdu pdu;
	unsigned char data[BUFFER_SIZE];
	size_t len;

	set_header_values(&pdu.header, common->version, PDU_TYPE_SERIAL_NOTIFY,
	    common->session_id);

	pdu.serial_number = start_serial;
	pdu.header.length = length_serial_notify_pdu(&pdu);

	len = serialize_serial_notify_pdu(&pdu, data);

	return send_response(common->fd, data, len);
}

int
send_cache_reset_pdu(struct sender_common *common)
{
	struct cache_reset_pdu pdu;
	unsigned char data[BUFFER_SIZE];
	size_t len;

	/* This PDU has only the header */
	set_header_values(&pdu.header, common->version, PDU_TYPE_CACHE_RESET,
	    0);
	pdu.header.length = HEADER_LENGTH;

	len = serialize_cache_reset_pdu(&pdu, data);
	return send_response(common->fd, data, len);
}

int
send_cache_response_pdu(struct sender_common *common)
{
	struct cache_response_pdu pdu;
	unsigned char data[BUFFER_SIZE];
	size_t len;

	/* This PDU has only the header */
	set_header_values(&pdu.header, common->version, PDU_TYPE_CACHE_RESPONSE,
	    common->session_id);
	pdu.header.length = HEADER_LENGTH;

	len = serialize_cache_response_pdu(&pdu, data);

	return send_response(common->fd, data, len);
}

static int
send_ipv4_prefix_pdu(struct sender_common *common, struct vrp const *vrp,
    uint8_t flags)
{
	struct ipv4_prefix_pdu pdu;
	unsigned char data[BUFFER_SIZE];
	size_t len;

	set_header_values(&pdu.header, common->version, PDU_TYPE_IPV4_PREFIX,
	    0);

	pdu.flags = flags;
	pdu.prefix_length = vrp->prefix_length;
	pdu.max_length = vrp->max_prefix_length;
	pdu.zero = 0;
	pdu.ipv4_prefix = vrp->prefix.v4;
	pdu.asn = vrp->asn;
	pdu.header.length = length_ipvx_prefix_pdu(true);

	len = serialize_ipv4_prefix_pdu(&pdu, data);

	return send_response(common->fd, data, len);
}

static int
send_ipv6_prefix_pdu(struct sender_common *common, struct vrp const *vrp,
    uint8_t flags)
{
	struct ipv6_prefix_pdu pdu;
	unsigned char data[BUFFER_SIZE];
	size_t len;

	set_header_values(&pdu.header, common->version, PDU_TYPE_IPV6_PREFIX,
	    0);

	pdu.flags = flags;
	pdu.prefix_length = vrp->prefix_length;
	pdu.max_length = vrp->max_prefix_length;
	pdu.zero = 0;
	pdu.ipv6_prefix = vrp->prefix.v6;
	pdu.asn = vrp->asn;
	pdu.header.length = length_ipvx_prefix_pdu(false);

	len = serialize_ipv6_prefix_pdu(&pdu, data);

	return send_response(common->fd, data, len);
}

int
send_prefix_pdu(struct sender_common *common, struct vrp const *vrp,
    uint8_t flags)
{
	switch (vrp->addr_fam) {
	case AF_INET:
		return send_ipv4_prefix_pdu(common, vrp, flags);
	case AF_INET6:
		return send_ipv6_prefix_pdu(common, vrp, flags);
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
	return send_prefix_pdu(arg, &delta->vrp, delta->flags);
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
send_pdus_delta(struct deltas_db *deltas, struct sender_common *common)
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
		    vrp_simply_send, common);
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
		error = send_prefix_pdu(common, &ptr->delta.vrp,
		    ptr->delta.flags);
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
send_end_of_data_pdu(struct sender_common *common, serial_t end_serial)
{
	struct end_of_data_pdu pdu;
	unsigned char data[BUFFER_SIZE];
	size_t len;
	int error;

	set_header_values(&pdu.header, common->version, PDU_TYPE_END_OF_DATA,
	    common->session_id);
	pdu.serial_number = end_serial;
	if (common->version == RTR_V1) {
		pdu.refresh_interval = config_get_refresh_interval();
		pdu.retry_interval = config_get_retry_interval();
		pdu.expire_interval = config_get_expire_interval();
	}
	pdu.header.length = length_end_of_data_pdu(&pdu);

	len = serialize_end_of_data_pdu(&pdu, data);

	error = send_response(common->fd, data, len);
	if (error)
		return error;

	clients_update_serial(common->fd, pdu.serial_number);
	return error;
}

int
send_error_report_pdu(int fd, uint8_t version, uint16_t code,
struct pdu_header *err_pdu_header, char const *message)
{
	struct error_report_pdu pdu;
	unsigned char data[BUFFER_SIZE];
	size_t len;

	set_header_values(&pdu.header, version, PDU_TYPE_ERROR_REPORT, code);

	pdu.error_pdu_length = 0;
	pdu.erroneous_pdu = (void *)err_pdu_header;
	if (err_pdu_header != NULL)
		pdu.error_pdu_length = sizeof(err_pdu_header);

	pdu.error_message_length = 0;
	pdu.error_message = NULL;
	if (message != NULL) {
		pdu.error_message = malloc(strlen(message) + 1);
		if (pdu.error_message == NULL)
			pr_warn("Error message couldn't be allocated, removed from PDU");
		else {
			pdu.error_message_length = strlen(message) + 1;
			strcpy(pdu.error_message, message);
		}
	}

	/* Calculate lengths */
	pdu.header.length = length_error_report_pdu(&pdu);

	len = serialize_error_report_pdu(&pdu, data);
	free(pdu.error_message);
	return send_response(fd, data, len);
}
