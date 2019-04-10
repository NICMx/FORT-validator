#include "pdu_sender.h"

#include <err.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../configuration.h"
#include "../vrps.h"
#include "pdu_serializer.h"

/* Header length field is always 64 bits long */
#define HEADER_LENGTH		8
/* IPvN PDUs length without header */
#define IPV4_PREFIX_LENGTH	12
#define IPV6_PREFIX_LENGTH	24

void
init_sender_common(struct sender_common *common, int fd, u_int8_t version,
    u_int16_t *session_id, u_int32_t *start_serial, u_int32_t *end_serial)
{
	common->fd = fd;
	common->version = version;
	common->session_id = session_id == NULL ? 0 : session_id;
	common->start_serial = start_serial;
	common->end_serial = end_serial;
}
/*
 * Set all the header values, EXCEPT length field.
 */
static void
set_header_values(struct pdu_header *header, u_int8_t version, u_int8_t type,
    u_int16_t reserved)
{
	header->protocol_version = version;
	header->pdu_type = type;
	header->reserved = reserved;
}

static u_int32_t
length_serial_notify_pdu(struct serial_notify_pdu *pdu)
{
	return HEADER_LENGTH + sizeof(pdu->serial_number);
}

static u_int32_t
length_ipvx_prefix_pdu(bool isv4)
{
	return HEADER_LENGTH +
	    (isv4 ? IPV4_PREFIX_LENGTH : IPV6_PREFIX_LENGTH);
}

static u_int32_t
length_end_of_data_pdu(struct end_of_data_pdu *pdu)
{
	u_int32_t len;

	len = HEADER_LENGTH;
	len += sizeof(pdu->serial_number);
	if (pdu->header.protocol_version == RTR_V1) {
		len += sizeof(pdu->refresh_interval);
		len += sizeof(pdu->retry_interval);
		len += sizeof(pdu->expire_interval);
	}

	return len;
}

static u_int32_t
length_router_key_pdu(struct router_key_pdu *pdu)
{
	return HEADER_LENGTH +
	    pdu->ski_len + sizeof(pdu->asn) + pdu->spki_len;
}

static u_int32_t
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
		if (tmp_buffer == NULL) {
			warnx("Couldn't allocate temp buffer");
			return -ENOMEM;
		}
		memcpy(tmp_buffer, ptr, buf_size);

		written = write(fd, tmp_buffer, buf_size);
		free(tmp_buffer);
		if (written < 0) {
			warnx("Error sending response");
			return -EINVAL;
		}
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
		if (error < 0) {
			warnx("Error sending response");
			return -EINVAL;
		}
		return 0;
	}

	error = send_large_response(fd, &buffer);
	free_buffer(&buffer);
	if (error)
		return error;

	return 0;
}

int
send_serial_notify_pdu(struct sender_common *common)
{
	struct serial_notify_pdu pdu;
	unsigned char data[BUFFER_SIZE];
	size_t len;

	set_header_values(&pdu.header, common->version, PDU_TYPE_SERIAL_NOTIFY,
	    *common->session_id);

	pdu.serial_number = *common->start_serial;
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
	set_header_values(&pdu.header, common->version,
	    PDU_TYPE_CACHE_RESPONSE, *common->session_id);
	pdu.header.length = HEADER_LENGTH;

	len = serialize_cache_response_pdu(&pdu, data);

	return send_response(common->fd, data, len);
}

static int
send_ipv4_prefix_pdu(struct sender_common *common, struct vrp *vrp)
{
	struct ipv4_prefix_pdu pdu;
	unsigned char data[BUFFER_SIZE];
	size_t len;

	set_header_values(&pdu.header, common->version, PDU_TYPE_IPV4_PREFIX,
	    0);

	pdu.flags = vrp->flags;
	pdu.prefix_length = vrp->prefix_length;
	pdu.max_length = vrp->max_prefix_length;
	pdu.zero = 0;
	pdu.ipv4_prefix = vrp->ipv4_prefix;
	pdu.asn = vrp->asn;
	pdu.header.length = length_ipvx_prefix_pdu(true);

	len = serialize_ipv4_prefix_pdu(&pdu, data);

	return send_response(common->fd, data, len);
}

static int
send_ipv6_prefix_pdu(struct sender_common *common, struct vrp *vrp)
{
	struct ipv6_prefix_pdu pdu;
	unsigned char data[BUFFER_SIZE];
	size_t len;

	set_header_values(&pdu.header, common->version, PDU_TYPE_IPV6_PREFIX,
	    0);

	pdu.flags = vrp->flags;
	pdu.prefix_length = vrp->prefix_length;
	pdu.max_length = vrp->max_prefix_length;
	pdu.zero = 0;
	pdu.ipv6_prefix = vrp->ipv6_prefix;
	pdu.asn = vrp->asn;
	pdu.header.length = length_ipvx_prefix_pdu(false);

	len = serialize_ipv6_prefix_pdu(&pdu, data);

	return send_response(common->fd, data, len);
}

static int
send_vrps_payload(struct sender_common *common)
{
	struct vrp *vrps, *ptr;
	unsigned int len;
	int error;

	vrps = malloc(sizeof(struct vrp));
	if (vrps == NULL) {
		warn("Couldn't allocate VRPs to send PDUs");
		return -ENOMEM;
	}
	len = get_vrps_delta(common->start_serial, common->end_serial, &vrps);
	if (len == 0)
		goto end;

	for (ptr = vrps; (ptr - vrps) < len; ptr++) {
		if (ptr->addr_fam == AF_INET)
			error = send_ipv4_prefix_pdu(common, ptr);
		else if (ptr->addr_fam == AF_INET6)
			error = send_ipv6_prefix_pdu(common, ptr);
		else
			error = -EINVAL;

		if (error) {
			free(vrps);
			return error;
		}
	}
end:
	free(vrps);
	return 0;
}

static int
send_router_key_pdu(struct sender_common *common,
    struct router_key *router_key)
{
	struct router_key_pdu pdu;
	unsigned char data[BUFFER_SIZE];
	size_t len;
	u_int16_t reserved;

	if (common->version == RTR_V0)
		return 0;

	reserved = 0;
	/* Set the flags at the first 8 bits of reserved field */
	reserved += (router_key->flags << 8);
	set_header_values(&pdu.header, common->version, PDU_TYPE_ROUTER_KEY,
	    reserved);

	pdu.ski = router_key->ski;
	pdu.ski_len = router_key->ski_len;
	pdu.asn = router_key->asn;
	pdu.spki = router_key->spki;
	pdu.spki_len = router_key->spki_len;
	pdu.header.length = length_router_key_pdu(&pdu);

	len = serialize_router_key_pdu(&pdu, data);

	return send_response(common->fd, data, len);
}

static int
send_keys_payload(struct sender_common *common)
{
	struct router_key *router_keys, *ptr;
	unsigned int len;
	int error;

	router_keys = malloc(sizeof(struct router_key));
	if (router_keys == NULL) {
		warn("Couldn't allocate Router Keys to send PDUs");
		return -ENOMEM;
	}
	len = get_router_keys_delta(common->start_serial, common->end_serial,
	    &router_keys);
	if (len == 0)
		goto end;

	for (ptr = router_keys; (ptr - router_keys) < len; ptr++) {
		error = send_router_key_pdu(common, ptr);
		if (error) {
			free(router_keys);
			return error;
		}
	}
end:
	free(router_keys);
	return 0;
}

int
send_payload_pdus(struct sender_common *common)
{
	int error;

	error = send_vrps_payload(common);
	if (error)
		return error;

	error = send_keys_payload(common);
	if (error)
		return error;

	return 0;
}

int
send_end_of_data_pdu(struct sender_common *common)
{
	struct end_of_data_pdu pdu;
	unsigned char data[BUFFER_SIZE];
	size_t len;

	set_header_values(&pdu.header, common->version, PDU_TYPE_END_OF_DATA,
	    *common->session_id);
	pdu.serial_number = *common->end_serial;
	if (common->version == RTR_V1) {
		pdu.refresh_interval = config_get_refresh_interval();
		pdu.retry_interval = config_get_retry_interval();
		pdu.expire_interval = config_get_expire_interval();
	}
	pdu.header.length = length_end_of_data_pdu(&pdu);

	len = serialize_end_of_data_pdu(&pdu, data);

	return send_response(common->fd, data, len);
}

int
send_error_report_pdu(int fd, u_int8_t version, u_int16_t code,
struct pdu_header *err_pdu_header, char *message)
{
	struct error_report_pdu pdu;
	unsigned char data[BUFFER_SIZE];
	size_t len;

	set_header_values(&pdu.header, version, PDU_TYPE_ERROR_REPORT,
	    code);

	pdu.error_pdu_length = 0;
	pdu.erroneous_pdu = (void *)err_pdu_header;
	if (err_pdu_header != NULL)
		pdu.error_pdu_length = sizeof(err_pdu_header);

	pdu.error_message_length = 0;
	pdu.error_message = NULL;
	if (message != NULL) {
		pdu.error_message = malloc(strlen(message) + 1);
		if (pdu.error_message == NULL)
			warn("Error message couldn't be allocated, removed from PDU");
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
