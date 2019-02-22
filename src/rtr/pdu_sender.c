#include "pdu_sender.h"

#include <err.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>

#include "../array_list.h"
#include "../configuration.h"
#include "../vrps.h"
#include "pdu.h"
#include "pdu_serializer.h"

/* Header without length field is always 32 bits long */
#define HEADER_LENGTH 4
/* IPvN PDUs length without header */
#define IPV4_PREFIX_LENGTH 12
#define IPV6_PREFIX_LENGTH 24

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
length_cache_response_pdu(struct cache_response_pdu *pdu)
{
	/* This PDU has no payload, consider 32 bits of the length field */
	return HEADER_LENGTH + sizeof(u_int32_t);
}

static u_int32_t
length_ipvx_prefix_pdu(bool isv4)
{
	/* Consider 32 bits of the length field */
	return HEADER_LENGTH + sizeof(u_int32_t) +
	    (isv4 ? IPV4_PREFIX_LENGTH : IPV6_PREFIX_LENGTH);
}

static u_int32_t
length_end_of_data_pdu(struct end_of_data_pdu *pdu)
{
	u_int32_t len;

	/* Consider 32 bits of the length field */
	len = HEADER_LENGTH + sizeof(u_int32_t);
	len += sizeof(pdu->serial_number);
	if (pdu->header.protocol_version == RTR_V1) {
		len += sizeof(pdu->refresh_interval);
		len += sizeof(pdu->retry_interval);
		len += sizeof(pdu->expire_interval);
	}

	return len;
}

static int
send_response(int fd, char *data, size_t data_len)
{
	struct data_buffer buffer;
	int error;

	init_buffer(&buffer);
	memcpy(buffer.data, data, data_len);
	buffer.len = data_len;

	/*
	 * FIXME Check for buffer overflow
	 */

	error = write(fd, buffer.data, buffer.len);
	free_buffer(&buffer);
	if (error < 0) {
		err(error, "Error sending response");
		/*
		 * TODO Send error PDU here depending on error type?
		 */
		return error;
	}

	return 0;
}

int
send_cache_response_pdu(int fd, u_int8_t version, u_int16_t session_id)
{
	struct cache_response_pdu pdu;
	char data[BUFFER_SIZE];
	size_t len;

	set_header_values(&pdu.header, version,
	    CACHE_RESPONSE_PDU_TYPE, session_id);
	pdu.header.length = length_cache_response_pdu(&pdu);

	len = serialize_cache_response_pdu(&pdu, data);
	/* TODO wait for the ACK? */
	return send_response(fd, data, len);
}

static int
send_ipv4_prefix_pdu(int fd, u_int8_t version, u_int32_t serial,
    struct vrp *vrp)
{
	struct ipv4_prefix_pdu pdu;
	char data[BUFFER_SIZE];
	size_t len;

	set_header_values(&pdu.header, version, IPV4_PREFIX_PDU_TYPE, 0);
	/* TODO FLAGS!! Hardcoded 1 to send announcement */
	pdu.flags = 1;
	pdu.prefix_length = vrp->prefix_length;
	pdu.max_length = vrp->max_prefix_length;
	pdu.zero = 0;
	pdu.ipv4_prefix = vrp->ipv4_prefix;
	pdu.asn = vrp->asn;
	pdu.header.length = length_ipvx_prefix_pdu(true);

	len = serialize_ipv4_prefix_pdu(&pdu, data);
	/* TODO wait for the ACK? */
	return send_response(fd, data, len);
}

static int
send_ipv6_prefix_pdu(int fd, u_int8_t version, u_int32_t serial,
    struct vrp *vrp)
{
	struct ipv6_prefix_pdu pdu;
	char data[BUFFER_SIZE];
	size_t len;

	set_header_values(&pdu.header, version, IPV6_PREFIX_PDU_TYPE, 0);
	/* TODO FLAGS!! Hardcoded 1 to send announcement */
	pdu.flags = 1;
	pdu.prefix_length = vrp->prefix_length;
	pdu.max_length = vrp->max_prefix_length;
	pdu.zero = 0;
	pdu.ipv6_prefix = vrp->ipv6_prefix;
	pdu.asn = vrp->asn;
	pdu.header.length = length_ipvx_prefix_pdu(false);

	len = serialize_ipv6_prefix_pdu(&pdu, data);
	/* TODO wait for the ACK? */
	return send_response(fd, data, len);
}

int
send_payload_pdus(int fd, u_int8_t version, u_int32_t serial)
{
	struct vrp **vrps, **ptr;
	unsigned int len, i;
	int error;

	vrps = get_vrps_delta(serial, &len);
	ptr = vrps;
	for (i = 0; i < len; i++) {
		if ((*ptr)->in_addr_len == INET_ADDRSTRLEN)
			error = send_ipv4_prefix_pdu(fd, version, serial, *ptr);
		else
			error = send_ipv6_prefix_pdu(fd, version, serial, *ptr);

		if (error)
			return error;
		ptr++;
	}

	return 0;
}

int
send_end_of_data_pdu(int fd, u_int8_t version, u_int16_t session_id)
{
	struct end_of_data_pdu pdu;
	char data[BUFFER_SIZE];
	size_t len;

	set_header_values(&pdu.header, version, END_OF_DATA_PDU_TYPE, session_id);
	pdu.serial_number = last_serial_number();
	if (version == RTR_V1) {
		pdu.refresh_interval = config_get_refresh_interval();
		pdu.retry_interval = config_get_retry_interval();
		pdu.expire_interval = config_get_expire_interval();
	}
	pdu.header.length = length_end_of_data_pdu(&pdu);

	len = serialize_end_of_data_pdu(&pdu, data);
	/* TODO wait for the ACK? */
	return send_response(fd, data, len);
}
