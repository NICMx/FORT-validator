#include "pdu_sender.h"

#include <err.h>
#include <stdlib.h>
#include <unistd.h>

#include "configuration.h"
#include "pdu.h"
#include "pdu_serializer.h"

/* Header without length field is always 32 bits long */
#define HEADER_LENGTH 4

#define BUFFER_SIZE 32

struct buffer {
	size_t len;
	size_t capacity;
	char *data;
};

static void
init_buffer(struct buffer *buffer)
{
	buffer->capacity = BUFFER_SIZE;
	buffer->data = malloc(BUFFER_SIZE);
}

static void
free_buffer(struct buffer *buffer)
{
	free(buffer->data);
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
length_cache_response_pdu(struct cache_response_pdu *pdu)
{
	/* This PDU has no payload, consider 32 bits of the length field */
	return HEADER_LENGTH + sizeof(u_int32_t);
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
send_response(int fd, struct buffer *buffer)
{
	int error;

	/*
	 * FIXME Check for buffer overflow
	 */

	error = write(fd, buffer->data, buffer->len);
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
	struct buffer buffer;
	int error;

	init_buffer(&buffer);
	set_header_values(&pdu.header, version,
	    CACHE_RESPONSE_PDU_TYPE, session_id);
	pdu.header.length = length_cache_response_pdu(&pdu);

	buffer.len = serialize_cache_response_pdu(&pdu, buffer.data);
	error = send_response(fd, &buffer);
	free_buffer(&buffer);
	if (error)
		return error;

	return 0;
}

int
send_payload_pdus(int fd, u_int8_t version)
{
	// FIXME Complete me!!
	return 0;
}

int
send_end_of_data_pdu(int fd, u_int8_t version, u_int16_t session_id)
{
	struct end_of_data_pdu pdu;
	struct buffer buffer;
	int error;

	init_buffer(&buffer);
	set_header_values(&pdu.header, version, END_OF_DATA_PDU_TYPE, session_id);
	pdu.serial_number = 16;
	if (version == RTR_V1) {
		pdu.refresh_interval = config_get_refresh_interval();
		pdu.retry_interval = config_get_retry_interval();
		pdu.expire_interval = config_get_expire_interval();
	}
	pdu.header.length = length_end_of_data_pdu(&pdu);

	buffer.len = serialize_end_of_data_pdu(&pdu, buffer.data);
	error = send_response(fd, &buffer);
	free_buffer(&buffer);
	if (error)
		return error;

	return 0;
}
