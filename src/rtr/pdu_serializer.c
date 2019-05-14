#include "pdu_serializer.h"

#include <stdlib.h>
#include <string.h>
#include "primitive_writer.h"

static size_t
serialize_pdu_header(struct pdu_header *header, uint16_t union_value,
    unsigned char *buf)
{
	unsigned char *ptr;

	ptr = buf;
	ptr = write_int8(ptr, header->protocol_version);
	ptr = write_int8(ptr, header->pdu_type);
	ptr = write_int16(ptr, union_value);
	ptr = write_int32(ptr, header->length);

	return ptr - buf;
}

size_t
serialize_serial_notify_pdu(struct serial_notify_pdu *pdu, unsigned char *buf)
{
	size_t head_size;
	unsigned char *ptr;

	head_size = serialize_pdu_header(&pdu->header, pdu->header.m.session_id,
	    buf);

	ptr = buf + head_size;
	ptr = write_int32(ptr, pdu->serial_number);

	return ptr - buf;
}

size_t
serialize_cache_response_pdu(struct cache_response_pdu *pdu,
    unsigned char *buf)
{
	/* No payload to serialize */
	return serialize_pdu_header(&pdu->header, pdu->header.m.session_id,
	    buf);
}

size_t
serialize_ipv4_prefix_pdu(struct ipv4_prefix_pdu *pdu, unsigned char *buf)
{
	size_t head_size;
	unsigned char *ptr;

	head_size = serialize_pdu_header(&pdu->header, pdu->header.m.reserved,
	    buf);

	ptr = buf + head_size;
	ptr = write_int8(ptr, pdu->flags);
	ptr = write_int8(ptr, pdu->prefix_length);
	ptr = write_int8(ptr, pdu->max_length);
	ptr = write_int8(ptr, pdu->zero);
	ptr = write_in_addr(ptr, pdu->ipv4_prefix);
	ptr = write_int32(ptr, pdu->asn);

	return ptr - buf;
}

size_t
serialize_ipv6_prefix_pdu(struct ipv6_prefix_pdu *pdu, unsigned char *buf)
{
	size_t head_size;
	unsigned char *ptr;

	head_size = serialize_pdu_header(&pdu->header, pdu->header.m.reserved,
	    buf);

	ptr = buf + head_size;
	ptr = write_int8(ptr, pdu->flags);
	ptr = write_int8(ptr, pdu->prefix_length);
	ptr = write_int8(ptr, pdu->max_length);
	ptr = write_int8(ptr, pdu->zero);
	ptr = write_in6_addr(ptr, pdu->ipv6_prefix);
	ptr = write_int32(ptr, pdu->asn);

	return ptr - buf;
}

size_t
serialize_end_of_data_pdu(struct end_of_data_pdu *pdu, unsigned char *buf)
{
	size_t head_size;
	unsigned char *ptr;

	head_size = serialize_pdu_header(&pdu->header, pdu->header.m.session_id,
	    buf);

	ptr = buf + head_size;
	ptr = write_int32(ptr, pdu->serial_number);
	if (pdu->header.protocol_version == RTR_V1) {
		ptr = write_int32(ptr, pdu->refresh_interval);
		ptr = write_int32(ptr, pdu->retry_interval);
		ptr = write_int32(ptr, pdu->expire_interval);
	}

	return ptr - buf;
}

size_t
serialize_cache_reset_pdu(struct cache_reset_pdu *pdu, unsigned char *buf)
{
	/* No payload to serialize */
	return serialize_pdu_header(&pdu->header, pdu->header.m.reserved, buf);
}

/*
 * Don't forget to use 'header->reserved' to set flags
 */
size_t
serialize_router_key_pdu(struct router_key_pdu *pdu, unsigned char *buf)
{
	size_t head_size;
	unsigned char *ptr;
	int i;

	if (pdu->header.protocol_version == RTR_V0)
		return 0;

	head_size = serialize_pdu_header(&pdu->header, pdu->header.m.reserved,
	    buf);

	ptr = buf + head_size;

	for (i = 0; i < pdu->ski_len; i++)
		ptr = write_int8(ptr, pdu->ski[i]);

	ptr = write_int32(ptr, pdu->asn);

	for (i = 0; i < pdu->spki_len; i++)
		ptr = write_int8(ptr, pdu->spki[i]);

	return ptr - buf;
}

size_t
serialize_error_report_pdu(struct error_report_pdu *pdu, unsigned char *buf)
{
	unsigned char *ptr;

	ptr = buf;
	ptr += serialize_pdu_header(&pdu->header, pdu->header.m.error_code, buf);

	ptr = write_int32(ptr, pdu->error_pdu_length);
	if (pdu->error_pdu_length > 0) {
		memcpy(ptr, pdu->erroneous_pdu, pdu->error_pdu_length);
		ptr += pdu->error_pdu_length;
	}

	ptr = write_int32(ptr, pdu->error_message_length);
	if (pdu->error_message_length > 0) {
		memcpy(ptr, pdu->error_message, pdu->error_message_length);
		ptr += pdu->error_message_length;
	}

	return ptr - buf;
}
