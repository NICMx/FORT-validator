#include "rtr/pdu.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "common.h"
#include "log.h"
#include "types/address.h"
#include "rtr/err_pdu.h"
#include "rtr/pdu_handler.h"

char const *
pdutype2str(enum pdu_type type)
{
	switch (type) {
	case PDU_TYPE_SERIAL_NOTIFY:
		return "Serial Notify PDU";
	case PDU_TYPE_SERIAL_QUERY:
		return "Serial Query PDU";
	case PDU_TYPE_RESET_QUERY:
		return "Reset Query PDU";
	case PDU_TYPE_CACHE_RESPONSE:
		return "Cache Response PDU";
	case PDU_TYPE_IPV4_PREFIX:
		return "IPv4 Prefix PDU";
	case PDU_TYPE_IPV6_PREFIX:
		return "IPv6 Prefix PDU";
	case PDU_TYPE_END_OF_DATA:
		return "End of Data PDU";
	case PDU_TYPE_CACHE_RESET:
		return "Cache Reset PDU";
	case PDU_TYPE_ROUTER_KEY:
		return "Router Key PDU";
	case PDU_TYPE_ERROR_REPORT:
		return "Error Report PDU";
	}

	return "unknown PDU";
}

static int
pdu_header_from_reader(struct pdu_reader *reader, struct pdu_header *header)
{
	int error;

	error = read_int8(reader, &header->protocol_version);
	if (error)
		return error;
	error = read_int8(reader, &header->pdu_type);
	if (error)
		return error;
	error = read_int16(reader, &header->m.session_id);
	if (error)
		return error;
	return read_int32(reader, &header->length);
}

static int
validate_rtr_version(struct rtr_client *client, struct pdu_header *header,
    unsigned char *hdr_bytes)
{
	if (client->rtr_version != -1) {
		if (header->protocol_version == client->rtr_version)
			return 0;

		/* Don't send error on a rcvd error! */
		if (header->pdu_type == PDU_TYPE_ERROR_REPORT)
			return -EINVAL;

		switch (client->rtr_version) {
		case RTR_V1:
			/* Rcvd version is valid, but unexpected */
			if (header->protocol_version == RTR_V0)
				return err_pdu_send_unexpected_proto_version(
				    client->fd, client->rtr_version, hdr_bytes,
				    "RTR version 0 was expected");
			/* Send common error */
		case RTR_V0:
			return err_pdu_send_unsupported_proto_version(
			    client->fd, client->rtr_version, hdr_bytes,
			    "RTR version received is unknown.");
		default:
			pr_crit("Unknown RTR version %u", client->rtr_version);
		}
	}

	/* Unsigned and incremental values, so compare against major version */
	if (header->protocol_version > RTR_V1)
		/* ...and send error with min version */
		return (header->pdu_type != PDU_TYPE_ERROR_REPORT)
		    ? err_pdu_send_unsupported_proto_version(client->fd, RTR_V0,
		          hdr_bytes, "RTR version received is unknown.")
		    : -EINVAL;

	client->rtr_version = header->protocol_version;
	return 0;
}

/* Do not use this macro before @header has been initialized, obviously. */
#define RESPOND_ERROR(report_cb) \
	((header.pdu_type != PDU_TYPE_ERROR_REPORT) ? (report_cb) : -EINVAL);

/*
 * Reads the next PDU from @reader. Returns the PDU in @request, and its
 * metadata in @metadata.
 */
int
pdu_load(struct pdu_reader *reader, struct rtr_client *client,
    struct rtr_request *request, struct pdu_metadata const **metadata)
{
	struct pdu_header header;
	struct pdu_metadata const *meta;
	int error;

	if (reader->size == 0) {
		pr_op_debug("Client packet contains no more PDUs.");
		return ENOENT;
	}

	request->bytes = reader->buffer;
	request->bytes_len = RTRPDU_HDR_LEN;

	error = pdu_header_from_reader(reader, &header);
	if (error)
		/* No error response because the PDU might have been an error */
		return error;

	pr_op_debug("PDU '%s' received from client '%s'",
	    pdutype2str(header.pdu_type), client->addr);

	error = validate_rtr_version(client, &header, request->bytes);
	if (error)
		return error; /* Error response PDU already sent */

	/*
	 * DO NOT USE THE err_pdu_* functions directly. Wrap them with
	 * RESPOND_ERROR() INSTEAD.
	 */

	if (header.length < RTRPDU_HDR_LEN)
		return RESPOND_ERROR(err_pdu_send_invalid_request_truncated(
		    client->fd, client->rtr_version, request->bytes,
		    "Invalid header length. (< 8 bytes)"));

	/*
	 * Error messages can be quite large.
	 * But they're probably not legitimate, so drop 'em.
	 * 512 is like a 5-paragraph error message, so it's probably enough.
	 * Most error messages are bound to be two phrases tops.
	 * (Warning: I'm assuming english tho.)
	 */
	if (header.length > 512)
		return RESPOND_ERROR(err_pdu_send_invalid_request_truncated(
		    client->fd, client->rtr_version, request->bytes,
		    "PDU is too large. (> 512 bytes)"));

	request->bytes_len = header.length;

	/* Deserialize the PDU. */
	meta = pdu_get_metadata(header.pdu_type);
	if (!meta)
		return RESPOND_ERROR(err_pdu_send_unsupported_pdu_type(
		    client->fd, client->rtr_version, request));

	request->pdu = malloc(meta->length);
	if (request->pdu == NULL)
		/* No error report PDU on allocation failures. */
		enomem_panic();

	error = meta->from_stream(&header, reader, request->pdu);
	if (error) {
		/* Communication interrupted; no error PDU. */
		free(request->pdu);
		return error;
	}

	/* Happy path. */
	*metadata = meta;
	return 0;
}

static int
serial_notify_from_stream(struct pdu_header *header, struct pdu_reader *reader,
    void *pdu_void)
{
	struct serial_notify_pdu *pdu = pdu_void;
	memcpy(&pdu->header, header, sizeof(*header));
	return read_int32(reader, &pdu->serial_number);
}

static int
serial_query_from_stream(struct pdu_header *header, struct pdu_reader *reader,
    void *pdu_void)
{
	struct serial_query_pdu *pdu = pdu_void;
	memcpy(&pdu->header, header, sizeof(*header));
	return read_int32(reader, &pdu->serial_number);
}

static int
reset_query_from_stream(struct pdu_header *header, struct pdu_reader *reader,
    void *pdu_void)
{
	struct reset_query_pdu *pdu = pdu_void;
	memcpy(&pdu->header, header, sizeof(*header));
	return 0;
}

static int
cache_response_from_stream(struct pdu_header *header, struct pdu_reader *reader,
    void *pdu_void)
{
	struct cache_response_pdu *pdu = pdu_void;
	memcpy(&pdu->header, header, sizeof(*header));
	return 0;
}

static int
ipv4_prefix_from_stream(struct pdu_header *header, struct pdu_reader *reader,
    void *pdu_void)
{
	struct ipv4_prefix_pdu *pdu = pdu_void;
	memcpy(&pdu->header, header, sizeof(*header));
	return read_int8(reader, &pdu->flags)
	    || read_int8(reader, &pdu->prefix_length)
	    || read_int8(reader, &pdu->max_length)
	    || read_int8(reader, &pdu->zero)
	    || read_in_addr(reader, &pdu->ipv4_prefix)
	    || read_int32(reader, &pdu->asn);
}

static int
ipv6_prefix_from_stream(struct pdu_header *header, struct pdu_reader *reader,
    void *pdu_void)
{
	struct ipv6_prefix_pdu *pdu = pdu_void;
	memcpy(&pdu->header, header, sizeof(*header));
	return read_int8(reader, &pdu->flags)
	    || read_int8(reader, &pdu->prefix_length)
	    || read_int8(reader, &pdu->max_length)
	    || read_int8(reader, &pdu->zero)
	    || read_in6_addr(reader, &pdu->ipv6_prefix)
	    || read_int32(reader, &pdu->asn);
}

static int
end_of_data_from_stream(struct pdu_header *header, struct pdu_reader *reader,
    void *pdu_void)
{
	struct end_of_data_pdu *pdu = pdu_void;
	memcpy(&pdu->header, header, sizeof(*header));
	return read_int32(reader, &pdu->serial_number);
}

static int
cache_reset_from_stream(struct pdu_header *header, struct pdu_reader *reader,
    void *pdu_void)
{
	struct cache_reset_pdu *pdu = pdu_void;
	memcpy(&pdu->header, header, sizeof(*header));
	return 0;
}

static int
router_key_from_stream(struct pdu_header *header, struct pdu_reader *reader,
    void *pdu_void)
{
	struct router_key_pdu *pdu = pdu_void;
	memcpy(&pdu->header, header, sizeof(*header));
	return 0;
}

static int
error_report_from_stream(struct pdu_header *header, struct pdu_reader *reader,
    void *pdu_void)
{
	struct error_report_pdu *pdu = pdu_void;
	int error;

	memcpy(&pdu->header, header, sizeof(*header));

	error = read_int32(reader, &pdu->error_pdu_length);
	if (error)
		return error;
	error = read_bytes(reader, pdu->erroneous_pdu, pdu->error_pdu_length);
	if (error)
		return error;
	error = read_int32(reader, &pdu->error_message_length);
	if (error)
		return error;
	return read_string(reader, pdu->error_message_length,
	    &pdu->error_message);
}

static void
error_report_destroy(void *pdu_void)
{
	struct error_report_pdu *pdu = pdu_void;
	free(pdu->error_message);
	free(pdu);
}

#define DEFINE_METADATA(name, dtor)					\
	static struct pdu_metadata const name ## _meta = {		\
		.length = sizeof(struct name ## _pdu),			\
		.from_stream = name ## _from_stream,			\
		.handle = handle_ ## name ## _pdu,			\
		.destructor = dtor,					\
	}

DEFINE_METADATA(serial_notify, free);
DEFINE_METADATA(serial_query, free); /* handle_serial_query_pdu */
DEFINE_METADATA(reset_query, free);
DEFINE_METADATA(cache_response, free);
DEFINE_METADATA(ipv4_prefix, free);
DEFINE_METADATA(ipv6_prefix, free);
DEFINE_METADATA(end_of_data, free);
DEFINE_METADATA(cache_reset, free);
DEFINE_METADATA(router_key, free);
DEFINE_METADATA(error_report, error_report_destroy);

static struct pdu_metadata const *const pdu_metadatas[] = {
	/* 0 */  &serial_notify_meta,
	/* 1 */  &serial_query_meta,
	/* 2 */  &reset_query_meta,
	/* 3 */  &cache_response_meta,
	/* 4 */  &ipv4_prefix_meta,
	/* 5 */  NULL,
	/* 6 */  &ipv6_prefix_meta,
	/* 7 */  &end_of_data_meta,
	/* 8 */  &cache_reset_meta,
	/* 9 */  &router_key_meta,
	/* 10 */ &error_report_meta,
};

struct pdu_metadata const *
pdu_get_metadata(uint8_t type)
{
	return (ARRAY_LEN(pdu_metadatas) <= type) ? NULL : pdu_metadatas[type];
}

struct pdu_header *
pdu_get_header(void *pdu)
{
	/* The header is by definition the first field of every PDU. */
	return pdu;
}
