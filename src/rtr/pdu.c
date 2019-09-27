#include "rtr/pdu.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "address.h"
#include "clients.h"
#include "common.h"
#include "log.h"
#include "rtr/err_pdu.h"
#include "rtr/pdu_handler.h"

char const *
pdutype2str(enum pdu_type type)
{
	switch (type) {
	case PDU_TYPE_SERIAL_NOTIFY:
		return "Serial Notify";
	case PDU_TYPE_SERIAL_QUERY:
		return "Serial Query";
	case PDU_TYPE_RESET_QUERY:
		return "Reset Query";
	case PDU_TYPE_CACHE_RESPONSE:
		return "Cache Response";
	case PDU_TYPE_IPV4_PREFIX:
		return "IPv4 Prefix";
	case PDU_TYPE_IPV6_PREFIX:
		return "IPv6 Prefix";
	case PDU_TYPE_END_OF_DATA:
		return "End of Data";
	case PDU_TYPE_CACHE_RESET:
		return "Cache Reset";
	case PDU_TYPE_ROUTER_KEY:
		return "Router Key";
	case PDU_TYPE_ERROR_REPORT:
		return "Error Report";
	}

	return "(unknown)";
}

static int
pdu_header_from_reader(struct pdu_reader *reader, struct pdu_header *header)
{
	return read_int8(reader, &header->protocol_version)
	    || read_int8(reader, &header->pdu_type)
	    || read_int16(reader, &header->m.session_id)
	    || read_int32(reader, &header->length);
}

/* Do not use this macro before @header has been initialized, obviously. */
#define RESPOND_ERROR(report_cb) \
	((header.pdu_type != PDU_TYPE_ERROR_REPORT) ? (report_cb) : -EINVAL);

static int
validate_rtr_version(int fd, struct pdu_header *header,
    unsigned char *hdr_bytes)
{
	uint8_t curr_version;
	bool version_set;
	int error;

	error = clients_get_rtr_version_set(fd, &version_set, &curr_version);
	if (error)
		/* Unlikely, but close connection with min version */
		return (header->pdu_type != PDU_TYPE_ERROR_REPORT) ?
		    err_pdu_send_internal_error(fd, RTR_V0) : -EINVAL;

	if (version_set) {
		if (header->protocol_version == curr_version)
			return 0;

		/* Don't send error on a rcvd error! */
		if (header->pdu_type == PDU_TYPE_ERROR_REPORT)
			return -EINVAL;

		switch(curr_version) {
		case RTR_V1:
			/* Rcvd version is valid, but unexpected */
			if (header->protocol_version == RTR_V0)
				return err_pdu_send_unexpected_proto_version(
				    fd, curr_version, hdr_bytes,
				    "RTR version 0 was expected");
			/* Send common error */
		case RTR_V0:
			return err_pdu_send_unsupported_proto_version(fd,
			    curr_version, hdr_bytes,
			    "RTR version received is unknown.");
		default:
			pr_crit("Unknown RTR version %u", curr_version);
			break;
		}
	}

	/* Unsigned and incremental values, so compare against major version */
	if (header->protocol_version > RTR_V1)
		/* ...and send error with min version */
		return (header->pdu_type != PDU_TYPE_ERROR_REPORT) ?
		    err_pdu_send_unsupported_proto_version(fd, RTR_V0,
		    hdr_bytes, "RTR version received is unknown.")
		    : -EINVAL;

	return clients_set_rtr_version(fd, header->protocol_version);
}

int
pdu_load(int fd, struct sockaddr_storage *client_addr,
    struct rtr_request *request, struct pdu_metadata const **metadata)
{
	unsigned char hdr_bytes[RTRPDU_HDR_LEN];
	struct pdu_reader reader;
	struct pdu_header header;
	struct pdu_metadata const *meta;
	uint8_t version;
	int error;

	/* Read the header into its buffer. */
	error = pdu_reader_init(&reader, fd, hdr_bytes, RTRPDU_HDR_LEN, true);
	if (error)
		/* Communication interrupted; omit error response */
		return error;
	error = pdu_header_from_reader(&reader, &header);
	if (error)
		/* No error response because the PDU might have been an error */
		return error;

#ifdef DEBUG
	{
		char buffer[INET6_ADDRSTRLEN];
		pr_debug("Received a %s PDU from %s.",
		    pdutype2str(header.pdu_type),
		    sockaddr2str(client_addr, buffer));
	}
#endif

	error = validate_rtr_version(fd, &header, hdr_bytes);
	if (error)
		return error; /* Error response PDU already sent */

	/* RTR version ok, keep it for later use */
	version = header.protocol_version;

	/*
	 * DO NOT USE THE err_pdu_* functions directly. Wrap them with
	 * RESPOND_ERROR() INSTEAD.
	 * TODO I think this comment should be above validate_rtr_version(),
	 * and validate_rtr_version() is buggy.
	 */

	if (header.length < RTRPDU_HDR_LEN)
		return RESPOND_ERROR(err_pdu_send_invalid_request_truncated(fd,
		    version, hdr_bytes, "Invalid header length. (< 8 bytes)"));

	/*
	 * Error messages can be quite large.
	 * But they're probably not legitimate, so drop 'em.
	 * 512 is like a 5-paragraph error message, so it's probably enough.
	 * Most error messages are bound to be two phrases tops.
	 * (Warning: I'm assuming english tho.)
	 */
	if (header.length > 512)
		return RESPOND_ERROR(err_pdu_send_invalid_request_truncated(fd,
		    version, hdr_bytes, "PDU is too large. (> 512 bytes)"));

	/* Read the rest of the PDU into its buffer. */
	request->bytes_len = header.length;
	request->bytes = malloc(header.length);
	if (request->bytes == NULL)
		/* No error report PDU on allocation failures. */
		return pr_enomem();

	memcpy(request->bytes, hdr_bytes, RTRPDU_HDR_LEN);
	error = pdu_reader_init(&reader, fd,
	    request->bytes + RTRPDU_HDR_LEN,
	    header.length - RTRPDU_HDR_LEN,
	    false);
	if (error)
		/* Communication interrupted; no error PDU. */
		goto revert_bytes;

	/* Deserialize the PDU. */
	meta = pdu_get_metadata(header.pdu_type);
	if (!meta) {
		error = RESPOND_ERROR(err_pdu_send_unsupported_pdu_type(fd,
		    version, request));
		goto revert_bytes;
	}

	request->pdu = malloc(meta->length);
	if (request->pdu == NULL) {
		error = pr_enomem();
		goto revert_bytes;
	}

	error = meta->from_stream(&header, &reader, request->pdu);
	if (reader.size != 0) {
		error = RESPOND_ERROR(err_pdu_send_invalid_request(fd, version,
		    request,
		    "The PDU length sent doesn't match the real PDU length"));
		goto revert_pdu;
	}
	if (error) {
		RESPOND_ERROR(err_pdu_send_internal_error(fd, version));
		goto revert_pdu;
	}

	/* Happy path. */
	*metadata = meta;
	return 0;

revert_pdu:
	free(request->pdu);
revert_bytes:
	free(request->bytes);
	return error;
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
DEFINE_METADATA(serial_query, free);
DEFINE_METADATA(reset_query, free);
DEFINE_METADATA(cache_response, free);
DEFINE_METADATA(ipv4_prefix, free);
DEFINE_METADATA(ipv6_prefix, free);
DEFINE_METADATA(end_of_data, free);
DEFINE_METADATA(cache_reset, free);
DEFINE_METADATA(router_key, free);
DEFINE_METADATA(error_report, error_report_destroy);

struct pdu_metadata const *const pdu_metadatas[] = {
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
