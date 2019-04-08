#include "pdu.h"

#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "../common.h"
#include "pdu_handler.h"

static int	pdu_header_from_stream(int, struct pdu_header *);
static int	serial_notify_from_stream(struct pdu_header *, int, void *);
static int	serial_query_from_stream(struct pdu_header *, int, void *);
static int	reset_query_from_stream(struct pdu_header *, int, void *);
static int	cache_response_from_stream(struct pdu_header *, int, void *);
static int	ipv4_prefix_from_stream(struct pdu_header *, int, void *);
static int	ipv6_prefix_from_stream(struct pdu_header *, int, void *);
static int	end_of_data_from_stream(struct pdu_header *, int, void *);
static int	cache_reset_from_stream(struct pdu_header *, int, void *);
static int	error_report_from_stream(struct pdu_header *, int, void *);
static void	error_report_destroy(void *);

int
pdu_load(int fd, void **pdu, struct pdu_metadata const **metadata,
    uint8_t *rtr_version)
{
	struct pdu_header header;
	struct pdu_metadata const *meta;
	int err;

	err = pdu_header_from_stream(fd, &header);
	if (err)
		return err;

	meta = pdu_get_metadata(header.pdu_type);
	if (!meta)
		return -ENOENT; /* TODO try to skip it anyway? */

	*pdu = malloc(meta->length);
	if (*pdu == NULL)
		return -ENOMEM;

	err = meta->from_stream(&header, fd, *pdu);
	if (err) {
		free(*pdu);
		return err;
	}
	*rtr_version = header.protocol_version;

	if (metadata)
		*metadata = meta;
	return 0;
}

static int
pdu_header_from_stream(int fd, struct pdu_header *header)
{
	/* If the first read yields no bytes, the connection was terminated. */
	return read_int8(fd, &header->protocol_version)
	    || read_int8(fd, &header->pdu_type)
	    || read_int16(fd, &header->m.session_id)
	    || read_int32(fd, &header->length);
}

static int
serial_notify_from_stream(struct pdu_header *header, int fd, void *pdu_void)
{
	struct serial_notify_pdu *pdu = pdu_void;
	memcpy(&pdu->header, header, sizeof(*header));
	return read_int32(fd, &pdu->serial_number);
}

static int
serial_query_from_stream(struct pdu_header *header, int fd, void *pdu_void)
{
	struct serial_query_pdu *pdu = pdu_void;
	memcpy(&pdu->header, header, sizeof(*header));
	return read_int32(fd, &pdu->serial_number);
}

static int
reset_query_from_stream(struct pdu_header *header, int fd, void *pdu_void)
{
	struct reset_query_pdu *pdu = pdu_void;
	memcpy(&pdu->header, header, sizeof(*header));
	return 0;
}

static int
cache_response_from_stream(struct pdu_header *header, int fd, void *pdu_void)
{
	struct cache_response_pdu *pdu = pdu_void;
	memcpy(&pdu->header, header, sizeof(*header));
	return 0;
}

static int
ipv4_prefix_from_stream(struct pdu_header *header, int fd, void *pdu_void)
{
	struct ipv4_prefix_pdu *pdu = pdu_void;
	memcpy(&pdu->header, header, sizeof(*header));
	return read_int8(fd, &pdu->flags)
	    || read_int8(fd, &pdu->prefix_length)
	    || read_int8(fd, &pdu->max_length)
	    || read_int8(fd, &pdu->zero)
	    || read_in_addr(fd, &pdu->ipv4_prefix)
	    || read_int32(fd, &pdu->asn);
}

static int
ipv6_prefix_from_stream(struct pdu_header *header, int fd, void *pdu_void)
{
	struct ipv6_prefix_pdu *pdu = pdu_void;
	memcpy(&pdu->header, header, sizeof(*header));
	return read_int8(fd, &pdu->flags)
	    || read_int8(fd, &pdu->prefix_length)
	    || read_int8(fd, &pdu->max_length)
	    || read_int8(fd, &pdu->zero)
	    || read_in6_addr(fd, &pdu->ipv6_prefix)
	    || read_int32(fd, &pdu->asn);
}

static int
end_of_data_from_stream(struct pdu_header *header, int fd, void *pdu_void)
{
	struct end_of_data_pdu *pdu = pdu_void;
	memcpy(&pdu->header, header, sizeof(*header));
	return read_int32(fd, &pdu->serial_number);
}

static int
cache_reset_from_stream(struct pdu_header *header, int fd, void *pdu_void)
{
	struct cache_reset_pdu *pdu = pdu_void;
	memcpy(&pdu->header, header, sizeof(*header));
	return 0;
}

static int
error_report_from_stream(struct pdu_header *header, int fd, void *pdu_void)
{
	struct error_report_pdu *pdu = pdu_void;
	uint32_t sub_pdu_len; /* TODO use this for something */
	uint8_t rtr_version;
	int error;

	memcpy(&pdu->header, header, sizeof(*header));

	error = read_int32(fd, &sub_pdu_len);
	if (error)
		return error;

	error = pdu_load(fd, &pdu->erroneous_pdu, NULL, &rtr_version);
	if (error)
		return -EINVAL;

	error = read_string(fd, &pdu->error_message);
	if (error) {
		free(pdu->erroneous_pdu);
		return error;
	}

	return 0;
}

static void
error_report_destroy(void *pdu_void)
{
	struct error_report_pdu *pdu = pdu_void;
	struct pdu_header *sub_hdr;
	struct pdu_metadata const *sub_meta;

	sub_hdr = pdu_get_header(pdu->erroneous_pdu);
	sub_meta = pdu_get_metadata(sub_hdr->pdu_type);
	if (sub_meta)
		sub_meta->destructor(pdu->erroneous_pdu);
	else
		warnx("Unknown PDU type (%u).", sub_hdr->pdu_type);

	free(pdu->error_message);
	free(pdu_void);
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
	/* 9 */  NULL,
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
