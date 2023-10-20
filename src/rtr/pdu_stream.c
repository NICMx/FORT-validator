#include "rtr/pdu_stream.h"

#include <errno.h>
#include <stddef.h>

#include "log.h"
#include "alloc.h"
#include "rtr/pdu.h"
#include "rtr/err_pdu.h"

enum buffer_state {
	/* We've read all available bytes for now. */
	BS_WOULD_BLOCK,
	/* "End of Stream." We've read all available bytes, ever. */
	BS_EOS,
	/* read() still has more data to yield (but buffer is full for now). */
	BS_KEEP_READING,
	/* Communication broken. */
	BS_ERROR,
};

struct pdu_stream {
	int fd;
	char addr[INET6_ADDRSTRLEN]; /* Printable address of the client. */
	int rtr_version; /* -1: unset; > 0: version number */

	unsigned char buffer[RTRPDU_MAX_LEN2];

	/* buffer's active bytes */
	unsigned char *start;
	unsigned char *end;
};

struct pdu_stream *pdustream_create(int fd, char const *addr)
{
	struct pdu_stream *result;

	result = pmalloc(sizeof(struct pdu_stream));
	result->fd = fd;
	strcpy(result->addr, addr);
	result->rtr_version = -1;
	result->start = result->buffer;
	result->end = result->buffer;

	return result;
}

void
pdustream_destroy(struct pdu_stream **_stream)
{
	struct pdu_stream *stream = *_stream;
	close(stream->fd);
	free(stream);
}

static size_t
get_length(struct pdu_stream *stream)
{
	return stream->end - stream->start;
}

/*
 * Will read whatever's in the stream without blocking, but not more than
 * RTRPDU_MAX_LEN2 bytes.
 *
 * It might read more than one PDU into the buffer, and extremely unlikely,
 * the last PDU might be incomplete (even if it's the only one).
 *
 * Returns
 * - true: success.
 * - false: oh noes; close socket.
 */
static enum buffer_state
update_buffer(struct pdu_stream *in /* "in"put stream */)
{
	ssize_t consumed;
	int error;

	/* Move leftover bytes to the beginning */
	if (in->buffer != in->start) {
		if (in->start != in->end)
			memmove(in->buffer, in->start, get_length(in));
		in->end -= in->start - in->buffer;
		in->start = in->buffer;
	}

	for (; in->end < in->start + RTRPDU_MAX_LEN2; in->end += consumed) {
		consumed = read(in->fd, in->end, RTRPDU_MAX_LEN2 - get_length(in));
		if (consumed == -1) {
			error = errno;
			if (error == EAGAIN || error == EWOULDBLOCK)
				return BS_WOULD_BLOCK;

			pr_op_err("Client socket read interrupted: %s",
			    strerror(error));
			return BS_ERROR;
		}

		if (consumed == 0) {
			pr_op_debug("Client closed the socket.");
			return BS_EOS;
		}
	}

	/*
	 * We might or might not have read everything, but we have at least one
	 * big PDU that either lengths exactly RTRPDU_MAX_LEN2, or is too big
	 * for us to to allow it.
	 */
	return BS_KEEP_READING;
}

static uint16_t
read_uint16(unsigned char *buffer)
{
	return (((uint16_t)buffer[0]) <<  8)
	     | (((uint16_t)buffer[1])      );
}

static uint32_t
read_uint32(unsigned char *buffer)
{
	return (((uint32_t)buffer[0]) << 24)
	     | (((uint32_t)buffer[1]) << 16)
	     | (((uint32_t)buffer[2]) <<  8)
	     | (((uint32_t)buffer[3])      );
}

#define EINVALID_UTF8 -0xFFFF

/*
 * Returns the length (in octets) of the UTF-8 code point that starts with
 * octet @first_octet.
 */
static int
get_octets(unsigned char first_octet)
{
	if ((first_octet & 0x80) == 0)
		return 1;
	if ((first_octet >> 5) == 6) /* 0b110 */
		return 2;
	if ((first_octet >> 4) == 14) /* 0b1110 */
		return 3;
	if ((first_octet >> 3) == 30) /* 0b11110 */
		return 4;
	return EINVALID_UTF8;
}

/* This is just a cast. The barebones version is too cluttered. */
#define UCHAR(c) ((unsigned char *)c)

/*
 * This also sanitizes the string, BTW.
 * (Because it overrides the first invalid character with the null chara.
 * The rest is silently ignored.)
 */
static void
place_null_character(char *str, size_t len)
{
	char *null_chara_pos;
	char *cursor;
	int octet;
	int octets;

	/*
	 * This could be optimized by noticing that all byte continuations in
	 * UTF-8 start with 0b10. This means that we could start from the end
	 * of the string and move left until we find a valid character.
	 * But if we do that, we'd lose the sanitization. So this is better
	 * methinks.
	 */

	null_chara_pos = str;
	cursor = str;

	while (cursor < str + len) {
		octets = get_octets(*UCHAR(cursor));
		if (octets == EINVALID_UTF8)
			break;
		cursor++;

		for (octet = 1; octet < octets; octet++) {
			/* Memory ends in the middle of this code point? */
			if (cursor >= str + len)
				goto end;
			/* All continuation octets must begin with 0b10. */
			if ((*(UCHAR(cursor)) >> 6) != 2 /* 0b10 */)
				goto end;
			cursor++;
		}

		null_chara_pos = cursor;
	}

end:
	*null_chara_pos = '\0';
}

static char *
read_string(struct pdu_stream *stream, uint32_t len)
{
	char *string;

	if (len == 0)
		return NULL;

	string = pmalloc(len + 1);
	memcpy(string, stream->start, len);
	place_null_character(string, len);

	return string;
}

static void
read_hdr(struct pdu_stream *stream, struct pdu_header *header)
{
	header->version = stream->start[0];
	header->type = stream->start[1];
	header->m.reserved = read_uint16(stream->start + 2);
	header->length = read_uint32(stream->start + 4);
}

static int
validate_rtr_version(struct pdu_stream *stream, struct pdu_header *header,
    struct rtr_buffer *request)
{
	switch (stream->rtr_version) {
	case RTR_V1:
		switch (header->version) {
		case RTR_V0:
			goto unexpected;
		case RTR_V1:
			return 0;
		default:
			goto unsupported;
		}

	case RTR_V0:
		switch (header->version) {
		case RTR_V0:
			return 0;
		case RTR_V1:
			goto unexpected;
		default:
			goto unsupported;
		}

	case -1:
		switch (header->version) {
		case RTR_V0:
		case RTR_V1:
			stream->rtr_version = header->version;
			return 0;
		default:
			goto unsupported;
		}
	}

	pr_crit("Unknown RTR version %u", stream->rtr_version);

unsupported:
	return err_pdu_send_unsupported_proto_version(
		stream->fd, stream->rtr_version, request,
		"The maximum supported RTR version is 1."
	);

unexpected:
	return err_pdu_send_unexpected_proto_version(
		stream->fd, stream->rtr_version, request,
		"The RTR version does not match the one we negotiated during the handshake."
	);
}

static int
load_serial_query(struct pdu_stream *stream, struct pdu_header *hdr,
    struct rtr_pdu *result)
{
	if (hdr->length != RTRPDU_SERIAL_QUERY_LEN) {
		return err_pdu_send_invalid_request(
			stream->fd, stream->rtr_version, &result->raw,
			"Expected length 12 for Serial Query PDUs."
		);
	}
	if (get_length(stream) < RTRPDU_SERIAL_QUERY_LEN)
		return EAGAIN;

	pr_op_debug("Received a Serial Query from %s.", stream->addr);

	memcpy(&result->obj.sq.header, hdr, sizeof(*hdr));
	stream->start += RTR_HDR_LEN;
	result->obj.sq.serial_number = read_uint32(stream->start);
	stream->start += 4;

	return 0;
}

static int
load_reset_query(struct pdu_stream *stream, struct pdu_header *hdr,
    struct rtr_pdu *result)
{
	if (hdr->length != RTRPDU_RESET_QUERY_LEN) {
		return err_pdu_send_invalid_request(
			stream->fd, stream->rtr_version, &result->raw,
			"Expected length 8 for Reset Query PDUs."
		);
	}
	if (get_length(stream) < RTRPDU_RESET_QUERY_LEN)
		return EAGAIN;

	pr_op_debug("Received a Reset Query from %s.", stream->addr);

	memcpy(&result->obj.rq.header, hdr, sizeof(*hdr));
	stream->start += RTR_HDR_LEN;

	return 0;
}

static int
load_error_report(struct pdu_stream *stream, struct pdu_header *hdr,
    struct rtr_pdu *result)
{
	struct error_report_pdu *pdu;
	int error;

	if (hdr->length > RTRPDU_ERROR_REPORT_MAX_LEN) {
		return pr_op_err(
			"RTR client %s sent a large Error Report PDU (%u bytes). This looks broken, so I'm dropping the connection.",
			stream->addr, hdr->length
		);
	}

	pr_op_debug("Received an Error Report from %s.", stream->addr);

	pdu = &result->obj.er;

	/* Header */
	memcpy(&pdu->header, hdr, sizeof(*hdr));
	stream->start += RTR_HDR_LEN;

	/* Error PDU length */
	if (get_length(stream) < 4) {
		error = EAGAIN;
		goto revert_hdr;
	}
	pdu->errpdu_len = read_uint32(stream->start);
	stream->start += 4;
	if (pdu->errpdu_len > RTRPDU_MAX_LEN) {
		/*
		 * We truncate PDUs larger than RTRPDU_MAX_LEN, so we couldn't
		 * have sent this PDU. Looks like someone is messing with us.
		 */
		error = pr_op_err(
			"RTR client %s sent an Error Report PDU containing a large error PDU (%u bytes). This looks broken/insecure; I'm dropping the connection.",
			stream->addr, pdu->errpdu_len
		);
		goto revert_errpdu_len;
	}

	/* Error PDU */
	if (get_length(stream) < pdu->errpdu_len) {
		error = EAGAIN;
		goto revert_errpdu_len;
	}

	memcpy(pdu->errpdu, stream->start, pdu->errpdu_len);
	stream->start += pdu->errpdu_len;

	/* Error msg length */
	if (get_length(stream) < 4) {
		error = EAGAIN;
		goto revert_errpdu;
	}
	pdu->errmsg_len = read_uint32(stream->start);
	stream->start += 4;
	if (hdr->length != rtrpdu_error_report_len(pdu->errpdu_len, pdu->errmsg_len)) {
		error = pr_op_err(
			"RTR client %s sent a malformed Error Report PDU; header length is %u, but effective length is %u + %u + %u + %u + %u.",
			stream->addr, hdr->length,
			RTR_HDR_LEN, 4, pdu->errpdu_len, 4, pdu->errmsg_len
		);
		goto revert_errmsg_len;
	}

	/* Error msg */
	pdu->errmsg = read_string(stream, pdu->errmsg_len);
	stream->start += pdu->errmsg_len;

	return 0;

revert_errmsg_len:
	stream->start -= 4;
revert_errpdu:
	stream->start -= pdu->errpdu_len;
revert_errpdu_len:
	stream->start -= 4;
revert_hdr:
	stream->start -= RTR_HDR_LEN;
	return error;
}

/*
 * Returns:
 * == 0: Success; at least zero PDUs read.
 * != 0: Communication broken; close the connection.
 */
int
pdustream_next(struct pdu_stream *stream, struct rtr_request **_result)
{
	enum buffer_state state;
	struct pdu_header hdr;
	struct rtr_request *result;
	struct rtr_pdu *pdu;
	size_t remainder;
	int error;

	result = pmalloc(sizeof(struct rtr_request));
	result->fd = stream->fd;
	strcpy(result->client_addr, stream->addr);
	STAILQ_INIT(&result->pdus);
	result->eos = false;

	pdu = NULL;

again:
	state = update_buffer(stream);
	if (state == BS_ERROR) {
		error = EINVAL;
		goto fail;
	}

	while (stream->start < stream->end) {
		remainder = get_length(stream);

		/* Read header. */
		if (remainder < RTR_HDR_LEN)
			break;
		read_hdr(stream, &hdr);

		/* Init raw PDU; Needed early because of error responses. */
		pdu = pzalloc(sizeof(struct rtr_pdu));
		pdu->raw.bytes_len = (hdr.length <= remainder)
		    ? hdr.length : remainder;
		pdu->raw.bytes = pmalloc(pdu->raw.bytes_len);
		memcpy(pdu->raw.bytes, stream->start, pdu->raw.bytes_len);

		/* Validate length; Needs raw. */
		if (hdr.length > RTRPDU_MAX_LEN2) {
			error = err_pdu_send_invalid_request(
				stream->fd,
				(stream->rtr_version != -1)
				    ? stream->rtr_version
				    : hdr.version,
				&pdu->raw,
				"PDU is too large."
			);
			goto fail;
		}

		if (remainder < hdr.length) {
			free(pdu->raw.bytes);
			free(pdu);
			break;
		}

		/* Validate version; Needs raw. */
		error = validate_rtr_version(stream, &hdr, &pdu->raw);
		if (error)
			goto fail;

		switch (hdr.type) {
		case PDU_TYPE_SERIAL_QUERY:
			error = load_serial_query(stream, &hdr, pdu);
			break;
		case PDU_TYPE_RESET_QUERY:
			error = load_reset_query(stream, &hdr, pdu);
			break;
		case PDU_TYPE_ERROR_REPORT:
			error = load_error_report(stream, &hdr, pdu);
			break;
		default:
			err_pdu_send_unsupported_pdu_type(stream->fd,
			    stream->rtr_version, &pdu->raw);
			error = ENOTSUP;
		}

		if (error)
			goto fail;

		STAILQ_INSERT_TAIL(&result->pdus, pdu, hook);
	}

	*_result = result;

	switch (state) {
	case BS_WOULD_BLOCK:
		result->eos = false;
		return 0;
	case BS_EOS:
		result->eos = true;
		return 0;
	case BS_KEEP_READING:
		goto again;
	default:
		error = EINVAL;
	}

fail:
	if (pdu != NULL) {
		free(pdu->raw.bytes);
		free(pdu);
	}
	rtreq_destroy(result);
	return error;
}

int
pdustream_fd(struct pdu_stream *stream)
{
	return stream->fd;
}

char const *
pdustream_addr(struct pdu_stream *stream)
{
	return stream->addr;
}

int
pdustream_version(struct pdu_stream *stream)
{
	return stream->rtr_version;
}

void
rtreq_destroy(struct rtr_request *request)
{
	struct rtr_pdu *pdu;

	while (!STAILQ_EMPTY(&request->pdus)) {
		pdu = STAILQ_FIRST(&request->pdus);
		STAILQ_REMOVE_HEAD(&request->pdus, hook);

		if (pdu->obj.hdr.type == PDU_TYPE_ERROR_REPORT)
			free(pdu->obj.er.errmsg);
		free(pdu->raw.bytes);
		free(pdu);
	}
}

