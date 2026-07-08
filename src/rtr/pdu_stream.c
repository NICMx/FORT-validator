#include "rtr/pdu_stream.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <unistd.h>

#include "alloc.h"
#include "common.h"
#include "log.h"
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

struct pdu_header {
	enum rtr_version version;
	enum pdu_type type;
	union {
		uint16_t session_id;
		uint16_t reserved;
		uint16_t error_code;
	} m; /* Note: "m" stands for "meh." I have no idea what to call this. */
	uint32_t len;
};

struct pdu_stream *pdustream_create(int fd, char const *addr)
{
	struct pdu_stream *result = pmalloc(sizeof(struct pdu_stream));

	result->fd = fd;
	strcpy(result->addr, addr);
	result->flags = 0;
	result->rtr_version = -1;
	result->session = -1;

	result->start = result->buffer;
	result->end = result->buffer;

	return result;
}

void
pdustream_destroy(struct pdu_stream *stream)
{
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
			if (error == EAGAIN || error == EWOULDBLOCK) {
				pr_op_debug("Reached stream limit for now.");
				return BS_WOULD_BLOCK;
			} else {
				pr_op_err("Client socket read errored: %s",
				    strerror(error));
				return BS_ERROR;
			}
		}

		if (consumed == 0) {
			pr_op_debug("Client '%s' closed the socket.", in->addr);
			return BS_EOS;
		}

		pr_op_debug("Received %zd bytes from %s.", consumed, in->addr);
	}

	/*
	 * We might or might not have read everything, but we have at least one
	 * big PDU that either lengths exactly RTRPDU_MAX_LEN2, or is too big
	 * for us to to allow it.
	 */
	pr_op_debug("Stream limit not reached yet.");
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
	header->len = read_uint32(stream->start + 4);
}

static int
validate_rtr_version(struct pdu_stream *stream, struct pdu_header *hdr,
    struct rtr_buffer *request)
{
	if (stream->rtr_version == -1) {
		if (RTR_V0 <= hdr->version && hdr->version <= RTR_V2) {
			stream->rtr_version = hdr->version;
			return 0;
		}
		return err_pdu_send_unsupported_proto_version(
			stream->fd, RTR_V2, request,
			"The maximum supported RTR version is 2."
		);
	}

	if (stream->rtr_version != hdr->version)
		return err_pdu_send_unexpected_proto_version(
			stream->fd, stream->rtr_version, request,
			"The RTR version does not match the one we negotiated during the handshake."
		);

	return 0;
}

static int
load_serial_query(struct pdu_stream *stream, struct pdu_header *hdr,
    struct rtr_request *result)
{
	size_t length;

	if (hdr->len != RTRPDU_SERIAL_QUERY_LEN) {
		pr_op_err("%s: Header length is not %u: %u",
		    stream->addr, RTRPDU_SERIAL_QUERY_LEN, hdr->len);
		return err_pdu_send_invalid_request(
			stream->fd, stream->rtr_version, &result->pdu.raw,
			"Expected length 12 for Serial Query PDUs."
		);
	}

	length = get_length(stream);
	if (length < RTRPDU_SERIAL_QUERY_LEN) {
		pr_op_debug("PDU fragmented after hdr (%zu)", length);
		return EAGAIN;
	}

	pr_op_debug("Received a Serial Query from %s.", stream->addr);

	result->pdu.obj.sq.session_id = hdr->m.session_id;
	stream->start += RTR_HDR_LEN;
	result->pdu.obj.sq.serial_number = read_uint32(stream->start);
	stream->start += 4;
	return 0;
}

static int
load_reset_query(struct pdu_stream *stream, struct pdu_header *hdr,
    struct rtr_request *result)
{
	size_t length;

	if (hdr->len != RTRPDU_RESET_QUERY_LEN) {
		pr_op_err("%s: Header length is not %u: %u",
		    stream->addr, RTRPDU_RESET_QUERY_LEN, hdr->len);
		return err_pdu_send_invalid_request(
			stream->fd, stream->rtr_version, &result->pdu.raw,
			"Expected length 8 for Reset Query PDUs."
		);
	}

	length = get_length(stream);
	if (length < RTRPDU_RESET_QUERY_LEN) {
		pr_op_debug("PDU fragmented after hdr (%zu)", length);
		return EAGAIN;
	}

	pr_op_debug("Received a Reset Query from %s.", stream->addr);

	stream->start += RTR_HDR_LEN;
	return 0;
}

static void
handle_error_report_pdu(uint16_t errcode, char const *errmsg,
    char const *client_addr)
{
	if (errmsg != NULL) {
		pr_op_err("RTR client %s responded with error PDU '%s' ('%s'). Closing socket.",
		    client_addr, err_pdu_to_string(errcode), errmsg);
	} else {
		pr_op_err("RTR client %s responded with error PDU '%s'. Closing socket.",
		    client_addr, err_pdu_to_string(errcode));
	}
}


static int
load_error_report(struct pdu_stream *stream, struct pdu_header *hdr)
{
	uint32_t errpdu_len;
	uint32_t errmsg_len;
	char *errmsg;
	int error;

	if (hdr->len > RTRPDU_ERROR_REPORT_MAX_LEN) {
		return pr_op_err(
			"%s: Error Report PDU is too big (%u bytes).",
			stream->addr, hdr->len
		);
	}
	if (hdr->len < RTR_HDR_LEN + 8) { /* hdr + errpdu len + errmsg len */
		return pr_op_err(
			"%s: Error Report PDU is too small (%u bytes).",
			stream->addr, hdr->len
		);
	}

	pr_op_debug("Received an Error Report from %s.", stream->addr);

	/* Header */
	stream->start += RTR_HDR_LEN;

	/* Error PDU length */
	if (get_length(stream) < 4) {
		pr_op_debug("Fragmented on error PDU length.");
		error = EAGAIN;
		goto revert_hdr;
	}
	errpdu_len = read_uint32(stream->start);
	stream->start += 4;
	if (errpdu_len > RTRPDU_MAX_LEN) {
		/*
		 * We truncate PDUs larger than RTRPDU_MAX_LEN, so we couldn't
		 * have sent this PDU. Looks like someone is messing with us.
		 */
		error = pr_op_err(
			"%s: Error Report PDU's embedded PDU is too big (%u bytes).",
			stream->addr, errpdu_len
		);
		goto revert_errpdu_len;
	}
	if (hdr->len < RTR_HDR_LEN + 8 + errpdu_len) {
		error = pr_op_err(
			"%s: Invalid Length of Encapsulated PDU (%u); PDU length is %u.",
			stream->addr, errpdu_len, hdr->len
		);
		goto revert_errpdu_len;
	}

	/* Error PDU */
	if (get_length(stream) < errpdu_len) {
		pr_op_debug("Fragmented on error PDU.");
		error = EAGAIN;
		goto revert_errpdu_len;
	}

	stream->start += errpdu_len; /* Skip it for now; we don't use it */

	/* Error msg length */
	if (get_length(stream) < 4) {
		pr_op_debug("Fragmented on error message length.");
		error = EAGAIN;
		goto revert_errpdu;
	}
	errmsg_len = read_uint32(stream->start);
	stream->start += 4;
	if (hdr->len != rtrpdu_error_report_len(errpdu_len, errmsg_len)) {
		error = pr_op_err(
			"%s: Error Report PDU is malformed; header length is %u, but effective length is %u + %u + %u + %u + %u.",
			stream->addr, hdr->len,
			RTR_HDR_LEN, 4, errpdu_len, 4, errmsg_len
		);
		goto revert_errmsg_len;
	}

	/* Error msg */
	errmsg = read_string(stream, errmsg_len);
	stream->start += errmsg_len;

	handle_error_report_pdu(hdr->m.error_code, errmsg, stream->addr);

	free(errmsg);
	return EINVAL;

revert_errmsg_len:
	stream->start -= 4;
revert_errpdu:
	stream->start -= errpdu_len;
revert_errpdu_len:
	stream->start -= 4;
revert_hdr:
	stream->start -= RTR_HDR_LEN;
	return error;
}

static struct rtr_request *
create_request(struct pdu_stream *stream, struct pdu_header *hdr,
    struct rtr_buffer *raw)
{
	struct rtr_request *result;

	result = pmalloc(sizeof(struct rtr_request));
	result->fd = stream->fd;
	strcpy(result->client_addr, stream->addr);
	result->stream = stream;
	result->pdu.rtr_version = hdr->version;
	result->pdu.type = hdr->type;
	result->pdu.raw = *raw;

	return result;
}

static int
queue_request(struct rtr_request_list *list, struct rtr_request *req)
{
	if (TAILQ_EMPTY(&list->nodes)) {
		TAILQ_INSERT_HEAD(&list->nodes, req, lh);
		list->count++;
		return 0;
	}

	if (list->count >= 4) {
		pr_op_err("%s: Too many simultaneous requests; Dropping RTR connection.",
		    req->client_addr);
		return ENOSPC;
	}

	TAILQ_INSERT_TAIL(&list->nodes, req, lh);
	list->count++;
	return 0;
}

/*
 * Parses request stream PDUs into stream's PDU list. Does not block.
 *
 * If there is at least one Error Report, it'll induce end of stream. This is
 * because all the currently defined client-sourced Error Reports are fatal.
 * The caller does not need to concern itself with handling Error Reports.
 *
 * Returns:
 * true: Success. The list might or might not be populated; check empty.
 * false: Input stream ended or broken; handle PDUs and end connection.
 */
bool
pdustream_parse(struct pdu_stream *stream, struct rtr_request_list *reqs)
{
	enum buffer_state state;
	struct pdu_header hdr;
	struct rtr_buffer raw = { 0 };
	struct rtr_request *request;
	size_t remainder;
	int error;

again:
	state = update_buffer(stream);
	if (state == BS_ERROR)
		return false;

	while (stream->start < stream->end) {
		request = NULL;
		remainder = get_length(stream);

		/* Read header. */
		if (remainder < RTR_HDR_LEN) {
			pr_op_debug("PDU fragmented on header (%zu)", remainder);
			break; /* PDU is fragmented */
		}
		read_hdr(stream, &hdr);

		/* Init raw PDU; Needed early because of error responses. */
		raw.bytes_len = (hdr.len <= remainder) ? hdr.len : remainder;
		raw.bytes = pmalloc(raw.bytes_len);
		memcpy(raw.bytes, stream->start, raw.bytes_len);

		/* Validate length; Needs raw. */
		if (hdr.len > RTRPDU_MAX_LEN2) {
			pr_op_err("%s: Header length too big: %u > %u",
			     stream->addr, hdr.len, RTRPDU_MAX_LEN2);
			err_pdu_send_invalid_request(
				stream->fd,
				(stream->rtr_version != -1)
				    ? stream->rtr_version
				    : hdr.version,
				&raw,
				"PDU is too large."
			);
			goto fail;
		}

		/* Validate version; Needs raw. */
		if (validate_rtr_version(stream, &hdr, &raw) != 0) {
			pr_op_err("%s: Bad RTR version: %u",
			    stream->addr, hdr.version);
			goto fail;
		}

		request = create_request(stream, &hdr, &raw);
		raw.bytes = NULL; /* Ownership transferred */

		switch (hdr.type) {
		case PDU_TYPE_SERIAL_QUERY:
			error = load_serial_query(stream, &hdr, request);
			break;
		case PDU_TYPE_RESET_QUERY:
			error = load_reset_query(stream, &hdr, request);
			break;
		case PDU_TYPE_ERROR_REPORT:
			error = load_error_report(stream, &hdr);
			break;
		default:
			pr_op_err("%s: Unknown PDU type: %u",
			    stream->addr, hdr.version);
			err_pdu_send_unsupported_pdu_type(stream->fd,
			    stream->rtr_version, &request->pdu.raw);
			goto fail;
		}

		if (error == EAGAIN) {
			rtreq_destroy(request);
			break;
		} else if (error) {
			goto fail;
		}

		error = queue_request(reqs, request);
		if (error)
			goto fail;
	}

	switch (state) {
	case BS_WOULD_BLOCK:
		return true;
	case BS_KEEP_READING:
		goto again;
	case BS_EOS:
		return false;
	case BS_ERROR:
		pr_crit("This should have been catched earlier.");
	}

fail:	if (request != NULL)
		rtreq_destroy(request);
	if (raw.bytes != NULL)
		free(raw.bytes);
	return false;
}

void
pdustream_disable_read(struct pdu_stream *stream)
{
	pr_op_debug("Shutting down input stream of client %s.", stream->addr);
	PS_ENABLE(stream, EOS);
	if (shutdown(stream->fd, SHUT_RD) < 0)
		pr_op_warn("Can't shut down read end of client socket: %s",
		    strerror(errno));
}

void
rtreq_destroy(struct rtr_request *request)
{
	free(request->pdu.raw.bytes);
	free(request);
}

struct rtr_request *
rtreqlist_pop(struct rtr_request_list *reqs)
{
	struct rtr_request *req;

	req = TAILQ_FIRST(&reqs->nodes);
	if (req) {
		TAILQ_REMOVE(&reqs->nodes, req, lh);
		reqs->count--;
	}

	return req;
}

void
rtreqlist_clear(struct rtr_request_list *list)
{
	struct rtr_request *req;

	while ((req = TAILQ_FIRST(&list->nodes)) != NULL) {
		TAILQ_REMOVE(&list->nodes, req, lh);
		rtreq_destroy(req);
	}

	list->count = 0;
}
