#include "rrdp_xml.h"

#include <errno.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "base64.h"
#include "config.h"
#include "http.h"
#include "log.h"
#include "thread_var.h"

/*
 * Implementation notes:
 *
 * - The parser is a state machine. Each state reads a "phrase" (from a buffer)
 *   composed of (at most 3) tokens.
 *   The buffer is finite. This means the parser might run into incomplete
 *   tokens. When this happens, store your (at most 2) already consumed tokens
 *   into the reader backups, and return TRR_MORE. This'll result in the state
 *   being re-run later with a fuller buffer. Restore the backups and re-attempt
 *   to read the missing token.
 * - XML Processing Instructions and CDATAs are rejected.
 *   These make no sense in RRDP, and I'm hesitant to implement XML bloat that
 *   might be exploitable.
 *   The only exception is XMLDecl, which is plausible RRDP, so it's parsed
 *   normally and considered optional.
 */

/*
 * Current longest allowed full RRDP token.
 * "Full" means it excludes tokens that can be parsed in chunks, such as base64.
 *
 * In RRDP, the largest potential full tokens are attribute URIs.
 * Which can be roughly any length, but I'm guessing anything larger than this
 * is a troll.
 */
#ifndef MAX_TKN_SIZE
#define MAX_TKN_SIZE ((size_t)1024u)
#endif

/* Current longest RRDP tag/attr + 1; strlen("notification") + 1*/
#define MAX_NAME_SIZE 13

/* Needs to be fairly small, otherwise libcrypto BIGNUM lags */
#define MAX_SERIAL_SIZE 64

#define XMLDECL_TAG "?xml ?"

enum token_read_result {
	TRR_OK,   /* Token is fully parsed and so far accepted. */
	TRR_MORE, /* Token was cut-off; need next buffer chunk. */
	TRR_ERR,  /* Parse error. Document is illegible; abort. */
};

struct rrdp_xml_reader;

typedef enum token_read_result (*consume_cb)(struct rrdp_xml_reader *);
static enum token_read_result state_root_tag(struct rrdp_xml_reader *);
static enum token_read_result state_root_content(struct rrdp_xml_reader *);
static enum token_read_result state_ignore_input(struct rrdp_xml_reader *);

enum rrdp_xml_type {
	RXT_NOTIF,
	RXT_SNAPSHOT,
	RXT_DELTA,
};

/*
 * Note:
 * RFC8182 says RRDP XMLs must be "US-ASCII."
 * US-ASCII includes non-printable characters...
 * The RFC never states RRDP XMLs must be fully printable.
 * It also doesn't seem to reference any generic XML specifications,
 * that might enforce printable characters.
 * But allowing non-printable while disallowing Unicode seems farcical.
 * So I've decided to reject non-printables anyway.
 * (Except in comments. Comments can contain whatever they want.)
 */
static bool
is_printable(char chr) /* According to US-ASCII */
{
	return 0x20 <= chr && chr <= 0x7E;
}

static bool
is_alphanumeric(char chr)
{
	return ('a' <= chr && chr <= 'z')
	    || ('A' <= chr && chr <= 'Z')
	    || ('0' <= chr && chr <= '9');
}

BIGNUM *
BN_create(void)
{
	BIGNUM *result = BN_new();
	if (result == NULL)
		enomem_panic();
	return result;
}

void
serial_copy(struct rrdp_serial *to, struct rrdp_serial *from)
{
	to->num = BN_create();
	BN_copy(to->num, from->num);
	to->str = pstrdup(from->str);
}

bool
serial_equals(struct rrdp_serial *a, struct rrdp_serial *b)
{
	if (a == b)
		return true;
	if (a == NULL || b == NULL)
		return false;
	return BN_cmp(a->num, b->num) == 0;
}

int
str2serial(char const *str, struct rrdp_serial *serial)
{
	serial->num = BN_create();
	serial->str = pstrdup(str);
	if (!BN_dec2bn(&serial->num, serial->str)) {
		BN_free(serial->num);
		free(serial->str);
		return pr_err("Not a serial number: %s", str);
	}

	return 0;
}

void
serial_cleanup(struct rrdp_serial *serial)
{
	BN_free(serial->num);
	serial->num = NULL;
	free(serial->str);
	serial->str = NULL;
}

static void
rrdpid_cleanup(struct rrdp_id *meta)
{
	free(meta->session_id);
	BN_free(meta->serial.num);
	free(meta->serial.str);
}

static void
metadata_cleanup(struct file_metadata *meta)
{
	uri_cleanup(&meta->uri);
}

static void
notification_delta_cleanup(struct notification_delta *delta)
{
	serial_cleanup(&delta->serial);
	metadata_cleanup(&delta->meta);
}

static void
notification_deltas_cleanup(struct notification_deltas *deltas)
{
	array_index d;

	for (d = 0; d < deltas->len; d++)
		notification_delta_cleanup(&deltas->arr[d]);
	free(deltas->arr);
}

void
notification_cleanup(struct update_notification *notif)
{
	rrdpid_cleanup(&notif->session);
	metadata_cleanup(&notif->snapshot);
	notification_deltas_cleanup(&notif->deltas);
}

enum xml_token_type {
	XTT_OPEN_TAG,          /* <  */
	XTT_OPENING_CLOSURE,   /* </ */
	XTT_CLOSE_TAG,         /*  > */
	XTT_CLOSING_CLOSURE,   /* /> */
	XTT_DOCTYPE,           /* <!DOCTYPE */
	XTT_PI_OPEN,           /* <? */
	XTT_PI_CLOSE,          /* ?> */
	XTT_COMMENT,           /* <!-- */
	XTT_XMLDECL,           /* <?xml */
	XTT_EQUALS,
	XTT_STR,
	XTT_QUOTED,
	XTT_UNKNOWN,
};

struct xml_token {
	enum xml_token_type type;
	/* Either literal or @buf. Do not assume NULL-terminated */
	char const *str;
	size_t len;

	char buf[MAX_TKN_SIZE];
	bool complete;
};

struct rrdp_xml_reader {
	enum rrdp_xml_type type;
	char const *type_str;
	char const *type_str_camel;
	struct uri const *notif_uri;

	/* Current chunk. Contains string data, but it's not null-terminated. */
	char const *buf;
	/* Bytes not yet consumed in @buf. */
	size_t buflen;

	/* Number of line currently being parsed */
	unsigned int line;

	/*
	 * Cached first token from the current phrase.
	 * It was already consumed from @buf, but the parser performed a
	 * rollback because it reached the end of @buf before completing the
	 * phrase. So we'll need to return it the next time the parser wants
	 * the first token of the phrase.
	 */
	struct xml_token tkn1;
	/*
	 * Cached second token from the current phrase.
	 * It was already consumed from @buf, but the parser performed a
	 * rollback because it reached the end of @buf before completing the
	 * phrase. So we'll need to return it the next time the parser wants
	 * the second token of the phrase.
	 */
	struct xml_token tkn2;
	/*
	 * Cached third token from the current phrase.
	 * It was already consumed from @buf, but the parser performed a
	 * rollback because it reached the end of @buf before completing the
	 * phrase. So we'll need to return it the next time the parser wants
	 * the third token of the phrase.
	 * (RRDP phrases never exceed three tokens.)
	 */
	struct xml_token tkn3;

	consume_cb state;
	/* The state that comes after @state */
	consume_cb next_state;

/* Already parsed xmlns attribute from root tag? */
#define RXRF_XMLNS_SET      (1 << 0)
/* Already parsed version attribute from root tag? */
#define RXRF_VERSION_SET    (1 << 1)
/* Already parsed session_id attribute from root tag? */
#define RXRF_SESSION_SET    (1 << 2)
/* Already parsed serial attribute from root tag? */
#define RXRF_SERIAL_SET     (1 << 3)
/* Already parsed the XMLDecl version attribute? */
#define RXRF_XMLV_SET       (1 << 4)
/* Got UTF-8 encoding in the XMLDecl? */
#define RXRF_UTF_8          (1 << 6)
/* Didn't get US-ASCII encoding in the XMLDecl? */
#define RXRF_NOT_ASCII      (1 << 7)
/* Have we found a (non-XMLDecl) PI so far? */
#define RXRF_FOUND_PI       (1 << 8)
/* Have we confirmed that the document is RRDP? */
#define RXRF_RRDP           (1 << 9)
	int flags;

	union {
		struct {
			/* The ID from the root tag */
			struct rrdp_id id;
			/*
			 * Exclusive minimum
			 * ie. the range is (min, max].
			 * (Where max is id.serial.num.)
			 */
			BIGNUM *min_serial;

			/* Snapshot tag, already parsed */
			struct file_metadata snapshot;
			/* The delta we're currently parsing */
			struct notification_delta delta;
			/* Deltas already parsed */
			struct notification_deltas deltas;
			/* Total deltas, including the ones we discarded */
			unsigned int ndeltas;
		} notif;
		struct {
			/* This file's ID, according to the notification */
			struct rrdp_id const *notif_id;
			/* URI and hash from the current publish or withdraw */
			struct file_metadata file;
			/* Base64 consumer of the current publish */
			struct base64decode2file b64;
			/* Path to the RRDP cage where we're exploding files */
			char const *pathid;
		} sd; /* snapshot or delta */
	} c; /* type-dependent file content */

	struct files_ht *rrdp_filerefs;
	struct cache_sequence *rrdp_seq;
};

static enum token_read_result
advance_buffer(struct rrdp_xml_reader *rdr, size_t bytes)
{
	if (bytes == 0)
		return TRR_OK;

	pr_clutter("Deleted from buffer: '%.*s'", (int)bytes, rdr->buf);
	rdr->buf += bytes;
	rdr->buflen -= bytes;
	return TRR_OK;
}

/* For literals */
static enum token_read_result
token_init(struct rrdp_xml_reader *rdr, struct xml_token *tkn,
    enum xml_token_type type, char const *str, size_t len)
{
	size_t diff = len - tkn->len;

	tkn->type = type;
	tkn->str = str;
	tkn->len = len;
	tkn->complete = true;

	return advance_buffer(rdr, diff);
}

/*
 * For fluid tokens.
 *
 * n is the total length of the token, not the addend.
 *
 * ASSUMES @n IS NOT HIGHER THAN MAX_TKN_SIZE.
 */
static enum token_read_result
token_init2(struct rrdp_xml_reader *rdr, struct xml_token *tkn,
    enum xml_token_type type, size_t n)
{
	size_t diff = n - tkn->len;

	tkn->type = type;
	tkn->str = tkn->buf;
	memcpy(tkn->buf + tkn->len, rdr->buf, diff);
	tkn->len = n;
	tkn->complete = true;

	return advance_buffer(rdr, diff);
}

static void
commit_partial_token(struct rrdp_xml_reader *rdr, struct xml_token *tkn)
{
	if (tkn->complete || rdr->buflen == 0)
		return;

	tkn->str = tkn->buf;
	memcpy(tkn->buf + tkn->len, rdr->buf, rdr->buflen);
	tkn->len += rdr->buflen;

	advance_buffer(rdr, rdr->buflen);
}

static void
cleanup_sd(struct rrdp_xml_reader *rdr)
{
	metadata_cleanup(&rdr->c.sd.file);
	memset(&rdr->c.sd.file, 0, sizeof(rdr->c.sd.file));
	/* Skip the base64 decoder; it can be reused. */
	rdr->c.sd.pathid = NULL;
}

static bool
is_whitespace(char chr)
{
	return chr == ' ' || chr == '\t' || chr == '\n' || chr == '\r';
}

static enum token_read_result
get_char(struct rrdp_xml_reader *rdr, array_index offset, char *chr)
{
	if (offset >= rdr->buflen)
		return TRR_MORE;

	*chr = (char)rdr->buf[offset];
	return TRR_OK;
}

static enum token_read_result
get_char2(struct rrdp_xml_reader *rdr, struct xml_token *tkn,
    size_t offset, char *chr)
{
	if (offset < tkn->len) {
		*chr = tkn->str[offset];
		return TRR_OK;
	}

	return get_char(rdr, offset - tkn->len, chr);
}

static enum token_read_result
is_NameStartChar(char chr)
{
	return ('a' <= chr && chr <= 'z')
	    || ('A' <= chr && chr <= 'Z')
	    || chr == ':'
	    || chr == '_';
}

static enum token_read_result
is_NameChar(char chr)
{
	return is_NameStartChar(chr)
	    || ('0' <= chr && chr <= '9')
	    || chr == '-'
	    || chr == '.';
}

static enum token_read_result
find_not_NameChar(struct rrdp_xml_reader *rdr, struct xml_token *tkn,
    array_index *offset)
{
	array_index c;
	enum token_read_result res;
	char chr;

	for (c = (tkn->len > 0) ? 0 : 1; (tkn->len + c) < MAX_NAME_SIZE; c++) {
		res = get_char(rdr, c, &chr);
		if (res != TRR_OK)
			return res;
		if (!is_NameChar(chr)) {
			*offset = tkn->len + c;
			return TRR_OK;
		}
	}

	pr_err("(Line %u) Name has too many characters: %.*s%.*s(...)",
	    rdr->line, (int)tkn->len, tkn->str, (int)(c - tkn->len), rdr->buf);
	return TRR_ERR;
}

static enum token_read_result
find_chr(struct rrdp_xml_reader *rdr, struct xml_token *tkn,
    char chr, array_index *offset, unsigned int *newlines)
{
	array_index i;
	enum token_read_result res;
	char next;

	for (i = (tkn->len > 0) ? 0 : 1; (tkn->len + i) < MAX_TKN_SIZE; i++) {
		res = get_char(rdr, i, &next);
		if (res != TRR_OK)
			return res;
		if (next == chr) {
			*offset = tkn->len + i;
			return TRR_OK;
		}
		if (next == '\n')
			(*newlines)++;
	}

	pr_err("(Line %u) Attribute value too long", rdr->line);
	return TRR_ERR;
}

static bool
tkn_equals(struct xml_token *tkn, char const *str)
{
	return (strlen(str) == tkn->len)
	    ? (strncmp(tkn->str, str, tkn->len) == 0)
	    : false;
}

static bool
tkn_case_equals(struct xml_token *tkn, char const *str)
{
	return (strlen(str) == tkn->len)
	    ? (strncasecmp(tkn->str, str, tkn->len) == 0)
	    : false;
}

static enum token_read_result
unexpected_tkn(struct rrdp_xml_reader *rdr, char const *pfx, char chr)
{
	if (is_printable(chr))
		pr_err("(Line %u) Unexpected token: '%s%c'",
		    rdr->line, pfx, chr);
	else
		pr_err("(Line %u) Unexpected character: 0x%02x",
		    rdr->line, (unsigned char)chr);
	return TRR_ERR;
}

static enum token_read_result
unexpected_chr(struct rrdp_xml_reader *rdr, char chr)
{
	if (is_printable(chr))
		pr_err("(Line %u) Unexpected character: '%c'",
		    rdr->line, chr);
	else
		pr_err("(Line %u) Unexpected character: 0x%02x",
		    rdr->line, (unsigned char)chr);
	return TRR_ERR;
}

/* Advances rdr->offset into the next non-whitespace character */
static enum token_read_result
find_non_whitespace(struct rrdp_xml_reader *rdr)
{
	size_t offset;

	for (offset = 0; offset < rdr->buflen; offset++) {
		if (rdr->buf[offset] == '\n')
			rdr->line++;
		if (!is_whitespace(rdr->buf[offset]))
			return advance_buffer(rdr, offset);
	}

	advance_buffer(rdr, offset);
	return TRR_MORE;
}

static enum token_read_result
init_quote(struct rrdp_xml_reader *rdr, struct xml_token *tkn, char delimiter)
{
	size_t tail;
	unsigned int newlines;
	enum token_read_result res;

	newlines = 0;

	res = find_chr(rdr, tkn, delimiter, &tail, &newlines);
	if (res != TRR_OK)
		return res;

	rdr->line += newlines; /* Only if TRR_OK */

	return token_init2(rdr, tkn, XTT_QUOTED, tail + 1);
}

static enum token_read_result
expect_meta(struct rrdp_xml_reader *rdr, struct xml_token *tkn,
    enum xml_token_type type, char const *str, bool need_whitespace)
{
	array_index offset;
	char chr;
	enum token_read_result res;

	for (offset = 3u; str[offset]; offset++) {
		res = get_char2(rdr, tkn, offset, &chr);
		if (res != TRR_OK)
			return res;
		if (chr != str[offset])
			goto unexpected;
	}

	if (need_whitespace) {
		res = get_char2(rdr, tkn, offset, &chr);
		if (res != TRR_OK)
			return res;
		if (!is_whitespace(chr))
			goto unexpected;
	}

	return token_init(rdr, tkn, type, str, offset);

unexpected:
	pr_err("(Line %u) Unexpected token: '%.*s%.*s'", rdr->line,
	    (int)tkn->len, tkn->str, (int)(offset - tkn->len + 1u), rdr->buf);
	return TRR_ERR;
}

static enum token_read_result
next_metadata(struct rrdp_xml_reader *rdr, struct xml_token *tkn)
{
	char chr;
	enum token_read_result res;

	res = get_char2(rdr, tkn, 2u, &chr);
	if (res != TRR_OK)
		return res;

	switch (chr) {
	case '-': return expect_meta(rdr, tkn, XTT_COMMENT, "<!--", false);
	case 'D': return expect_meta(rdr, tkn, XTT_DOCTYPE, "<!DOCTYPE", true);
	default:  return unexpected_tkn(rdr, "<!", chr);
	}
}

static enum token_read_result
next_pi(struct rrdp_xml_reader *rdr, struct xml_token *tkn)
{
	static char const *const XMLDECL = "<?xml";
	array_index offset;
	char chr;
	enum token_read_result res;

	for (offset = 2u; XMLDECL[offset]; offset++) {
		res = get_char2(rdr, tkn, offset, &chr);
		if (res != TRR_OK)
			return res;
		if (chr != XMLDECL[offset])
			goto found_pi;
	}

	res = get_char2(rdr, tkn, offset, &chr);
	if (res != TRR_OK)
		return res;
	if (!is_whitespace(chr))
		goto found_pi;

	return token_init(rdr, tkn, XTT_XMLDECL, "<?xml", 5u);

found_pi:
	return token_init(rdr, tkn, XTT_PI_OPEN, "<?", 2u);
}

static enum token_read_result
next_tkn_chunk(struct rrdp_xml_reader *rdr, struct xml_token *tkn)
{
	char chr;
	size_t tail;
	enum token_read_result res;

	if (tkn->len == 0) {
		res = find_non_whitespace(rdr);
		if (res != TRR_OK)
			return res;
	}

	res = get_char2(rdr, tkn, 0, &chr);
	if (res != TRR_OK)
		return res;

	switch (chr) {
	case '<':
		res = get_char2(rdr, tkn, 1u, &chr);
		if (res != TRR_OK)
			return res;
		switch (chr) {
		case '/': return token_init(rdr, tkn, XTT_OPENING_CLOSURE, "</", 2u);
		case '!': return next_metadata(rdr, tkn);
		case '?': return next_pi(rdr, tkn);
		}
		return token_init(rdr, tkn, XTT_OPEN_TAG, "<", 1u);

	case '/':
		res = get_char2(rdr, tkn, 1u, &chr);
		if (res != TRR_OK)
			return res;
		if (chr != '>')
			return unexpected_tkn(rdr, "/", chr);
		return token_init(rdr, tkn, XTT_CLOSING_CLOSURE, "/>", 2);

	case '>':
		return token_init(rdr, tkn, XTT_CLOSE_TAG, ">", 1);

	case '=':
		return token_init(rdr, tkn, XTT_EQUALS, "=", 1);

	case '?':
		res = get_char2(rdr, tkn, 1u, &chr);
		if (res != TRR_OK)
			return res;
		if (chr != '>')
			return unexpected_tkn(rdr, "?", chr);
		return token_init(rdr, tkn, XTT_PI_CLOSE, "?>", 2);
	}

	if (!is_NameStartChar(chr))
		return unexpected_chr(rdr, chr);

	res = find_not_NameChar(rdr, tkn, &tail);
	if (res != TRR_OK)
		return res;

	return token_init2(rdr, tkn, XTT_STR, tail);
}

static enum token_read_result
next_tkn(struct rrdp_xml_reader *rdr, struct xml_token *tkn)
{
	enum token_read_result res;

	if (tkn->complete)
		return TRR_OK;

	res = next_tkn_chunk(rdr, tkn);
	if (res == TRR_OK)
		pr_clutter("Consumed token: '%.*s'", (int)tkn->len, tkn->str);

	return res;
}

static enum token_read_result
check_tkn_type(struct rrdp_xml_reader *rdr, struct xml_token *tkn,
    enum xml_token_type type, char const *what)
{
	if (tkn->type != type) {
		pr_err("(Line %u) Expected %s, got '%.*s'",
		    rdr->line, what, (int)tkn->len, tkn->str);
		return TRR_ERR;
	}

	return TRR_OK;
}

static enum token_read_result
bad_tkn_type(struct rrdp_xml_reader *rdr, struct xml_token *tkn,
    char const *what)
{
	pr_err("(Line %u) Expected %s, got '%.*s'",
	    rdr->line, what, (int)tkn->len, tkn->str);
	return TRR_ERR;
}

static enum token_read_result
next_tkn_type(struct rrdp_xml_reader *rdr, struct xml_token *tkn,
    enum xml_token_type type, char const *what)
{
	enum token_read_result res;

	res = next_tkn(rdr, tkn);
	if (res != TRR_OK)
		return res;
	return check_tkn_type(rdr, tkn, type, what);
}

static enum token_read_result
next_str(struct rrdp_xml_reader *rdr, struct xml_token *tkn)
{
	enum token_read_result res;

	res = next_tkn(rdr, tkn);
	if (res != TRR_OK)
		return res;
	return check_tkn_type(rdr, tkn, XTT_STR, "string");
}

static enum token_read_result
next_name(struct rrdp_xml_reader *rdr, struct xml_token *tkn, char const *str)
{
	enum token_read_result res;

	res = next_tkn(rdr, tkn);
	if (res != TRR_OK)
		return res;

	if (tkn->type != XTT_STR || !tkn_equals(tkn, str)) {
		pr_err("(Line %u) Expected name '%s', got '%.*s'",
		    rdr->line, str, (int)tkn->len, tkn->str);
		return TRR_ERR;
	}

	return TRR_OK;
}

static enum token_read_result
next_quoted(struct rrdp_xml_reader *rdr, struct xml_token *tkn)
{
	char chr;
	enum token_read_result res;

	if (tkn->len == 0) {
		res = find_non_whitespace(rdr);
		if (res != TRR_OK)
			return res;
	}

	res = get_char2(rdr, tkn, 0, &chr);
	if (res != TRR_OK)
		return res;

	switch (chr) {
	case '"':  res = init_quote(rdr, tkn, '"'); break;
	case '\'': res = init_quote(rdr, tkn, '\''); break;
	default:   return unexpected_chr(rdr, chr);
	}

	if (res == TRR_OK) {
		tkn->str++;
		tkn->len -= 2;
	}
	return res;
}

static enum token_read_result
fail_unexpected_token(struct rrdp_xml_reader *rdr, struct xml_token *actual)
{
	pr_err("(Line %u) Unexpected token: %.*s",
	    rdr->line, (int)actual->len, actual->str);
	return TRR_ERR;
}

static enum token_read_result
fail_missing_attr(struct rrdp_xml_reader *rdr, char const *tag,
    char const *attr)
{
	pr_err("(Line %u) <%s> is missing the '%s' attribute.",
	    rdr->line, tag, attr);
	return TRR_ERR;
}

static enum token_read_result
fail_unknown_attr(struct rrdp_xml_reader *rdr, char const *tag,
    struct xml_token *tkn)
{
	pr_err("(Line %u) Unknown <%s> attribute: %.*s",
	    rdr->line, tag, (int)tkn->len, tkn->str);
	return TRR_ERR;
}

static enum token_read_result
fail_attr_value(struct rrdp_xml_reader *rdr, char const *tag, char const *attr,
    char const *expected, struct xml_token *actual)
{
	pr_err("(Line %u) <%s> %s is not %s: %.*s",
	    rdr->line, tag, attr, expected, (int)actual->len, actual->str);
	return TRR_ERR;
}

static enum token_read_result
fail_multiple_attrs(struct rrdp_xml_reader *rdr, char const *tag,
    char const *attr)
{
	pr_err("(Line %u) <%s> has multiple '%s' attributes.",
	    rdr->line, tag, attr);
	return TRR_ERR;
}

static enum token_read_result
state_ignore_input(struct rrdp_xml_reader *rdr)
{
	pr_clutter("== State: ignore_input == ");
	return advance_buffer(rdr, rdr->buflen);
}

static char
get_char3(struct rrdp_xml_reader *rdr, struct xml_token *tkn, array_index i)
{
	return (i < tkn->len) ? tkn->str[i] : rdr->buf[i - tkn->len];
}

/*
 * TODO (fiiiiine) Extensible Markup Language (XML) 1.0 (Fifth Edition):
 *
 * > Note that the grammar does not allow a comment ending in --->.
 * > The following example is not well-formed.
 * >
 * > 	<!-- B+, B, or B--->
 *
 * This function does not reject the above.
 */
static enum token_read_result
state_throw_away_comment(struct rrdp_xml_reader *rdr)
{
	char chr;
	array_index i;
	size_t n;

	pr_clutter("== State: throw_away_comment ==");

	if (rdr->tkn1.len > 2u) {
		memmove(rdr->tkn1.buf, rdr->tkn1.buf + rdr->tkn1.len - 2u, 2u);
		rdr->tkn1.len = 2u;
	}

	n = rdr->tkn1.len + rdr->buflen;
	if (n < 3u)
		return TRR_MORE;

	for (i = 0; i <= n - 3u; i++) {
		chr = get_char3(rdr, &rdr->tkn1, i);
		if (chr != '-') {
			if (chr == '\n')
				rdr->line++;
			continue;
		}
		if (get_char3(rdr, &rdr->tkn1, i + 1u) != '-')
			continue;
		if (get_char3(rdr, &rdr->tkn1, i + 2u) != '>')
			continue;

		rdr->state = rdr->next_state;
		return advance_buffer(rdr, i + 3u - rdr->tkn1.len);
	}

	advance_buffer(rdr , i - 1u);
	return TRR_MORE;
}

static enum token_read_result
state_throw_away_pi(struct rrdp_xml_reader *rdr)
{
	char chr;
	array_index i;
	size_t n;

	pr_clutter("== State: throw_away_pi ==");
	rdr->flags |= RXRF_FOUND_PI;

	if (rdr->tkn1.len > 1u) {
		rdr->tkn1.buf[0] = rdr->tkn1.buf[rdr->tkn1.len - 1];
		rdr->tkn1.len = 1u;
	}

	n = rdr->tkn1.len + rdr->buflen;
	if (n < 2u)
		return TRR_MORE;

	for (i = 0; i <= n - 2u; i++) {
		chr = get_char3(rdr, &rdr->tkn1, i);
		if (chr != '?') {
			if (chr == '\n')
				rdr->line++;
			continue;
		}
		if (get_char3(rdr, &rdr->tkn1, i + 1u) != '>')
			continue;

		rdr->state = rdr->next_state;
		return advance_buffer(rdr, i + 2u - rdr->tkn1.len);
	}

	advance_buffer(rdr , i - 1u);
	return TRR_MORE;
}

static enum token_read_result
init_serial(struct rrdp_xml_reader *rdr, struct rrdp_serial *serial,
    struct xml_token *tkn, char const *what)
{
	char *str;
	BIGNUM *num;

	if (tkn->len > MAX_SERIAL_SIZE) {
		pr_err("(Line %u) <%s> serial is too long: %zu chars",
		    rdr->line, what, tkn->len);
		return TRR_ERR;
	}

	str = pstrndup(tkn->str, tkn->len);
	num = BN_create();

	if (BN_dec2bn(&num, str) == 0) {
		pr_err("(Line %u) Not a number: %s", rdr->line, str);
		goto fail;
	}
	if (BN_is_negative(num)) {
		pr_err("(Line %u) Negative serial: %s", rdr->line, str);
		goto fail;
	}

	serial->str = str;
	serial->num = num;
	return TRR_OK;

fail:	free(str);
	BN_free(num);
	return TRR_ERR;
}

static enum token_read_result
init_min_serial(struct rrdp_xml_reader *rdr)
{
	BIGNUM *min;

	min = BN_create();
	if (!BN_copy(min, rdr->c.notif.id.serial.num)) {
		pr_err("(Line %u) Cannot copy serial: Unknown error",
		    rdr->line);
		goto fail;
	}
	if (!BN_sub_word(min, config_get_rrdp_delta_threshold())) {
		pr_err("(Line %u) Cannot subtract serial: Unknown error",
		    rdr->line);
		goto fail;
	}
	if (BN_is_negative(min) && !BN_set_word(min, 0)) {
		pr_err("(Line %u) Cannot assign 0 to serial: Unknown error",
		    rdr->line);
		goto fail;
	}

	rdr->c.notif.min_serial = min;
	return TRR_OK;

fail:	BN_free(min);
	return TRR_ERR;
}

static enum token_read_result
init_deltas_array(struct rrdp_xml_reader *rdr)
{
	BIGNUM *delta;

	delta = BN_create();
	if (!BN_sub(delta, rdr->c.notif.id.serial.num, rdr->c.notif.min_serial)) {
		pr_err("(Line %u) Cannot subtract BIGNUMs: Generic error",
		    rdr->line);
		return TRR_ERR;
	}
	if (BN_is_negative(delta))
		pr_panic("max serial - min serial = negative.");

	rdr->c.notif.deltas.cap = BN_get_word(delta);
	rdr->c.notif.deltas.arr = pcalloc(rdr->c.notif.deltas.cap,
	    sizeof(struct notification_delta));

	BN_free(delta);
	return TRR_OK;
}

static enum token_read_result
init_uri(struct rrdp_xml_reader *rdr, struct uri *uri, struct xml_token *tkn)
{
	array_index u;
	char *uristr;
	error_msg errmsg;

	for (u = 0; u < tkn->len; u++)
		if (!is_printable(tkn->str[u])) {
			pr_err("(Line %u) uri has illegal character: 0x%02x",
			    rdr->line, (unsigned char)(tkn->str[u]));
			return TRR_ERR;
		}

	/* TODO (performance) this dupe shouldn't be necessary */
	uristr = pstrndup(tkn->str, tkn->len);
	errmsg = uri_init(uri, uristr);
	free(uristr);

	if (errmsg) {
		pr_err("(Line %u) '%.*s' is not a valid URI: %s",
		    rdr->line, (int)tkn->len, tkn->str, errmsg);
		return TRR_ERR;
	}

	return TRR_OK;
}

static enum token_read_result
init_notif_uri(struct rrdp_xml_reader *rdr, struct uri *uri,
    struct xml_token *tkn, char const *what)
{
	enum token_read_result res;

	res = init_uri(rdr, uri, tkn);
	if (res != TRR_OK)
		return res;

	if (!uri_same_origin(rdr->notif_uri, uri)) {
		pr_err("(Line %u) Notification '%s' does not have the same origin as its %s: %s",
		    rdr->line, uri_str(rdr->notif_uri), what, uri_str(uri));
		return TRR_ERR;
	}

	return TRR_OK;
}

static enum token_read_result
init_hash(struct rrdp_xml_reader *rdr, struct file_metadata *file,
    struct xml_token *tkn)
{
	if (str2hash(tkn->str, tkn->len, &file->hash) != 0) {
		pr_err("(Line %u) Not a valid hash: %.*s",
		    rdr->line, (int)tkn->len, tkn->str);
		return TRR_ERR;
	}

	return TRR_OK;
}

static enum token_read_result
commit_serial(struct rrdp_xml_reader *rdr)
{
	struct notification_delta *src;
	struct notification_delta *dst;

	src = &rdr->c.notif.delta;

	/* if this serial > max serial */
	if (BN_cmp(src->serial.num, rdr->c.notif.id.serial.num) > 0) {
		pr_err("(Line %u) Delta serial %s is larger than Notification serial %s",
		    rdr->line, src->serial.str, rdr->c.notif.id.serial.str);
		return TRR_ERR;
	}

	/* if this serial <= min serial */
	if (BN_cmp(src->serial.num, rdr->c.notif.min_serial) <= 0) {
		/* We won't need it; discard. */
		notification_delta_cleanup(src);
		goto done;
	}

	if (rdr->c.notif.deltas.len >= rdr->c.notif.deltas.cap) {
		/*
		 * The notification has more than delta_threshold deltas whose
		 * serials satisfy min < serial <= max.
		 * (Where max - min == delta_threshold.)
		 */
		pr_err("The Notification has duplicate delta serials");
		return TRR_ERR;
	}

	dst = &rdr->c.notif.deltas.arr[rdr->c.notif.deltas.len++];
	memcpy(dst, src, sizeof(*src));
done:	memset(src, 0, sizeof(*src));
	return TRR_OK;
}

static enum token_read_result
attr_boilerplate(struct rrdp_xml_reader *rdr)
{
	enum token_read_result res;

	res = check_tkn_type(rdr, &rdr->tkn1, XTT_STR, "name");
	if (res != TRR_OK)
		return res;
	res = next_tkn_type(rdr, &rdr->tkn2, XTT_EQUALS, "equals");
	if (res != TRR_OK)
		return res;
	return next_quoted(rdr, &rdr->tkn3);
}

static enum token_read_result
state_notif_snapshot_attrs(struct rrdp_xml_reader *rdr)
{
	char const *const TAG = "snapshot";
	struct xml_token *key, *val;
	enum token_read_result res;

	pr_clutter("== State: notif_snapshot_attrs ==");

	res = next_tkn(rdr, &rdr->tkn1);
	if (res != TRR_OK)
		return res;
	key = &rdr->tkn1;

	if (key->type == XTT_CLOSING_CLOSURE) {
		if (uri_str(&rdr->c.notif.snapshot.uri) == NULL)
			return fail_missing_attr(rdr, TAG, "uri");
		if (!rdr->c.notif.snapshot.hash.set)
			return fail_missing_attr(rdr, TAG, "hash");

		rdr->state = state_root_content;
		return res;
	}

	res = attr_boilerplate(rdr);
	if (res != TRR_OK)
		return res;
	val = &rdr->tkn3;

	if (tkn_equals(key, "uri")) {
		return uri_str(&rdr->c.notif.snapshot.uri)
		    ? fail_multiple_attrs(rdr, TAG, "uri")
		    : init_notif_uri(rdr, &rdr->c.notif.snapshot.uri, val, "Snapshot");

	} else if (tkn_equals(key, "hash")) {
		return rdr->c.notif.snapshot.hash.set
		    ? fail_multiple_attrs(rdr, TAG, "hash")
		    : init_hash(rdr, &rdr->c.notif.snapshot, val);
	}

	return fail_unknown_attr(rdr, TAG, key);
}

static enum token_read_result
state_notif_delta_attrs(struct rrdp_xml_reader *rdr)
{
	char const *const TAG = "delta";
	struct xml_token *key, *val;
	enum token_read_result res;

	pr_clutter("== State: notif_delta_attrs ==");

	res = next_tkn(rdr, &rdr->tkn1);
	if (res != TRR_OK)
		return res;
	key = &rdr->tkn1;

	if (key->type == XTT_CLOSING_CLOSURE) {
		if (rdr->c.notif.delta.serial.str == NULL)
			return fail_missing_attr(rdr, TAG, "serial");
		if (uri_str(&rdr->c.notif.delta.meta.uri) == NULL)
			return fail_missing_attr(rdr, TAG, "uri");
		if (!rdr->c.notif.delta.meta.hash.set)
			return fail_missing_attr(rdr, TAG, "hash");

		res = commit_serial(rdr);
		if (res != TRR_OK)
			return res;

		rdr->c.notif.ndeltas++;
		rdr->state = state_root_content;
		return res;
	}

	res = attr_boilerplate(rdr);
	if (res != TRR_OK)
		return res;
	val = &rdr->tkn3;

	if (tkn_equals(key, "serial")) {
		if (rdr->c.notif.delta.serial.str != NULL)
			return fail_multiple_attrs(rdr, TAG, "serial");
		return init_serial(rdr, &rdr->c.notif.delta.serial, val, TAG);

	} else if (tkn_equals(key, "uri")) {
		return uri_str(&rdr->c.notif.delta.meta.uri)
		    ? fail_multiple_attrs(rdr, TAG, "uri")
		    : init_notif_uri(rdr, &rdr->c.notif.delta.meta.uri, val, "Delta");

	} else if (tkn_equals(key, "hash")) {
		return rdr->c.notif.delta.meta.hash.set
		    ? fail_multiple_attrs(rdr, TAG, "hash")
		    : init_hash(rdr, &rdr->c.notif.delta.meta, val);
	}

	return fail_unknown_attr(rdr, TAG, key);
}

static enum token_read_result
state_publish_closure(struct rrdp_xml_reader *rdr)
{
	enum token_read_result res;

	pr_clutter("== State: publish_closure ==");

	res = next_name(rdr, &rdr->tkn1, "publish");
	if (res != TRR_OK)
		return res;
	res = next_tkn_type(rdr, &rdr->tkn2, XTT_CLOSE_TAG, "close tag");
	if (res != TRR_OK)
		return res;

	rdr->state = state_root_content;
	return TRR_OK;
}

/* Steals @rdr->c.sd.b64.filename. */
static void
register_fileref(struct rrdp_xml_reader *rdr, unsigned char *hash)
{
	if (rdr->c.sd.b64.filename == NULL)
		return;

	filerefs_add_uri(
		rdr->rrdp_filerefs,
		cachefile_create(
			&rdr->c.sd.file.uri,
			rdr->c.sd.b64.filename,
			rdr->c.sd.pathid,
			hash
		),
		0
	);

	rdr->c.sd.b64.filename = NULL;
}

static bool
is_base64Binary(char chr)
{
	return ('A' <= chr && chr <= 'Z')
	    || ('a' <= chr && chr <= 'z')
	    || ('0' <= chr && chr <= '9')
	    || chr == '+' || chr == '/' || chr == '=';
}

/* TODO remember to set up a file size limit */
static enum token_read_result
state_publish_content(struct rrdp_xml_reader *rdr)
{
	enum token_read_result res;
	char chr;
	unsigned char hash[EVP_MAX_MD_SIZE];
	array_index i;

	pr_clutter("== State: publish_content ==");

	res = find_non_whitespace(rdr);
	if (res != TRR_OK)
		return res;

	chr = rdr->buf[0];
	if (chr == '<') {
		res = get_char(rdr, 1, &chr);
		if (res != TRR_OK)
			return res;
		switch (chr) {
		case '/':
			if (b64d2f_finish(&rdr->c.sd.b64, hash) != 0)
				return TRR_ERR;
			register_fileref(rdr, hash);
			cleanup_sd(rdr);

			rdr->state = state_publish_closure;
			return advance_buffer(rdr, 2u);
		case '!':
			res = next_metadata(rdr, &rdr->tkn1);
			if (res != TRR_OK)
				return res;
			if (rdr->tkn1.type != XTT_COMMENT)
				return fail_unexpected_token(rdr, &rdr->tkn1);

			rdr->state = state_throw_away_comment;
			rdr->next_state = state_publish_content;
			return TRR_OK;
		default:
			return unexpected_tkn(rdr, "", chr);
		}
	}

	if (!is_base64Binary(chr)) {
		if (is_printable(chr))
			pr_err("(Line %u) Unrecognized base64 char: %c",
			    rdr->line, chr);
		else
			pr_err("(Line %u) Unrecognized base64 char: 0x%02x",
			    rdr->line, (unsigned char)chr);
		return TRR_ERR;
	}

	for (i = 1; i < rdr->buflen; i++)
		if (!is_base64Binary(rdr->buf[i]))
			break;
	if (b64d2f_write(&rdr->c.sd.b64, rdr->buf, i) != 0)
		return TRR_ERR;

	return advance_buffer(rdr, i);
}

static bool
is_known_extension(struct uri const *uri)
{
	size_t len;
	char const *ext;

	len = uri_len(uri);
	if (len < 4)
		return false;

	ext = uri_str(uri) + len - 4;
	return ((strcmp(ext, ".cer") == 0)
	     || (strcmp(ext, ".roa") == 0)
	     || (strcmp(ext, ".mft") == 0)
	     || (strcmp(ext, ".crl") == 0)
	     || (strcmp(ext, ".gbr") == 0));
}

static int
validate_hash2(struct rrdp_xml_reader *rdr, struct file_metadata *meta,
    unsigned char const *hash)
{
	if (memcmp(meta->hash.bytes, hash, SHA256_DIGEST_LENGTH) != 0)
		goto bad;
	return 0;

bad:	return pr_err("(Line %u) File '%s' does not match its expected hash.",
	    rdr->line, uri_str(&meta->uri));
}

static enum token_read_result
validate_hash(struct rrdp_xml_reader *rdr)
{
	struct cache_file_ref *fileref;

	fileref = filerefs_find_uri(rdr->rrdp_filerefs, &rdr->c.sd.file.uri);

	/* rfc8181#section-2.2 */
	if (fileref) {
		if (!rdr->c.sd.file.hash.set) {
			// XXX watch out for this in the log before release
			pr_err("(Line %u) RRDP desync: "
			    "<publish> is attempting to create '%s', "
			    "but the file is already cached.",
			    rdr->line, uri_str(&rdr->c.sd.file.uri));
			return TRR_ERR;
		}

		if (validate_hash2(rdr, &rdr->c.sd.file, fileref->file->hash) != 0)
			return TRR_ERR;

		HASH_DEL(rdr->rrdp_filerefs->ht, fileref);
		fileref_free(fileref, true);

	} else {
		if (rdr->c.sd.file.hash.set) {
			// XXX watch out for this in the log before release
			pr_err("(Line %u) RRDP desync: "
			    "<publish> is attempting to overwrite '%s', "
			    "but the file is absent in the cache.",
			    rdr->line, uri_str(&rdr->c.sd.file.uri));
			return TRR_ERR;
		}
	}

	return TRR_OK;
}

static enum token_read_result
start_publish(struct rrdp_xml_reader *rdr)
{
	char *filename;
	enum token_read_result res;

	if (!is_known_extension(&rdr->c.sd.file.uri))
		return TRR_OK; /* Mirror rsync filters */

	res = validate_hash(rdr);
	if (res != TRR_OK)
		return res;
	filename = cseq_next(rdr->rrdp_seq, &rdr->c.sd.pathid);
	if (!filename)
		return TRR_ERR;
	if (b64d2f_init(&rdr->c.sd.b64, filename) != 0)
		return TRR_ERR;

	return TRR_OK;
}

static enum token_read_result
state_publish_attrs(struct rrdp_xml_reader *rdr)
{
	char const *const TAG = "publish";
	struct xml_token *key, *val;
	enum token_read_result res;

	pr_clutter("== State: publish_attrs ==");

	res = next_tkn(rdr, &rdr->tkn1);
	if (res != TRR_OK)
		return res;
	key = &rdr->tkn1;

	if (key->type == XTT_CLOSE_TAG) {
		if (uri_str(&rdr->c.sd.file.uri) == NULL)
			return fail_missing_attr(rdr, TAG, "uri");

		res = start_publish(rdr);
		if (res != TRR_OK)
			return res;

		rdr->state = state_publish_content;
		return TRR_OK;
	}

	res = attr_boilerplate(rdr);
	if (res != TRR_OK)
		return res;
	val = &rdr->tkn3;

	if (tkn_equals(key, "uri")) {
		return uri_str(&rdr->c.sd.file.uri)
		    ? fail_multiple_attrs(rdr, TAG, "uri")
		    : init_uri(rdr, &rdr->c.sd.file.uri, val);

	} else if (rdr->type == RXT_DELTA && tkn_equals(key, "hash")) {
		return rdr->c.sd.file.hash.set
		    ? fail_multiple_attrs(rdr, TAG, "hash")
		    : init_hash(rdr, &rdr->c.sd.file, val);
	}

	return fail_unknown_attr(rdr, TAG, key);
}

static enum token_read_result
run_withdraw(struct rrdp_xml_reader *rdr)
{
	struct cache_file_ref *fileref;

	if (!is_known_extension(&rdr->c.sd.file.uri))
		return TRR_OK; /* Mirror rsync filters */

	fileref = filerefs_find_uri(rdr->rrdp_filerefs, &rdr->c.sd.file.uri);

	if (!fileref) {
		pr_err("(Line %u) Broken RRDP: "
		    "<withdraw> is attempting to delete unknown file '%s'.",
		    rdr->line, uri_str(&rdr->c.sd.file.uri));
		return TRR_ERR;
	}

	if (validate_hash2(rdr, &rdr->c.sd.file, fileref->file->hash) != 0)
		return TRR_ERR;

	HASH_DEL(rdr->rrdp_filerefs->ht, fileref);
	fileref_free(fileref, true);
	return TRR_OK;
}

static enum token_read_result
state_withdraw_attrs(struct rrdp_xml_reader *rdr)
{
	char const *const TAG = "withdraw";
	struct xml_token *key, *val;
	enum token_read_result res;

	pr_clutter("== State: withdraw_attrs ==");

	res = next_tkn(rdr, &rdr->tkn1);
	if (res != TRR_OK)
		return res;
	key = &rdr->tkn1;

	if (key->type == XTT_CLOSING_CLOSURE) {
		if (uri_str(&rdr->c.sd.file.uri) == NULL)
			return fail_missing_attr(rdr, TAG, "uri");
		if (!rdr->c.sd.file.hash.set)
			return fail_missing_attr(rdr, TAG, "hash");

		res = run_withdraw(rdr);
		if (res != TRR_OK)
			return res;

		cleanup_sd(rdr);
		rdr->state = state_root_content;
		return res;
	}

	res = attr_boilerplate(rdr);
	if (res != TRR_OK)
		return res;
	val = &rdr->tkn3;

	if (tkn_equals(key, "uri")) {
		return uri_str(&rdr->c.sd.file.uri)
		    ? fail_multiple_attrs(rdr, TAG, "uri")
		    : init_uri(rdr, &rdr->c.sd.file.uri, val);

	} else if (tkn_equals(key, "hash")) {
		return rdr->c.sd.file.hash.set
		    ? fail_multiple_attrs(rdr, TAG, "hash")
		    : init_hash(rdr, &rdr->c.sd.file, val);
	}

	return fail_unknown_attr(rdr, TAG, key);
}

static enum token_read_result
state_root_content(struct rrdp_xml_reader *rdr)
{
	enum token_read_result res;

	pr_clutter("== State: root_content ==");

	res = next_tkn(rdr, &rdr->tkn1);
	if (res != TRR_OK)
		return res;

	switch (rdr->tkn1.type) {
	case XTT_OPEN_TAG:
		break;

	case XTT_OPENING_CLOSURE:
		res = next_name(rdr, &rdr->tkn2, rdr->type_str);
		if (res != TRR_OK)
			return res;
		res = next_tkn_type(rdr, &rdr->tkn3, XTT_CLOSE_TAG, "close tag");
		if (res != TRR_OK)
			return res;

		if (rdr->type == RXT_NOTIF &&
		    uri_str(&rdr->c.notif.snapshot.uri) == NULL) {
			pr_err("Notification lacks a Snapshot");
			return TRR_ERR;
		}

		rdr->state = state_ignore_input;
		return TRR_OK;

	case XTT_COMMENT:
		rdr->state = state_throw_away_comment;
		rdr->next_state = state_root_content;
		return TRR_OK;

	default:
		return bad_tkn_type(rdr, &rdr->tkn1, "<");
	}

	res = next_str(rdr, &rdr->tkn2);
	if (res != TRR_OK)
		return res;

	switch (rdr->type) {
	case RXT_NOTIF:
		if (tkn_equals(&rdr->tkn2, "snapshot")) {
			rdr->state = state_notif_snapshot_attrs;
			return TRR_OK;
		}
		if (tkn_equals(&rdr->tkn2, "delta")) {
			rdr->state = state_notif_delta_attrs;
			return TRR_OK;
		}
		break;

	case RXT_SNAPSHOT:
		if (tkn_equals(&rdr->tkn2, "publish")) {
			rdr->state = state_publish_attrs;
			return TRR_OK;
		}
		break;

	case RXT_DELTA:
		if (tkn_equals(&rdr->tkn2, "publish")) {
			rdr->state = state_publish_attrs;
			return TRR_OK;
		}
		if (tkn_equals(&rdr->tkn2, "withdraw")) {
			rdr->state = state_withdraw_attrs;
			return TRR_OK;
		}
		break;
	}

	return fail_unexpected_token(rdr, &rdr->tkn2);
}

static enum token_read_result
confirm_rrdp(struct rrdp_xml_reader *rdr)
{
	if (rdr->flags & RXRF_RRDP)
		return TRR_OK;

	if (rdr->flags & RXRF_FOUND_PI) {
		pr_err("Document has at least one Processing Instruction (<? ... ?>).");
		return TRR_ERR;
	}

	/*
	 * This is probably going to be common (among documents that contain an
	 * XMLDecl), but inoffensive. Warn rather than reject.
	 */
	if (rdr->flags & RXRF_UTF_8) {
		/*
		 * Note: Comments are thrown away without checking, so those
		 * can actually contain unicodes. Whatever.
		 */
		pr_wrn("%s should declare US-ASCII encoding, not UTF-8. "
		    "I'll let this slide for now, "
		    "but will reject the document if I find non-ASCII chars.",
		    rdr->type_str_camel);
		goto done;
	}

	if (rdr->flags & RXRF_NOT_ASCII) {
		pr_err("The XML encoding is not US-ASCII.");
		return TRR_ERR;
	}

done:	rdr->flags |= RXRF_RRDP;
	return TRR_OK;
}

static enum token_read_result
confirm_not_rrdp(struct rrdp_xml_reader *rdr)
{
	pr_trc("This is not a %s.", rdr->type_str_camel);
	rdr->state = state_ignore_input;
	return TRR_OK;
}

static int
check_session_chars(struct rrdp_xml_reader *rdr, struct xml_token *val)
{
	array_index v;
	char chr;

	if (val->len == 0)
		return pr_err("(Line %u) session_id is an empty string",
		    rdr->line);

	for (v = 0; v < val->len; v++) {
		chr = val->str[v];
		if (!is_printable(chr))
			return pr_err("(Line %u) session_id has illegal character: 0x%02x",
			    rdr->line, (unsigned char)chr);
		if (!is_alphanumeric(chr) && chr != '-')
			return pr_err("(Line %u) session_id has illegal character: %c",
			    rdr->line, chr);
	}

	return 0;
}

static enum token_read_result
parse_root_session_attr(struct rrdp_xml_reader *rdr, struct xml_token *val)
{
	if (rdr->flags & RXRF_SESSION_SET)
		return fail_multiple_attrs(rdr, rdr->type_str, "session_id");
	rdr->flags |= RXRF_SESSION_SET;

	if (rdr->type == RXT_NOTIF) {
		if (check_session_chars(rdr, val) != 0)
			return TRR_ERR;
		rdr->c.notif.id.session_id = pstrndup(val->str, val->len);
		return TRR_OK;
	}

	if (tkn_equals(val, rdr->c.sd.notif_id->session_id))
		return TRR_OK;

	pr_err("(Line %u) %s session_id '%.*s' does not match Notification session_id '%s'",
	    rdr->line, rdr->type_str_camel, (int)val->len, val->str,
	    rdr->c.sd.notif_id->session_id);
	return TRR_ERR;
}

static enum token_read_result
parse_root_serial_attr(struct rrdp_xml_reader *rdr, struct xml_token *val)
{
	enum token_read_result res;
	struct rrdp_serial subserial;
	int cmp;

	if (rdr->flags & RXRF_SERIAL_SET)
		return fail_multiple_attrs(rdr, rdr->type_str, "serial");
	rdr->flags |= RXRF_SERIAL_SET;

	if (rdr->type == RXT_NOTIF) {
		res = init_serial(rdr, &rdr->c.notif.id.serial, val,
		    rdr->type_str);
		if (res != TRR_OK)
			return res;
		res = init_min_serial(rdr);
		if (res != TRR_OK)
			return res;
		return init_deltas_array(rdr); /* Happy path */
	}

	res = init_serial(rdr, &subserial, val, rdr->type_str);
	if (res != TRR_OK)
		return res;
	cmp = BN_cmp(rdr->c.sd.notif_id->serial.num, subserial.num);
	serial_cleanup(&subserial);

	if (cmp == 0)
		return TRR_OK; /* Happy path */

	pr_err("(Line %u) %s serial '%.*s' does not match Notification serial '%s'",
	    rdr->line, rdr->type_str_camel, (int)val->len, val->str,
	    rdr->c.sd.notif_id->serial.str);
	return TRR_ERR;
}

static enum token_read_result
accept_root_attrs(struct rrdp_xml_reader *rdr)
{
	char const *const RRDP_XMLNS = "http://www.ripe.net/rpki/rrdp";
	char const *const RRDP_VER = "1";
	char const *const TAG = rdr->type_str;
	struct xml_token *key, *val;
	enum token_read_result res;

	pr_clutter("== State: root_attrs ==");

	res = next_tkn(rdr, &rdr->tkn1);
	if (res != TRR_OK)
		return res;
	key = &rdr->tkn1;

	if (key->type == XTT_CLOSE_TAG) {
		if (!(rdr->flags & RXRF_XMLNS_SET))
			return fail_missing_attr(rdr, TAG, "xmlns");
		if (!(rdr->flags & RXRF_VERSION_SET))
			return fail_missing_attr(rdr, TAG, "version");
		if (!(rdr->flags & RXRF_SESSION_SET))
			return fail_missing_attr(rdr, TAG, "session");
		if (!(rdr->flags & RXRF_SERIAL_SET))
			return fail_missing_attr(rdr, TAG, "serial");
		rdr->state = state_root_content;
		return res;
	}

	res = attr_boilerplate(rdr);
	if (res != TRR_OK)
		return res;
	val = &rdr->tkn3;

	if (tkn_equals(key, "xmlns")) {
		if (rdr->flags & RXRF_XMLNS_SET)
			return fail_multiple_attrs(rdr, TAG, "xmlns");
		if (!tkn_equals(val, RRDP_XMLNS))
			return fail_attr_value(rdr, TAG, "xmlns", RRDP_XMLNS, val);
		rdr->flags |= RXRF_XMLNS_SET;
		return TRR_OK;

	} else if (tkn_equals(key, "version")) {
		if (rdr->flags & RXRF_VERSION_SET)
			return fail_multiple_attrs(rdr, TAG, "version");
		if (!tkn_equals(val, RRDP_VER))
			return fail_attr_value(rdr, TAG, "version", RRDP_VER, val);
		rdr->flags |= RXRF_VERSION_SET;
		return TRR_OK;

	} else if (tkn_equals(key, "session_id")) {
		return parse_root_session_attr(rdr, val);

	} else if (tkn_equals(key, "serial")) {
		return parse_root_serial_attr(rdr, val);
	}

	return fail_unknown_attr(rdr, TAG, key);
}

static enum token_read_result
state_root_tag(struct rrdp_xml_reader *rdr)
{
	enum token_read_result res;

	pr_clutter("== State: root_tag ==");

	res = next_str(rdr, &rdr->tkn1);
	if (res != TRR_OK)
		return res;
	if (tkn_equals(&rdr->tkn1, rdr->type_str)) {
		res = confirm_rrdp(rdr);
		if (res != TRR_OK)
			return res;
	} else {
		return confirm_not_rrdp(rdr);
	}

	rdr->state = accept_root_attrs;
	return TRR_OK;
}

static enum token_read_result
state_post_doctype(struct rrdp_xml_reader *rdr)
{
	enum token_read_result res;

	pr_clutter("== State: post_doctype ==");

	res = next_tkn(rdr, &rdr->tkn1);
	if (res != TRR_OK)
		return res;

	switch (rdr->tkn1.type) {
	case XTT_OPEN_TAG:
		rdr->state = state_root_tag;
		return TRR_OK;
	case XTT_COMMENT:
		rdr->state = state_throw_away_comment;
		rdr->next_state = state_post_doctype;
		return TRR_OK;
	case XTT_PI_OPEN:
		if (!(rdr->flags & RXRF_RRDP)) {
			rdr->state = state_throw_away_pi;
			rdr->next_state = state_post_doctype;
		}
		/* No break */
	default:
		return bad_tkn_type(rdr, &rdr->tkn1, "xml start");
	}
}

/*
 * Not sure about this one.
 * Wikipedia says the point of a DOCTYPE is specifying a DTD. RRDP does not
 * have nor need one.
 * But HTML5 has a DTD-less DOCTYPE.
 * So we'll allow an optional DTD-less DOCTYPE, I guess.
 *
 * We also need to handle DOCTYPEs when the server returns a redirection.
 */
static enum token_read_result
state_doctype_tag(struct rrdp_xml_reader *rdr)
{
	enum token_read_result res;

	pr_clutter("== State: doctype_tag ==");

	res = next_str(rdr, &rdr->tkn1);
	if (res != TRR_OK)
		return res;
	if (tkn_case_equals(&rdr->tkn1, rdr->type_str)) {
		res = confirm_rrdp(rdr);
		if (res != TRR_OK)
			return res;
	} else {
		return confirm_not_rrdp(rdr);
	}

	res = next_tkn_type(rdr, &rdr->tkn2, XTT_CLOSE_TAG, ">");
	if (res != TRR_OK)
		return res;

	rdr->state = state_post_doctype;
	return TRR_OK;
}

static enum token_read_result
state_post_xmldecl(struct rrdp_xml_reader *rdr)
{
	enum token_read_result res;

	pr_clutter("== State: post_xmldecl ==");

	res = next_tkn(rdr, &rdr->tkn1);
	if (res != TRR_OK)
		return res;

	switch (rdr->tkn1.type) {
	case XTT_OPEN_TAG:
		rdr->state = state_root_tag;
		return TRR_OK;
	case XTT_DOCTYPE:
		rdr->state = state_doctype_tag;
		return TRR_OK;
	case XTT_COMMENT:
		rdr->state = state_throw_away_comment;
		rdr->next_state = state_post_xmldecl;
		return TRR_OK;
	case XTT_PI_OPEN:
		rdr->state = state_throw_away_pi;
		rdr->next_state = state_post_xmldecl;
		return TRR_OK;
	default:
		return bad_tkn_type(rdr, &rdr->tkn1, "xml start");
	}
}

static enum token_read_result
parse_xmldecl_version(struct rrdp_xml_reader *rdr, struct xml_token *val)
{
	array_index i;

	if (val->len < 3 || val->str[0] != '1' || val->str[1] != '.')
		goto fail;

	for (i = 2; i < val->len; i++)
		if (val->str[i] < '0' || '9' < val->str[i])
			goto fail;

	rdr->flags |= RXRF_XMLV_SET;
	return TRR_OK;

fail:	return fail_attr_value(rdr, XMLDECL_TAG, "version", "1.x", val);
}

static enum token_read_result
parse_xmldecl_encoding(struct rrdp_xml_reader *rdr, struct xml_token *val)
{
	if (tkn_case_equals(val, "US-ASCII"))
		return TRR_OK;
	if (tkn_case_equals(val, "UTF-8"))
		rdr->flags |= RXRF_UTF_8;
	rdr->flags |= RXRF_NOT_ASCII;
	return TRR_OK;
}

static enum token_read_result
parse_xmldecl_standalone(struct rrdp_xml_reader *rdr, struct xml_token *val)
{
	return (tkn_equals(val, "yes") || tkn_equals(val, "no"))
	    ? TRR_OK /* idc which */
	    : fail_attr_value(rdr, XMLDECL_TAG, "standalone", "(yes|no)", val);
}

static enum token_read_result
state_xmldecl_attrs(struct rrdp_xml_reader *rdr)
{
	struct xml_token *key, *val;
	enum token_read_result res;

	pr_clutter("== State: xmldecl_attrs ==");

	res = next_tkn(rdr, &rdr->tkn1);
	if (res != TRR_OK)
		return res;
	key = &rdr->tkn1;

	if (key->type == XTT_PI_CLOSE) {
		if (!(rdr->flags & RXRF_XMLV_SET))
			return fail_missing_attr(rdr, XMLDECL_TAG, "version");
		rdr->state = state_post_xmldecl;
		return TRR_OK;
	}

	res = attr_boilerplate(rdr);
	if (res != TRR_OK)
		return res;
	val = &rdr->tkn3;

	if (tkn_equals(key, "version"))
		return parse_xmldecl_version(rdr, val);
	if (tkn_equals(key, "encoding"))
		return parse_xmldecl_encoding(rdr, val);
	if (tkn_equals(key, "standalone"))
		return parse_xmldecl_standalone(rdr, val);

	return fail_unknown_attr(rdr, XMLDECL_TAG, key);
}

static enum token_read_result
state_xmldecl_tag(struct rrdp_xml_reader *rdr)
{
	enum token_read_result res;

	pr_clutter("== State: xmldecl_tag ==");

	/*
	 * Sometimes, libcurl feeds us input that's not RRDP XML.
	 * For example, if the server wants to redirect us, we'll get HTTP
	 * (containing HTTP code 30X).
	 *
	 * When this happens, we don't want to return parse error, because that
	 * will result in immediate request termination. What libcurl seems to
	 * expect us to do is ignore the input. This results in automatic
	 * redirect handling (partly done by libcurl).
	 *
	 * RFC 8182 does not define a content-type header for RRDP (not even
	 * "application/xml"), and servers respond inconsistent content-types
	 * through the tree...
	 *
	 * So, until we get to the DOCTYPE or root tag, the parser must not
	 * assume that the document is RRDP.
	 */

	res = next_tkn(rdr, &rdr->tkn1);
	if (res != TRR_OK)
		return res;

	switch (rdr->tkn1.type) {
	case XTT_OPEN_TAG:
		rdr->state = state_root_tag;
		return TRR_OK;
	case XTT_XMLDECL:
		rdr->state = state_xmldecl_attrs;
		return TRR_OK;
	case XTT_DOCTYPE:
		rdr->state = state_doctype_tag;
		return TRR_OK;
	case XTT_COMMENT:
		rdr->state = state_throw_away_comment;
		rdr->next_state = state_post_xmldecl;
		return TRR_OK;
	case XTT_PI_OPEN:
		rdr->state = state_throw_away_pi;
		rdr->next_state = state_post_xmldecl;
		return TRR_OK;
	default:
		return bad_tkn_type(rdr, &rdr->tkn1, "xml start");
	}
}

static struct rrdp_xml_reader *
rrdp_xml_create(enum rrdp_xml_type type)
{
	struct rrdp_xml_reader *result;

	result = pzalloc(sizeof(struct rrdp_xml_reader));

	result->type = type;
	switch (type) {
	case RXT_NOTIF:
		result->type_str = "notification";
		result->type_str_camel = "Notification";
		break;
	case RXT_SNAPSHOT:
		result->type_str = "snapshot";
		result->type_str_camel = "Snapshot";
		break;
	case RXT_DELTA:
		result->type_str = "delta";
		result->type_str_camel = "Delta";
		break;
	}

	result->line = 1;
	result->state = state_xmldecl_tag;

	return result;
}

static int
rrdp_xml_parse(struct rrdp_xml_reader *rdr, char const *in, size_t inlen)
{
	rdr->buf = in;
	rdr->buflen = inlen;

	while (rdr->buflen > 0) {
		pr_clutter("Buffer: '%.*s'", (int)rdr->buflen, rdr->buf);

		switch (rdr->state(rdr)) {
		case TRR_OK:
			pr_clutter("TRR_OK. Discarding '%.*s' '%.*s' '%.*s'",
			    (int)rdr->tkn1.len, rdr->tkn1.str,
			    (int)rdr->tkn2.len, rdr->tkn2.str,
			    (int)rdr->tkn3.len, rdr->tkn3.str);
			memset(&rdr->tkn1, 0, sizeof(rdr->tkn1));
			memset(&rdr->tkn2, 0, sizeof(rdr->tkn2));
			memset(&rdr->tkn3, 0, sizeof(rdr->tkn3));
			break;
		case TRR_MORE:
			pr_clutter("TRR_MORE. Tokens: '%.*s' '%.*s' '%.*s'",
			    (int)rdr->tkn1.len, rdr->tkn1.str,
			    (int)rdr->tkn2.len, rdr->tkn2.str,
			    (int)rdr->tkn3.len, rdr->tkn3.str);
			commit_partial_token(rdr, &rdr->tkn1);
			commit_partial_token(rdr, &rdr->tkn2);
			commit_partial_token(rdr, &rdr->tkn3);
			break;
		case TRR_ERR:
			return EINVAL;
		}
	}

	return 0;
}

static void
rrdp_xml_destroy(struct rrdp_xml_reader *rdr)
{
	switch (rdr->type) {
	case RXT_NOTIF:
		free(rdr->c.notif.id.session_id);
		BN_free(rdr->c.notif.id.serial.num);
		free(rdr->c.notif.id.serial.str);
		BN_free(rdr->c.notif.min_serial);
		metadata_cleanup(&rdr->c.notif.snapshot);
		notification_delta_cleanup(&rdr->c.notif.delta);
		notification_deltas_cleanup(&rdr->c.notif.deltas);
		break;

	case RXT_SNAPSHOT:
	case RXT_DELTA:
		metadata_cleanup(&rdr->c.sd.file);
		b64d2f_destroy(&rdr->c.sd.b64);
		break;
	}

	free(rdr);
}

static int
swap_until_sorted(struct rrdp_xml_reader *rdr, array_index i, BIGNUM *min,
    BIGNUM *diff)
{
	struct notification_delta *array;
	size_t deltas_len;
	BN_ULONG j;
	struct notification_delta tmp;

	array = rdr->c.notif.deltas.arr;
	deltas_len = rdr->c.notif.deltas.len;

	while (true) {
		if (!BN_sub(diff, array[i].serial.num, min))
			return pr_crypto_err("BN_sub() returned error.");
		j = deltas_len - BN_get_word(diff) - 1;
		if (i == j)
			return 0;
		if (BN_cmp(array[i].serial.num, array[j].serial.num) == 0) {
			return pr_err("Notification delta serial '%s' is not unique",
			    array[i].serial.str);
		}

		/* Simple swap */
		tmp = array[j];
		array[j] = array[i];
		array[i] = tmp;
	}
}

/* Descending sort */
static int
sort_deltas(struct rrdp_xml_reader *rdr)
{
	BIGNUM *min, *aux;
	array_index i;
	int error;

	/*
	 * Note: The RFC explicitly states that the serials have to be
	 * a "contiguous sequence."
	 * Effective linear sort FTW.
	 */

	if (rdr->c.notif.deltas.len == 0)
		return 0;
	if (rdr->c.notif.ndeltas >= rdr->c.notif.deltas.cap &&
	    rdr->c.notif.deltas.cap > rdr->c.notif.deltas.len)
		return pr_err("The serials listed in the Notification's deltas do not form a contiguous sequence");

	min = rdr->c.notif.deltas.arr[0].serial.num;
	for (i = 1; i < rdr->c.notif.deltas.len; i++) {
		aux = rdr->c.notif.deltas.arr[i].serial.num;
		if (BN_cmp(aux, min) < 0)
			min = aux;
	}

	aux = BN_create();

	error = 0;
	ARRAYLIST_FOREACH_IDX(&rdr->c.notif.deltas, i) {
		error = swap_until_sorted(rdr, i, min, aux);
		if (error)
			goto end;
	}

	if (BN_cmp(rdr->c.notif.id.serial.num, rdr->c.notif.deltas.arr[0].serial.num) != 0) {
		pr_err("Notification serial does not match highest delta serial: %s != %s",
		    rdr->c.notif.id.serial.str,
		    rdr->c.notif.deltas.arr[0].serial.str);
		error = EINVAL;
	}

end:	BN_free(aux);
	return error;
}

struct write_callback_arg {
	struct rrdp_xml_reader *rdr;
	size_t total_bytes;
	EVP_MD_CTX *hasher;
	int error;
};

static size_t
write_callback(char *data, size_t size, size_t nmemb, void *userp)
{
	struct write_callback_arg *arg = userp;

	size *= nmemb;

	arg->total_bytes += size;
	if (arg->total_bytes > config_get_http_max_file_size()) {
		/*
		 * If the server doesn't provide the file size beforehand,
		 * CURLOPT_MAXFILESIZE doesn't prevent large file downloads.
		 *
		 * Therefore, we cover our asses by way of this reactive
		 * approach. We already reached the size limit, but we're going
		 * to reject the file anyway.
		 */
		arg->error = EFBIG;
		return CURL_WRITEFUNC_ERROR;
	}

	if (arg->rdr->state == state_ignore_input)
		return size;

	if (arg->hasher && sha256_update(arg->hasher, data, size) != 0)
		return CURL_WRITEFUNC_ERROR;

	return rrdp_xml_parse(arg->rdr, data, size)
	    ? CURL_WRITEFUNC_ERROR
	    : size;
}

static int
validate_file_size(struct write_callback_arg *args)
{
	float ratio;

	if (args->error == EFBIG) {
		pr_err("File too big (read: %zu bytes). Rejecting.",
		    args->total_bytes);
		return EFBIG;
	}

	ratio = args->total_bytes / (float) config_get_http_max_file_size();
	if (ratio > 0.4f) {
		pr_wrn("File size exceeds 40%% of the configured limit (%zu/%ld bytes).",
		    args->total_bytes, config_get_http_max_file_size());
	}

	pr_trc("Done. Total bytes transferred: %zu", args->total_bytes);
	return 0;
}

int
rrdpxml_fetch_notif(struct uri const *url, time_t mtim, bool *changed,
    struct update_notification *notif)
{
	struct write_callback_arg wargs;
	int error;

	wargs.rdr = rrdp_xml_create(RXT_NOTIF);
	wargs.rdr->notif_uri = url;
	wargs.total_bytes = 0;
	wargs.hasher = NULL;
	wargs.error = 0;
	*changed = false;

	error = http_download(url, write_callback, &wargs, mtim, changed);
	if (error)
		goto end;

	if (!(wargs.rdr->flags & RXRF_RRDP)) {
		error = pr_err("The document was not an RRDP Notification.");
		goto end;
	}
	if (!(*changed)) {
		pr_trc("The Notification has not changed.");
		goto end;
	}
	if (wargs.rdr->state != state_ignore_input) {
		error = pr_err("XML is unterminated");
		goto end;
	}
	error = validate_file_size(&wargs);
	if (error)
		goto end;

	error = sort_deltas(wargs.rdr);
	if (error)
		goto end;

	notif->session = wargs.rdr->c.notif.id;
	memset(&wargs.rdr->c.notif.id, 0, sizeof(wargs.rdr->c.notif.id));
	notif->snapshot = wargs.rdr->c.notif.snapshot;
	memset(&wargs.rdr->c.notif.snapshot, 0,
	    sizeof(wargs.rdr->c.notif.snapshot));
	notif->deltas = wargs.rdr->c.notif.deltas;
	memset(&wargs.rdr->c.notif.deltas, 0,
	    sizeof(wargs.rdr->c.notif.deltas));
	notif->url = url;

end:	rrdp_xml_destroy(wargs.rdr);
	return error;
}

int
rrdpxml_explode_snapshot(struct update_notification const *notif,
    struct files_ht *files,
    struct cache_sequence *seq)
{
	struct uri const *url;
	struct write_callback_arg wargs;
	int error;

	url = &notif->snapshot.uri;
	fnstack_push(uri_str(url));

	if (!uri_same_origin(notif->url, url)) {
		error = pr_err("Notification %s and Snapshot %s are not hosted by the same origin.",
		    uri_str(notif->url), uri_str(url));
		goto pop;
	}

	wargs.rdr = rrdp_xml_create(RXT_SNAPSHOT);
	wargs.rdr->c.sd.notif_id = &notif->session;
	wargs.rdr->rrdp_filerefs = files;
	wargs.rdr->rrdp_seq = seq;
	wargs.total_bytes = 0;
	wargs.hasher = sha256_create();
	sha256_init(wargs.hasher);
	wargs.error = 0;

	pr_trc("Exploding snaphsot into %s...", seq->pfx.str);

	error = http_download(url, write_callback, &wargs, 0, NULL);
	if (error)
		goto end;

	if (!(wargs.rdr->flags & RXRF_RRDP)) {
		error = pr_err("The document was not an RRDP Snapshot.");
		goto end;
	}
	if (wargs.rdr->state != state_ignore_input) {
		error = pr_err("XML is unterminated");
		goto end;
	}
	error = validate_file_size(&wargs);
	if (error)
		goto end;
	error = sha256_check(wargs.hasher, notif->snapshot.hash.bytes,
	    "Snapshot", uri_str(url));

	pr_trc("Snapshot exploded.");

end:	sha256_destroy(wargs.hasher);
	rrdp_xml_destroy(wargs.rdr);
pop:	fnstack_pop();
	return error;
}

int
rrdpxml_explode_delta(struct update_notification *notif,
    struct notification_delta *delta,
    struct files_ht *files,
    struct cache_sequence *seq)
{
	struct uri const *url;
	struct rrdp_id notif_id;
	struct write_callback_arg wargs;
	int error;

	url = &delta->meta.uri;
	fnstack_push(uri_str(url));

	if (!uri_same_origin(notif->url, url)) {
		error = pr_err("Notification %s and Delta %s are not hosted by the same origin.",
		    uri_str(notif->url), uri_str(url));
		goto pop;
	}

	notif_id.session_id = notif->session.session_id;
	notif_id.serial = delta->serial;

	wargs.rdr = rrdp_xml_create(RXT_DELTA);
	wargs.rdr->c.sd.notif_id = &notif_id;
	wargs.rdr->rrdp_filerefs = files;
	wargs.rdr->rrdp_seq = seq;
	wargs.total_bytes = 0;
	wargs.hasher = sha256_create();
	sha256_init(wargs.hasher);
	wargs.error = 0;

	pr_trc("Exploding delta into %s...", seq->pfx.str);

	error = http_download(url, write_callback, &wargs, 0, NULL);
	if (error)
		goto end;

	if (!(wargs.rdr->flags & RXRF_RRDP)) {
		error = pr_err("The document was not an RRDP Delta.");
		goto end;
	}
	if (wargs.rdr->state != state_ignore_input) {
		error = pr_err("XML is unterminated");
		goto end;
	}
	error = validate_file_size(&wargs);
	if (error)
		goto end;
	error = sha256_check(wargs.hasher, delta->meta.hash.bytes,
	    "Delta", uri_str(url));

	pr_trc("Delta exploded.");

end:	sha256_destroy(wargs.hasher);
	rrdp_xml_destroy(wargs.rdr);
pop:	fnstack_pop();
	return error;
}
