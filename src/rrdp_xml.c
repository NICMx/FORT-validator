#include "rrdp_xml.h"

#include <errno.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "base64.h"
#include "config.h"
#include "http.h"
#include "log.h"
#include "thread_var.h"

#ifndef XML_BUF_SIZE
#define XML_BUF_SIZE ((size_t)4096u)
#endif

/*
 * Maximum attribute value size. Needs to be <= XML_BUF_SIZE.
 * In RRDP, the largest potential attributes are URIs.
 * Which can be roughly any length, but I'm guessing anything larger than this
 * is a troll.
 * Includes quotes.
 */
#ifndef MAX_QUOTE_SIZE
#define MAX_QUOTE_SIZE ((size_t)1024u)
#endif

/* Current longest RRDP tag/attr; strlen("notification") + nullchar */
#define MAX_TKN_SIZE 13

/* Needs to be fairly small, otherwise libcrypto BIGNUM lags */
#define MAX_SERIAL_SIZE 64

enum token_read_result {
	TRR_OK,
	TRR_ERR,
	TRR_MORE,
};

struct rrdp_xml_reader;

typedef enum token_read_result (*consume_cb)(struct rrdp_xml_reader *);
static enum token_read_result accept_root_content(struct rrdp_xml_reader *);

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
is_printable(unsigned char chr) /* According to US-ASCII */
{
	return 0x20u <= chr && chr <= 0x7Eu;
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
	XTT_META,              /* <! */
	XTT_EQUALS,
	XTT_STR,
	XTT_QUOTED,
	XTT_UNKNOWN,
};

struct xml_token {
	enum xml_token_type type;
	char const *str;
	size_t len;
};

static enum token_read_result
token_init(struct xml_token *tkn, enum xml_token_type type,
    char const *str, size_t len)
{
	tkn->type = type;
	tkn->str = str;
	tkn->len = len;
	return TRR_OK;
}

struct xml_token_bkp {
	struct xml_token meta;
	unsigned char buf[MAX_TKN_SIZE];
};

struct rrdp_xml_reader {
	enum rrdp_xml_type type;
	char const *type_str;
	char const *type_str_camel;
	struct uri const *notif_uri;

	/* Contains string data, but it's not null-terminated. */
	unsigned char buf[XML_BUF_SIZE];
	/* Points to @buf's next not-yet-consumed token */
	size_t offset;
	/* Entire populated area from @buf. (Includes bytes before @offset) */
	size_t buflen;

	/*
	 * Cached next token.
	 * It was already consumed from @buf, but the parser performed a
	 * rollback because it reached the end of @buf before completing the
	 * phrase. So we'll need to return it the next time the parser wants
	 * the first token of the phrase.
	 * Unset if meta.len == 0.
	 */
	struct xml_token_bkp tkn1;
	/*
	 * Cached token after next token.
	 * It was already consumed from @buf, but the parser performed a
	 * rollback because it reached the end of @buf before completing the
	 * phrase. So we'll need to return it the next time the parser wants
	 * the second token of the phrase.
	 * (RRDP phrases never exceed three tokens.)
	 * Unset if meta.len == 0.
	 */
	struct xml_token_bkp tkn2;

	consume_cb consume;

/* Already parsed xmlns attribute from root tag? */
#define RXRF_XMLNS_SET     (1 << 0)
/* Already parsed version attribute from root tag? */
#define RXRF_VERSION_SET   (1 << 1)
/* Already parsed session_id attribute from root tag? */
#define RXRF_SESSION_SET   (1 << 2)
/* Already parsed serial attribute from root tag? */
#define RXRF_SERIAL_SET    (1 << 3)
/* Already reached the end of the XML? */
#define RXRF_DONE          (1 << 8)
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
get_char(struct rrdp_xml_reader const *rdr, array_index offset, char *chr)
{
	offset += rdr->offset;

	if (offset >= rdr->buflen)
		return TRR_MORE;

	*chr = (char)rdr->buf[offset];
	return TRR_OK;
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
find_not_string_char(struct rrdp_xml_reader const *rdr, array_index *offset)
{
	array_index c;
	enum token_read_result res;
	char chr;

	for (c = 0; c < 16; c++) {
		res = get_char(rdr, c, &chr);
		if (res != TRR_OK)
			return res;
		if (!is_NameChar(chr)) {
			*offset = rdr->offset + c;
			return TRR_OK;
		}
	}

	/* The current longest RRDP tag/attr is 'notification' (12 chars) */
	pr_err("Token has too many characters: %.*s(...)",
	    (int)c, rdr->buf + rdr->offset);
	return TRR_ERR;
}

static enum token_read_result
find_chr(struct rrdp_xml_reader const *rdr, char chr, array_index *offset)
{
	array_index i;
	enum token_read_result res;
	char next;

	for (i = 1; i < MAX_QUOTE_SIZE; i++) {
		res = get_char(rdr, i, &next);
		if (res != TRR_OK)
			return res;
		if (next == chr) {
			*offset = i;
			return TRR_OK;
		}
	}

	pr_err("Attribute value too long");
	return TRR_ERR;
}

static bool
tkn_equals(struct xml_token *tkn, char const *str)
{
	if (strlen(str) != tkn->len)
		return false;

	return strncmp(tkn->str, str, tkn->len) == 0;
}

/*
 * TODO (probably fine) Extensible Markup Language (XML) 1.0 (Fifth Edition):
 *
 * > Note that the grammar does not allow a comment ending in --->.
 * > The following example is not well-formed.
 * >
 * > 	<!-- B+, B, or B--->
 *
 * This function does not reject the above.
 */
static enum token_read_result
skip_comment(struct rrdp_xml_reader *rdr)
{
	array_index offset;
	char chr;
	enum token_read_result res;

	res = get_char(rdr, 3u, &chr);
	if (res != TRR_OK)
		return res;
	if (chr != '-') {
		pr_err("Unexpected token: <!-%c", chr);
		return TRR_ERR;
	}

	if (rdr->buflen - rdr->offset < 6u)
		return TRR_MORE;

	for (offset = rdr->offset + 6u; offset < rdr->buflen; offset++) {
		if (rdr->buf[offset - 2u] == '-' &&
		    rdr->buf[offset - 1u] == '-' &&
		    rdr->buf[offset     ] == '>') {
			rdr->offset = offset + 1u;
			return TRR_OK;
		}
	}

	if (rdr->buf[rdr->buflen - 1u] == '-') {
		if (rdr->buf[rdr->buflen - 2u] == '-') {
			rdr->buf[rdr->offset + 4u] = '-';
			rdr->buf[rdr->offset + 5u] = '-';
			offset = 6u;
		} else {
			rdr->buf[rdr->offset + 4u] = '-';
			offset = 5u;
		}
	} else {
		offset = 4u;
	}

	rdr->buflen = rdr->offset + offset;
	return TRR_MORE;
}

/* Advances rdr->offset into the next non-whitespace character */
static enum token_read_result
find_non_whitespace(struct rrdp_xml_reader *rdr)
{
	array_index offset;

	for (offset = rdr->offset; offset < rdr->buflen; offset++)
		if (!is_whitespace(rdr->buf[offset])) {
			rdr->offset = offset;
			return TRR_OK;
		}

	rdr->buflen = rdr->offset; /* Truncate trash */
	return TRR_MORE;
}

static enum token_read_result
next_token(struct rrdp_xml_reader *rdr, struct xml_token *tkn)
{
	char chr;
	size_t tail;
	enum token_read_result res;

retry:	res = find_non_whitespace(rdr);
	if (res != TRR_OK)
		return res;

	chr = rdr->buf[rdr->offset];
	switch (chr) {
	case '<':
		res = get_char(rdr, 1, &chr);
		if (res != TRR_OK)
			return res;
		switch (chr) {
		case '/':
			return token_init(tkn, XTT_OPENING_CLOSURE, "</", 2);
		case '!':
			res = get_char(rdr, 2u, &chr);
			if (res != TRR_OK)
				return res;
			if (chr != '-')
				return token_init(tkn, XTT_META, "<!", 2);

			res = skip_comment(rdr);
			if (res != TRR_OK)
				return res;
			goto retry;
		}
		return token_init(tkn, XTT_OPEN_TAG, "<", 1);

	case '/':
		res = get_char(rdr, 1, &chr);
		if (res != TRR_OK)
			return res;
		if (chr != '>') {
			pr_err("Unexpected token: '/%c'", chr);
			return TRR_ERR;
		}
		return token_init(tkn, XTT_CLOSING_CLOSURE, "/>", 2);

	case '>':
		return token_init(tkn, XTT_CLOSE_TAG, ">", 1);

	case '=':
		return token_init(tkn, XTT_EQUALS, "=", 1);

	case '"':
		res = find_chr(rdr, '"', &tail);
		if (res != TRR_OK)
			return res;

		return token_init(tkn, XTT_QUOTED,
		    (char const *)(rdr->buf + rdr->offset),
		    tail + 1);

	case '\'':
		res = find_chr(rdr, '\'', &tail);
		if (res != TRR_OK)
			return res;

		return token_init(tkn, XTT_QUOTED,
		    (char const *)(rdr->buf + rdr->offset),
		    tail + 1);
	}

	if (!is_NameStartChar(chr)) {
		if (is_printable(chr))
			pr_err("Unexpected character: %c", chr);
		else
			pr_err("Unexpected character: 0x%02x",
			    (unsigned char)chr);
		return TRR_ERR;
	}

	res = find_not_string_char(rdr, &tail);
	if (res != TRR_OK)
		return res;

	tkn->type = XTT_STR;
	tkn->str = (char const *)(rdr->buf + rdr->offset);
	tkn->len = tail - rdr->offset;
	return TRR_OK;
}

static enum token_read_result
next_bkp_tkn(struct rrdp_xml_reader *rdr, struct xml_token_bkp *bkp,
    struct xml_token *out)
{
	enum token_read_result res;

	if (bkp->meta.len != 0) {
		*out = bkp->meta;
		return TRR_OK;
	}

	res = next_token(rdr, out);
	if (res != TRR_OK)
		return res;

	bkp->meta.type = out->type;
	strncpy((char *)bkp->buf, out->str, out->len);
	bkp->meta.len = out->len;

	rdr->offset += out->len;
	return TRR_OK;
}

static enum token_read_result
expect_tkn_type(struct xml_token *tkn, enum xml_token_type type,
    char const *what)
{
	if (tkn->type != type) {
		pr_err("Expected %s, got '%.*s'", what,
		    (int)tkn->len, tkn->str);
		return TRR_ERR;
	}

	return TRR_OK;
}

static enum token_read_result
expect_string(struct xml_token *tkn, char const *str)
{
	if (tkn->type != XTT_STR || !tkn_equals(tkn, str)) {
		pr_err("Expected '%s', got '%.*s'", str,
		    (int)tkn->len, tkn->str);
		return TRR_ERR;
	}

	return TRR_OK;
}

static enum token_read_result
expect_quoted(struct rrdp_xml_reader *rdr, struct xml_token *val)
{
	enum token_read_result res;

	res = next_token(rdr, val);
	if (res != TRR_OK)
		return res;

	if (val->type != XTT_QUOTED) {
		pr_err("Expected attribute value, got '%.*s'",
		    (int)val->len, val->str);
		return TRR_ERR;
	}

	rdr->offset += val->len;

	val->str++;
	val->len -= 2;
	return TRR_OK;
}

static enum token_read_result
fail_unexpected_token(struct xml_token *actual)
{
	pr_err("Unexpected token: %.*s", (int)actual->len, actual->str);
	return TRR_ERR;
}

static enum token_read_result
fail_missing_attr(char const *tag, char const *attr)
{
	pr_err("<%s> is missing the '%s' attribute.", tag, attr);
	return TRR_ERR;
}

static enum token_read_result
fail_unknown_attr(char const *tag, struct xml_token *tkn)
{
	pr_err("Unknown <%s> attribute: %.*s", tag, (int)tkn->len, tkn->str);
	return TRR_ERR;
}

static enum token_read_result
fail_attr_value(char const *tag, char const *attr,
    char const *expected, struct xml_token *actual)
{
	pr_err("<%s> %s is not %s: %.*s", tag, attr, expected,
	    (int)actual->len, actual->str);
	return TRR_ERR;
}

static enum token_read_result
fail_multiple_attrs(char const *tag, char const *attr)
{
	pr_err("<%s> has multiple '%s' attributes.", tag, attr);
	return TRR_ERR;
}

static enum token_read_result
init_serial(struct rrdp_serial *serial, struct xml_token *tkn)
{
	char *str;
	BIGNUM *num;

	str = pstrndup(tkn->str, tkn->len);
	num = BN_create();

	if (BN_dec2bn(&num, str) == 0) {
		pr_err("Not a number: %s", str);
		goto fail;
	}
	if (BN_is_negative(num)) {
		pr_err("Negative serial: %s", str);
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
		pr_err("Cannot copy serial: Unknown error");
		goto fail;
	}
	if (!BN_sub_word(min, config_get_rrdp_delta_threshold())) {
		pr_err("Cannot subtract serial: Unknown error");
		goto fail;
	}
	if (BN_is_negative(min) && !BN_set_word(min, 0)) {
		pr_err("Cannot assign 0 to serial: Unknown error");
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
		pr_err("Cannot subtract BIGNUMs: Generic error");
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
init_uri(struct uri *uri, struct xml_token *tkn)
{
	array_index u;
	unsigned char chr;
	char *uristr;
	error_msg errmsg;

	for (u = 0; u < tkn->len; u++) {
		chr = (unsigned char)(tkn->str[u]);
		if (!is_printable(chr)) {
			pr_err("uri has illegal character: 0x%02x", chr);
			return TRR_ERR;
		}
	}

	/* TODO (performance) this dupe shouldn't be necessary */
	uristr = pstrndup(tkn->str, tkn->len);
	errmsg = uri_init(uri, uristr);
	free(uristr);

	if (errmsg) {
		pr_err("'%.*s' is not a valid URI: %s",
		    (int)tkn->len, tkn->str, errmsg);
		return TRR_ERR;
	}

	return TRR_OK;
}

static enum token_read_result
init_notif_uri(struct rrdp_xml_reader *rdr, struct uri *uri,
    struct xml_token *tkn, char const *what)
{
	enum token_read_result res;

	res = init_uri(uri, tkn);
	if (res != TRR_OK)
		return res;

	if (!uri_same_origin(rdr->notif_uri, uri)) {
		pr_err("Notification '%s' does not have the same origin as its %s: %s",
		    uri_str(rdr->notif_uri), what, uri_str(uri));
		return TRR_ERR;
	}

	return TRR_OK;
}

static enum token_read_result
init_hash(struct file_metadata *file, struct xml_token *tkn)
{
	if (str2hash(tkn->str, tkn->len, &file->hash) != 0) {
		pr_err("Not a valid hash: %.*s", (int)tkn->len, tkn->str);
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
		pr_err("Delta serial %s is larger than Notification serial %s",
		    src->serial.str, rdr->c.notif.id.serial.str);
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
accept_notif_snapshot_attrs(struct rrdp_xml_reader *rdr)
{
	char const *TAG = "snapshot";
	struct xml_token key, equals, val;
	enum token_read_result res;

	pr_clutter("State: notif_snapshot_attr");

	res = next_bkp_tkn(rdr, &rdr->tkn1, &key);
	if (res != TRR_OK)
		return res;

	if (key.type == XTT_CLOSING_CLOSURE) {
		if (uri_str(&rdr->c.notif.snapshot.uri) == NULL)
			return fail_missing_attr(TAG, "uri");
		if (!rdr->c.notif.snapshot.hash.set)
			return fail_missing_attr(TAG, "hash");

		rdr->consume = accept_root_content;
		return res;
	}

	if (key.type != XTT_STR)
		return fail_unexpected_token(&key);

	res = next_bkp_tkn(rdr, &rdr->tkn2, &equals);
	if (res != TRR_OK)
		return res;
	res = expect_tkn_type(&equals, XTT_EQUALS, "equals");
	if (res != TRR_OK)
		return res;

	res = expect_quoted(rdr, &val);
	if (res != TRR_OK)
		return res;

	if (tkn_equals(&key, "uri")) {
		return uri_str(&rdr->c.notif.snapshot.uri)
		    ? fail_multiple_attrs(TAG, "uri")
		    : init_notif_uri(rdr, &rdr->c.notif.snapshot.uri, &val, "Snapshot");

	} else if (tkn_equals(&key, "hash")) {
		return rdr->c.notif.snapshot.hash.set
		    ? fail_multiple_attrs(TAG, "hash")
		    : init_hash(&rdr->c.notif.snapshot, &val);
	}

	return fail_unknown_attr(TAG, &key);
}

static enum token_read_result
accept_notif_delta_attrs(struct rrdp_xml_reader *rdr)
{
	char const *TAG = "delta";
	struct xml_token key, equals, val;
	enum token_read_result res;

	pr_clutter("State: notif_delta_attrs");

	res = next_bkp_tkn(rdr, &rdr->tkn1, &key);
	if (res != TRR_OK)
		return res;

	if (key.type == XTT_CLOSING_CLOSURE) {
		if (rdr->c.notif.delta.serial.str == NULL)
			return fail_missing_attr(TAG, "serial");
		if (uri_str(&rdr->c.notif.delta.meta.uri) == NULL)
			return fail_missing_attr(TAG, "uri");
		if (!rdr->c.notif.delta.meta.hash.set)
			return fail_missing_attr(TAG, "hash");

		res = commit_serial(rdr);
		if (res != TRR_OK)
			return res;

		rdr->c.notif.ndeltas++;
		rdr->consume = accept_root_content;
		return res;
	}

	if (key.type != XTT_STR)
		return fail_unexpected_token(&key);

	res = next_bkp_tkn(rdr, &rdr->tkn2, &equals);
	if (res != TRR_OK)
		return res;
	res = expect_tkn_type(&equals, XTT_EQUALS, "equals");
	if (res != TRR_OK)
		return res;

	res = expect_quoted(rdr, &val);
	if (res != TRR_OK)
		return res;

	if (tkn_equals(&key, "serial")) {
		if (rdr->c.notif.delta.serial.str != NULL)
			return fail_multiple_attrs(TAG, "serial");
		return init_serial(&rdr->c.notif.delta.serial, &val);

	} else if (tkn_equals(&key, "uri")) {
		return uri_str(&rdr->c.notif.delta.meta.uri)
		    ? fail_multiple_attrs(TAG, "uri")
		    : init_notif_uri(rdr, &rdr->c.notif.delta.meta.uri, &val, "Delta");

	} else if (tkn_equals(&key, "hash")) {
		return rdr->c.notif.delta.meta.hash.set
		    ? fail_multiple_attrs(TAG, "hash")
		    : init_hash(&rdr->c.notif.delta.meta, &val);
	}

	return fail_unknown_attr(TAG, &key);
}

static enum token_read_result
accept_publish_closure(struct rrdp_xml_reader *rdr)
{
	struct xml_token tkn;
	enum token_read_result res;

	res = next_bkp_tkn(rdr, &rdr->tkn1, &tkn);
	if (res != TRR_OK)
		return res;
	res = expect_string(&tkn, "publish");
	if (res != TRR_OK)
		return res;

	res = next_bkp_tkn(rdr, &rdr->tkn2, &tkn);
	if (res != TRR_OK)
		return res;
	res = expect_tkn_type(&tkn, XTT_CLOSE_TAG, "close tag");
	if (res != TRR_OK)
		return res;

	rdr->consume = accept_root_content;
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
accept_publish_content(struct rrdp_xml_reader *rdr)
{
	enum token_read_result res;
	char chr;
	unsigned char hash[EVP_MAX_MD_SIZE];
	array_index i;

	pr_clutter("State: publish_content");

	res = find_non_whitespace(rdr);
	if (res != TRR_OK)
		return res;

	chr = rdr->buf[rdr->offset];
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
			rdr->offset += 2;
			rdr->consume = accept_publish_closure;
			return TRR_OK;
		case '!':
			res = get_char(rdr, 2u, &chr);
			if (res != TRR_OK)
				return res;
			if (chr != '-') {
				pr_err("Unexpected token: <!%c", chr);
				return TRR_ERR;
			}

			return skip_comment(rdr);
		default:
			pr_err("Unexpected token: <");
			return TRR_ERR;
		}
	}

	if (!is_base64Binary(chr)) {
		pr_err("Unrecognized base64 character: %c (0x%02x)", chr, chr);
		return TRR_ERR;
	}

	for (i = rdr->offset + 1; i < rdr->buflen; i++)
		if (!is_base64Binary(rdr->buf[i]))
			break;
	if (b64d2f_write(&rdr->c.sd.b64, rdr->buf + rdr->offset, i - rdr->offset) != 0)
		return TRR_ERR;
	rdr->offset = i;
	return TRR_OK;
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
validate_hash2(struct file_metadata *meta, unsigned char const *hash)
{
	if (memcmp(meta->hash.bytes, hash, SHA256_DIGEST_LENGTH) != 0)
		goto bad;
	return 0;

bad:	return pr_err("File '%s' does not match its expected hash.",
	    uri_str(&meta->uri));
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
			pr_err("RRDP desync: "
			    "<publish> is attempting to create '%s', "
			    "but the file is already cached.",
			    uri_str(&rdr->c.sd.file.uri));
			return TRR_ERR;
		}

		if (validate_hash2(&rdr->c.sd.file, fileref->file->hash) != 0)
			return TRR_ERR;

		HASH_DEL(rdr->rrdp_filerefs->ht, fileref);
		fileref_free(fileref, true);

	} else {
		if (rdr->c.sd.file.hash.set) {
			// XXX watch out for this in the log before release
			pr_err("RRDP desync: "
			    "<publish> is attempting to overwrite '%s', "
			    "but the file is absent in the cache.",
			    uri_str(&rdr->c.sd.file.uri));
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
accept_publish_attrs(struct rrdp_xml_reader *rdr)
{
	char const *TAG = "publish";
	struct xml_token key, equals, val;
	enum token_read_result res;

	pr_clutter("State: publish_attrs");

	res = next_bkp_tkn(rdr, &rdr->tkn1, &key);
	if (res != TRR_OK)
		return res;

	if (key.type == XTT_CLOSE_TAG) {
		if (uri_str(&rdr->c.sd.file.uri) == NULL)
			return fail_missing_attr(TAG, "uri");

		res = start_publish(rdr);
		if (res != TRR_OK)
			return res;

		rdr->consume = accept_publish_content;
		return TRR_OK;
	}

	if (key.type != XTT_STR)
		return fail_unexpected_token(&key);

	res = next_bkp_tkn(rdr, &rdr->tkn2, &equals);
	if (res != TRR_OK)
		return res;
	res = expect_tkn_type(&equals, XTT_EQUALS, "equals");
	if (res != TRR_OK)
		return res;

	res = expect_quoted(rdr, &val);
	if (res != TRR_OK)
		return res;

	if (tkn_equals(&key, "uri")) {
		return uri_str(&rdr->c.sd.file.uri)
		    ? fail_multiple_attrs(TAG, "uri")
		    : init_uri(&rdr->c.sd.file.uri, &val);

	} else if (rdr->type == RXT_DELTA && tkn_equals(&key, "hash")) {
		return rdr->c.sd.file.hash.set
		    ? fail_multiple_attrs(TAG, "hash")
		    : init_hash(&rdr->c.sd.file, &val);
	}

	return fail_unknown_attr(TAG, &key);
}

static enum token_read_result
run_withdraw(struct rrdp_xml_reader *rdr)
{
	struct cache_file_ref *fileref;

	if (!is_known_extension(&rdr->c.sd.file.uri))
		return TRR_OK; /* Mirror rsync filters */

	fileref = filerefs_find_uri(rdr->rrdp_filerefs, &rdr->c.sd.file.uri);

	if (!fileref) {
		pr_err("Broken RRDP: "
		    "<withdraw> is attempting to delete unknown file '%s'.",
		    uri_str(&rdr->c.sd.file.uri));
		return TRR_ERR;
	}

	if (validate_hash2(&rdr->c.sd.file, fileref->file->hash) != 0)
		return TRR_ERR;

	HASH_DEL(rdr->rrdp_filerefs->ht, fileref);
	fileref_free(fileref, true);
	return TRR_OK;
}

static enum token_read_result
accept_withdraw_attrs(struct rrdp_xml_reader *rdr)
{
	char const *TAG = "withdraw";
	struct xml_token key, equals, val;
	enum token_read_result res;

	pr_clutter("State: withdraw_attrs");

	res = next_bkp_tkn(rdr, &rdr->tkn1, &key);
	if (res != TRR_OK)
		return res;

	if (key.type == XTT_CLOSING_CLOSURE) {
		if (uri_str(&rdr->c.sd.file.uri) == NULL)
			return fail_missing_attr(TAG, "uri");
		if (!rdr->c.sd.file.hash.set)
			return fail_missing_attr(TAG, "hash");

		res = run_withdraw(rdr);
		if (res != TRR_OK)
			return res;

		cleanup_sd(rdr);
		rdr->consume = accept_root_content;
		return res;
	}

	if (key.type != XTT_STR)
		return fail_unexpected_token(&key);

	res = next_bkp_tkn(rdr, &rdr->tkn2, &equals);
	if (res != TRR_OK)
		return res;
	res = expect_tkn_type(&equals, XTT_EQUALS, "equals");
	if (res != TRR_OK)
		return res;
	res = expect_quoted(rdr, &val);
	if (res != TRR_OK)
		return res;

	if (tkn_equals(&key, "uri")) {
		return uri_str(&rdr->c.sd.file.uri)
		    ? fail_multiple_attrs(TAG, "uri")
		    : init_uri(&rdr->c.sd.file.uri, &val);

	} else if (tkn_equals(&key, "hash")) {
		return rdr->c.sd.file.hash.set
		    ? fail_multiple_attrs(TAG, "hash")
		    : init_hash(&rdr->c.sd.file, &val);
	}

	return fail_unknown_attr(TAG, &key);
}

static enum token_read_result
accept_root_content(struct rrdp_xml_reader *rdr)
{
	enum token_read_result res;
	struct xml_token tkn;

	pr_clutter("State: root_content");

	res = next_bkp_tkn(rdr, &rdr->tkn1, &tkn);
	if (res != TRR_OK)
		return res;

	if (tkn.type == XTT_OPENING_CLOSURE) {
		res = next_bkp_tkn(rdr, &rdr->tkn2, &tkn);
		if (res != TRR_OK)
			return res;
		res = expect_string(&tkn, rdr->type_str);
		if (res != TRR_OK)
			return res;
		res = next_token(rdr, &tkn);
		if (res != TRR_OK)
			return res;
		res = expect_tkn_type(&tkn, XTT_CLOSE_TAG, "close tag");
		if (res != TRR_OK)
			return res;
		rdr->offset += tkn.len;

		if (rdr->type == RXT_NOTIF &&
		    uri_str(&rdr->c.notif.snapshot.uri) == NULL) {
			pr_err("Notification lacks a Snapshot");
			return TRR_ERR;
		}

		rdr->flags |= RXRF_DONE;
		return TRR_OK;
	}

	if (tkn.type != XTT_OPEN_TAG)
		return fail_unexpected_token(&tkn);

	res = next_bkp_tkn(rdr, &rdr->tkn2, &tkn);
	if (res != TRR_OK)
		return res;
	if (tkn.type != XTT_STR)
		return fail_unexpected_token(&tkn);

	switch (rdr->type) {
	case RXT_NOTIF:
		if (tkn_equals(&tkn, "snapshot")) {
			rdr->consume = accept_notif_snapshot_attrs;
			return TRR_OK;
		}
		if (tkn_equals(&tkn, "delta")) {
			rdr->consume = accept_notif_delta_attrs;
			return TRR_OK;
		}
		break;

	case RXT_SNAPSHOT:
		if (tkn_equals(&tkn, "publish")) {
			rdr->consume = accept_publish_attrs;
			return TRR_OK;
		}
		break;

	case RXT_DELTA:
		if (tkn_equals(&tkn, "publish")) {
			rdr->consume = accept_publish_attrs;
			return TRR_OK;
		}
		if (tkn_equals(&tkn, "withdraw")) {
			rdr->consume = accept_withdraw_attrs;
			return TRR_OK;
		}
		break;
	}

	return fail_unexpected_token(&tkn);
}

static int
check_session_chars(struct xml_token *val)
{
	array_index v;
	unsigned char chr;

	if (val->len == 0)
		return pr_err("session_id is an empty string");

	for (v = 0; v < val->len; v++) {
		chr = (unsigned char)(val->str[v]);
		if (!is_printable(chr))
			return pr_err("session_id has illegal character: "
			    "0x%02x", chr);
		if (!is_alphanumeric(chr) && chr != '-')
			return pr_err("session_id has illegal character: "
			    "%c", chr);
	}

	return 0;
}

static enum token_read_result
parse_root_session_attr(struct rrdp_xml_reader *rdr, struct xml_token *val)
{
	if (rdr->flags & RXRF_SESSION_SET)
		return fail_multiple_attrs(rdr->type_str, "session_id");
	rdr->flags |= RXRF_SESSION_SET;

	if (rdr->type == RXT_NOTIF) {
		if (check_session_chars(val) != 0)
			return TRR_ERR;
		rdr->c.notif.id.session_id = pstrndup(val->str, val->len);
		return TRR_OK;
	}

	if (tkn_equals(val, rdr->c.sd.notif_id->session_id))
		return TRR_OK;

	pr_err("%s session_id '%.*s' does not match Notification session_id '%s'",
	    rdr->type_str_camel, (int)val->len, val->str,
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
		return fail_multiple_attrs(rdr->type_str, "serial");
	rdr->flags |= RXRF_SERIAL_SET;

	if (val->len > MAX_SERIAL_SIZE) {
		pr_err("%s serial is too long: %zu chars",
		    rdr->type_str_camel, val->len);
		return TRR_ERR;
	}

	if (rdr->type == RXT_NOTIF) {
		res = init_serial(&rdr->c.notif.id.serial, val);
		if (res != TRR_OK)
			return res;
		res = init_min_serial(rdr);
		if (res != TRR_OK)
			return res;
		return init_deltas_array(rdr); /* Happy path */
	}

	res = init_serial(&subserial, val);
	if (res != TRR_OK)
		return res;
	cmp = BN_cmp(rdr->c.sd.notif_id->serial.num, subserial.num);
	serial_cleanup(&subserial);

	if (cmp == 0)
		return TRR_OK; /* Happy path */

	pr_err("%s serial '%.*s' does not match Notification serial '%s'",
	    rdr->type_str_camel, (int)val->len, val->str,
	    rdr->c.sd.notif_id->serial.str);
	return TRR_ERR;
}

static enum token_read_result
accept_root_attrs(struct rrdp_xml_reader *rdr)
{
	char const *RRDP_XMLNS = "http://www.ripe.net/rpki/rrdp";
	char const *RRDP_VER = "1";
	char const *TAG = rdr->type_str;
	struct xml_token key, equals, val;
	enum token_read_result res;

	pr_clutter("State: root_attrs");

	res = next_bkp_tkn(rdr, &rdr->tkn1, &key);
	if (res != TRR_OK)
		return res;

	if (key.type == XTT_CLOSE_TAG) {
		if (!(rdr->flags & RXRF_XMLNS_SET))
			return fail_missing_attr(TAG, "xmlns");
		if (!(rdr->flags & RXRF_VERSION_SET))
			return fail_missing_attr(TAG, "version");
		if (!(rdr->flags & RXRF_SESSION_SET))
			return fail_missing_attr(TAG, "session");
		if (!(rdr->flags & RXRF_SERIAL_SET))
			return fail_missing_attr(TAG, "serial");
		rdr->consume = accept_root_content;
		return res;
	}

	if (key.type != XTT_STR)
		return fail_unexpected_token(&key);

	res = next_bkp_tkn(rdr, &rdr->tkn2, &equals);
	if (res != TRR_OK)
		return res;
	res = expect_tkn_type(&equals, XTT_EQUALS, "equals");
	if (res != TRR_OK)
		return res;

	res = expect_quoted(rdr, &val);
	if (res != TRR_OK)
		return res;

	if (tkn_equals(&key, "xmlns")) {
		if (rdr->flags & RXRF_XMLNS_SET)
			return fail_multiple_attrs(TAG, "xmlns");
		if (!tkn_equals(&val, RRDP_XMLNS))
			return fail_attr_value(TAG, "xmlns", RRDP_XMLNS, &val);
		rdr->flags |= RXRF_XMLNS_SET;
		return TRR_OK;

	} else if (tkn_equals(&key, "version")) {
		if (rdr->flags & RXRF_VERSION_SET)
			return fail_multiple_attrs(TAG, "version");
		if (!tkn_equals(&val, RRDP_VER))
			return fail_attr_value(TAG, "version", RRDP_VER, &val);
		rdr->flags |= RXRF_VERSION_SET;
		return TRR_OK;

	} else if (tkn_equals(&key, "session_id")) {
		return parse_root_session_attr(rdr, &val);

	} else if (tkn_equals(&key, "serial")) {
		return parse_root_serial_attr(rdr, &val);
	}

	return fail_unknown_attr(TAG, &key);
}

static enum token_read_result
accept_root_tag(struct rrdp_xml_reader *rdr)
{
	struct xml_token tkn;
	enum token_read_result res;

	pr_clutter("State: root_tag");

	/*
	 * Sometimes, libcurl feeds us input that's not RRDP XML.
	 * For example, if the server wants to redirect us, we'll get HTTP
	 * (containing HTTP code 30X).
	 *
	 * When this happens, we don't want to return parse error, because that
	 * will result in immediate request termination. What libcurl seems to
	 * expect us to do is ignore the input. This results in automatic
	 * redirect handling (mostly done by libcurl).
	 *
	 * So I guess we're supposed to identify the root tag as a magic header,
	 * and if it's not there, slip through all remaining input.
	 */

	res = next_bkp_tkn(rdr, &rdr->tkn1, &tkn);
	if (res != TRR_OK)
		return res;
	if (tkn.type != XTT_OPEN_TAG)
		goto not_magic;

	res = next_bkp_tkn(rdr, &rdr->tkn2, &tkn);
	if (res != TRR_OK)
		return res;
	if (tkn.type != XTT_STR || !tkn_equals(&tkn, rdr->type_str))
		goto not_magic;

	rdr->consume = accept_root_attrs;
	return TRR_OK;

not_magic:
	rdr->flags |= RXRF_DONE;
	return TRR_OK;
}

static struct rrdp_xml_reader *
rrdp_xml_create(enum rrdp_xml_type type)
{
	struct rrdp_xml_reader *result;

	result = pmalloc(sizeof(struct rrdp_xml_reader));

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
	result->notif_uri = NULL;

	result->offset = 0;
	result->buflen = 0;
	result->tkn1.meta.str = (char *)result->tkn1.buf;
	result->tkn1.meta.len = 0;
	result->tkn2.meta.str = (char *)result->tkn2.buf;
	result->tkn2.meta.len = 0;
	result->consume = accept_root_tag;
	result->flags = 0;
	memset(&result->c, 0, sizeof(result->c));
	result->rrdp_filerefs = NULL;
	result->rrdp_seq = NULL;

	return result;
}

static int
rrdp_xml_parse(struct rrdp_xml_reader *rdr, char const *in, size_t inlen)
{
	size_t cp;

	while (inlen > 0) {
		if (rdr->offset > 0) {
			rdr->buflen -= rdr->offset;
			memmove(rdr->buf, rdr->buf + rdr->offset, rdr->buflen);
			rdr->offset = 0;
		}

		cp = XML_BUF_SIZE - rdr->buflen;
		if (cp > inlen)
			cp = inlen;
		memcpy(rdr->buf + rdr->buflen, in, cp);
		rdr->buflen += cp;
		in += cp;
		inlen -= cp;

again:		switch (rdr->consume(rdr)) {
		case TRR_OK:
			if (rdr->flags & RXRF_DONE)
				return 0;
			rdr->tkn1.meta.len = 0;
			rdr->tkn2.meta.len = 0;
			goto again;
		case TRR_ERR:
			return EINVAL;
		case TRR_MORE:
			break;
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

	if (arg->rdr->flags & RXRF_DONE)
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

	if (!(*changed)) {
		pr_trc("The Notification has not changed.");
		goto end;
	}

	if (!(wargs.rdr->flags & RXRF_DONE)) {
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
