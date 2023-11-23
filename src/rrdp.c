#include "rrdp.h"

#include <ctype.h>
#include <openssl/bn.h>
#include <openssl/evp.h>

#include "alloc.h"
#include "common.h"
#include "file.h"
#include "log.h"
#include "thread_var.h"
#include "cache/local_cache.h"
#include "crypto/base64.h"
#include "crypto/hash.h"
#include "xml/relax_ng.h"

/* RRDP's XML namespace */
#define RRDP_NAMESPACE		"http://www.ripe.net/rpki/rrdp"

/* XML tags */
#define RRDP_ELEM_NOTIFICATION	"notification"
#define RRDP_ELEM_SNAPSHOT	"snapshot"
#define RRDP_ELEM_DELTA		"delta"
#define RRDP_ELEM_PUBLISH	"publish"
#define RRDP_ELEM_WITHDRAW	"withdraw"

/* XML attributes */
#define RRDP_ATTR_VERSION	"version"
#define RRDP_ATTR_SESSION_ID	"session_id"
#define RRDP_ATTR_SERIAL	"serial"
#define RRDP_ATTR_URI		"uri"
#define RRDP_ATTR_HASH		"hash"

/* These are supposed to be unbounded */
struct rrdp_serial {
	BIGNUM *num;
	xmlChar *str; /* for printing */
};

struct rrdp_session {
	xmlChar *session_id;
	struct rrdp_serial serial;
};

/* The hash is sometimes omitted. */
struct file_metadata {
	struct rpki_uri *uri;
	unsigned char *hash;
	size_t hash_len;
};

/* A delta tag, listed by a notification. (Not the actual delta file.) */
struct notification_delta {
	struct rrdp_serial serial;
	struct file_metadata meta;
};

/* An array of delta tags, listed by a notification. */
STATIC_ARRAY_LIST(notification_deltas, struct notification_delta)

/* A deserialized "Update Notification" file (aka "Notification"). */
struct update_notification {
	struct rrdp_session session;
	struct file_metadata snapshot;
	struct notification_deltas deltas;
	struct rpki_uri *uri;
};

/* A deserialized <publish> tag, from a snapshot or delta. */
struct publish {
	struct file_metadata meta;
	unsigned char *content;
	size_t content_len;
};

/* A deserialized <withdraw> tag, from a delta. */
struct withdraw {
	struct file_metadata meta;
};

/* Helpful context while reading a snapshot or delta. */
struct rrdp_ctx {
	struct rpki_uri *notif;
	struct rrdp_session session;
};

typedef enum {
	HR_MANDATORY,
	HR_OPTIONAL,
	HR_IGNORE,
} hash_requirement;

static BIGNUM *
BN_create(void)
{
	BIGNUM *result = BN_new();
	if (result == NULL)
		enomem_panic();
	return result;
}

static void
serial_cleanup(struct rrdp_serial *serial)
{
	BN_free(serial->num);
	serial->num = NULL;
	xmlFree(serial->str);
	serial->str = NULL;
}

static void
session_cleanup(struct rrdp_session *meta)
{
	xmlFree(meta->session_id);
	BN_free(meta->serial.num);
	xmlFree(meta->serial.str);
}

static void
metadata_cleanup(struct file_metadata *meta)
{
	free(meta->hash);
	uri_refput(meta->uri);
}

static void
notification_delta_cleanup(struct notification_delta *delta)
{
	serial_cleanup(&delta->serial);
	metadata_cleanup(&delta->meta);
}

static void
update_notification_init(struct update_notification *notif,
    struct rpki_uri *uri)
{
	memset(&notif->session, 0, sizeof(notif->session));
	memset(&notif->snapshot, 0, sizeof(notif->snapshot));
	notification_deltas_init(&notif->deltas);
	notif->uri = uri_refget(uri);
}

static void
update_notification_cleanup(struct update_notification *file)
{
	metadata_cleanup(&file->snapshot);
	session_cleanup(&file->session);
	notification_deltas_cleanup(&file->deltas, notification_delta_cleanup);
	uri_refput(file->uri);
}

static int
validate_hash(struct file_metadata *meta)
{
	return hash_validate_file(meta->uri, meta->hash, meta->hash_len);
}

/* Left trim @from, setting the result at @result pointer */
static int
ltrim(char const *from, char const **result, size_t *result_size)
{
	char const *start;
	size_t tmp_size;

	start = from;
	tmp_size = strlen(from);
	while (isspace(*start)) {
		start++;
		tmp_size--;
	}
	if (*start == '\0')
		return pr_val_err("Invalid base64 encoded string (seems to be empty or full of spaces).");

	*result = start;
	*result_size = tmp_size;
	return 0;
}

/*
 * Get the base64 chars from @content and allocate to @out with lines no greater
 * than 65 chars (including line feed).
 *
 * Why? LibreSSL doesn't like lines greater than 80 chars, so use a common
 * length per line.
 */
static int
base64_sanitize(char const *content, char **out)
{
#define BUF_SIZE 65
	char *result;
	char const *tmp;
	size_t original_size, new_size;
	size_t offset, buf_len;
	int error;

	original_size = 0;
	error = ltrim(content, &tmp, &original_size);
	if (error)
		return error;

	if (original_size <= BUF_SIZE) {
		*out = pstrdup(content);
		return 0;
	}

	new_size = original_size + (original_size / BUF_SIZE);
	result = pmalloc(new_size + 1);

	offset = 0;
	while (original_size > 0){
		buf_len = original_size > BUF_SIZE ? BUF_SIZE : original_size;
		memcpy(&result[offset], tmp, buf_len);
		tmp += buf_len;
		offset += buf_len;
		original_size -= buf_len;

		if (original_size <= 0)
			break;
		result[offset] = '\n';
		offset++;
	}

	/* Reallocate to exact size and add nul char */
	if (offset != new_size + 1)
		result = prealloc(result, offset + 1);

	result[offset] = '\0';
	*out = result;
	return 0;
#undef BUF_SIZE
}

static int
base64_read(char const *content, unsigned char **out, size_t *out_len)
{
	BIO *encoded; /* base64 encoded. */
	unsigned char *result;
	char *sanitized;
	size_t alloc_size;
	size_t result_len;
	int error;

	sanitized = NULL;
	error = base64_sanitize(content, &sanitized);
	if (error)
		return error;

	encoded = BIO_new_mem_buf(sanitized, -1);
	if (encoded == NULL) {
		error = val_crypto_err("BIO_new_mem_buf() returned NULL");
		goto release_sanitized;
	}

	alloc_size = EVP_DECODE_LENGTH(strlen(content));
	result = pmalloc(alloc_size);

	if (!base64_decode(encoded, result, true, alloc_size, &result_len)) {
		error = val_crypto_err("Cannot decode publish tag's base64.");
		goto release_result;
	}

	free(sanitized);
	BIO_free(encoded);

	(*out) = result;
	(*out_len) = result_len;
	return 0;

release_result:
	free(result);
	BIO_free(encoded);
release_sanitized:
	free(sanitized);
	return error;
}

static int
parse_ulong(xmlTextReaderPtr reader, char const *attr, unsigned long *result)
{
	xmlChar *str;
	int error;

	str = xmlTextReaderGetAttribute(reader, BAD_CAST attr);
	if (str == NULL)
		return pr_val_err("RRDP file: Couldn't find xml attribute '%s'",
		    attr);

	errno = 0;
	*result = strtoul((char const *) str, NULL, 10);
	error = errno;
	xmlFree(str);
	if (error) {
		pr_val_err("RRDP file: Invalid long value '%s': %s",
		    str, strerror(error));
		return error;
	}

	return 0;
}

static xmlChar *
parse_string(xmlTextReaderPtr reader, char const *attr)
{
	xmlChar *result;

	if (attr == NULL) {
		result = xmlTextReaderValue(reader);
		if (result == NULL)
			pr_val_err("RRDP file: Couldn't find string content from '%s'",
			    xmlTextReaderConstLocalName(reader));
	} else {
		result = xmlTextReaderGetAttribute(reader, BAD_CAST attr);
		if (result == NULL)
			pr_val_err("RRDP file: Couldn't find xml attribute '%s' from tag '%s'",
			    attr, xmlTextReaderConstLocalName(reader));
	}

	return result;
}

static int
parse_hex_string(xmlTextReaderPtr reader, hash_requirement hr, char const *attr,
    unsigned char **result, size_t *result_len)
{
	xmlChar *xml_value;
	unsigned char *tmp, *ptr;
	char *xml_cur;
	char buf[2];
	size_t tmp_len;

	xml_value = xmlTextReaderGetAttribute(reader, BAD_CAST attr);
	if (xml_value == NULL)
		return (hr == HR_MANDATORY)
		    ? pr_val_err("RRDP file: Couldn't find xml attribute '%s'", attr)
		    : 0;

	/* The rest of the checks are done at the schema */
	if (xmlStrlen(xml_value) % 2 != 0) {
		xmlFree(xml_value);
		return pr_val_err("RRDP file: Attribute %s isn't a valid hex string",
		    attr);
	}

	tmp_len = xmlStrlen(xml_value) / 2;
	tmp = pzalloc(tmp_len);

	ptr = tmp;
	xml_cur = (char *) xml_value;
	while (ptr - tmp < tmp_len) {
		memcpy(buf, xml_cur, 2);
		*ptr = strtol(buf, NULL, 16);
		xml_cur+=2;
		ptr++;
	}
	xmlFree(xml_value);

	*result = tmp;
	(*result_len) = tmp_len;
	return 0;
}

static int
validate_version(xmlTextReaderPtr reader, unsigned long expected)
{
	unsigned long version = 0;
	int error;

	error = parse_ulong(reader, RRDP_ATTR_VERSION, &version);
	if (error)
		return error;

	if (version != expected)
		return pr_val_err("Invalid version, must be '%lu' and is '%lu'.",
		    expected, version);

	return 0;
}

static int
parse_serial(xmlTextReaderPtr reader, struct rrdp_serial *serial)
{
	serial->str = parse_string(reader, RRDP_ATTR_SERIAL);
	if (serial->str == NULL)
		return EINVAL;

	serial->num = BN_create();
	if (BN_dec2bn(&serial->num, (char const *) serial->str) == 0)
		goto fail;
	if (BN_is_negative(serial->num)) {
		pr_val_err("Serial '%s' is negative.", serial->str);
		goto fail;
	}

	return 0;

fail:
	serial_cleanup(serial);
	return EINVAL;
}

static int
parse_session(xmlTextReaderPtr reader, struct rrdp_session *meta)
{
	int error;

	/*
	 * The following rule appies to all files:
	 * - The XML namespace MUST be "http://www.ripe.net/rpki/rrdp".
	 * - The version attribute MUST be "1".
	 */
	if (!xmlStrEqual(xmlTextReaderConstNamespaceUri(reader),
	    BAD_CAST RRDP_NAMESPACE))
		return pr_val_err("Namespace isn't '%s', current value is '%s'",
		    RRDP_NAMESPACE, xmlTextReaderConstNamespaceUri(reader));

	error = validate_version(reader, 1);
	if (error)
		return error;

	meta->session_id = parse_string(reader, RRDP_ATTR_SESSION_ID);
	if (meta->session_id == NULL)
		return EINVAL;

	error = parse_serial(reader, &meta->serial);
	if (error) {
		xmlFree(meta->session_id);
		meta->session_id = NULL;
		return error;
	}

	return 0;
}

static int
validate_session(xmlTextReaderPtr reader, struct rrdp_session *expected)
{
	struct rrdp_session actual = { 0 };
	int error;

	error = parse_session(reader, &actual);
	if (error)
		return error;

	if (xmlStrcmp(expected->session_id, actual.session_id) != 0) {
		error = pr_val_err("File session id [%s] doesn't match notification's session id [%s]",
		    expected->session_id, actual.session_id);
		goto end;
	}

	if (BN_cmp(actual.serial.num, expected->serial.num) != 0) {
		error = pr_val_err("File serial [%s] doesn't match notification's serial [%s]",
		    actual.serial.str, expected->serial.str);
		goto end;
	}

end:
	session_cleanup(&actual);
	return error;
}

/*
 * Extracts the following two attributes from @reader's current tag:
 *
 * 1. "uri"
 * 2. "hash" (optional, depending on @hr)
 */
static int
parse_file_metadata(xmlTextReaderPtr reader, struct rpki_uri *notif,
    hash_requirement hr, struct file_metadata *meta)
{
	xmlChar *uri;
	int error;

	memset(meta, 0, sizeof(*meta));

	uri = parse_string(reader, RRDP_ATTR_URI);
	if (uri == NULL)
		return -EINVAL;
	error = uri_create(&meta->uri,
	    tal_get_file_name(validation_tal(state_retrieve())),
	    (notif != NULL) ? UT_CAGED : UT_HTTPS,
	    notif, (char const *)uri);
	xmlFree(uri);
	if (error)
		return error;

	if (hr == HR_IGNORE)
		return 0;

	error = parse_hex_string(reader, hr, RRDP_ATTR_HASH, &meta->hash,
	    &meta->hash_len);
	if (error) {
		uri_refput(meta->uri);
		meta->uri = NULL;
		return error;
	}

	return 0;
}

static int
parse_publish(xmlTextReaderPtr reader, struct rpki_uri *notif,
    hash_requirement hr, struct publish *tag)
{
	xmlChar *base64_str;
	int error;

	error = parse_file_metadata(reader, notif, hr, &tag->meta);
	if (error)
		return error;

	/* Read the text */
	if (xmlTextReaderRead(reader) != 1) {
		return pr_val_err(
		    "Couldn't read publish content of element '%s'",
		    uri_get_global(tag->meta.uri)
		);
	}

	base64_str = parse_string(reader, NULL);
	if (base64_str == NULL)
		return -EINVAL;
	error = base64_read((char const *)base64_str, &tag->content,
	    &tag->content_len);
	xmlFree(base64_str);
	if (error)
		return error;

	/* rfc8181#section-2.2 but considering optional hash */
	if (tag->meta.hash_len > 0)
		error = validate_hash(&tag->meta);

	return error;
}

static int
parse_withdraw(xmlTextReaderPtr reader, struct rpki_uri *notif,
    struct withdraw *tag)
{
	int error;

	error = parse_file_metadata(reader, notif, HR_MANDATORY, &tag->meta);
	if (error)
		return error;

	return validate_hash(&tag->meta);
}

static int
write_file(struct rpki_uri *uri, unsigned char *content, size_t content_len)
{
	FILE *out;
	size_t written;
	int error;

	error = mkdir_p(uri_get_local(uri), false);
	if (error)
		return error;

	error = file_write(uri_get_local(uri), &out);
	if (error)
		return error;

	written = fwrite(content, sizeof(unsigned char), content_len, out);
	file_close(out);

	if (written != content_len) {
		return pr_val_err(
		    "Couldn't write file '%s' (error code not available)",
		    uri_get_local(uri)
		);
	}

	return 0;
}

/* Remove a local file and its directory tree (if empty) */
static int
delete_file(struct rpki_uri *uri)
{
	/* Delete parent dirs only if empty. */
	return delete_dir_recursive_bottom_up(uri_get_local(uri));
}

static int
handle_publish(xmlTextReaderPtr reader, struct rpki_uri *notif,
    hash_requirement hr)
{
	struct publish tag = { 0 };
	int error;

	error = parse_publish(reader, notif, hr, &tag);
	if (!error)
		error = write_file(tag.meta.uri, tag.content, tag.content_len);

	metadata_cleanup(&tag.meta);
	free(tag.content);
	return error;
}

static int
handle_withdraw(xmlTextReaderPtr reader, struct rpki_uri *notif)
{
	struct withdraw tag = { 0 };
	int error;

	error = parse_withdraw(reader, notif, &tag);
	if (!error)
		error = delete_file(tag.meta.uri);

	metadata_cleanup(&tag.meta);
	return error;
}

static int
parse_notification_delta(xmlTextReaderPtr reader,
    struct update_notification *notif)
{
	struct notification_delta delta;
	int error;

	error = parse_serial(reader, &delta.serial);
	if (error)
		return error;

	error = parse_file_metadata(reader, NULL, HR_MANDATORY, &delta.meta);
	if (error) {
		serial_cleanup(&delta.serial);
		return error;
	}

	notification_deltas_add(&notif->deltas, &delta);
	return 0;
}

static int
swap_until_sorted(struct notification_delta *deltas, array_index i,
    BIGNUM *min, struct rrdp_serial *max, BIGNUM *target_slot)
{
	BN_ULONG _target_slot;
	struct notification_delta tmp;

	while (true) {
		if (BN_cmp(deltas[i].serial.num, min) < 0) {
			char *str = BN_bn2dec(min);
			pr_val_err(
			    "Deltas: Serial '%s' is out of bounds. (min:%s)",
			    deltas[i].serial.str, str);
			OPENSSL_free(str);
			return -EINVAL;
		}
		if (BN_cmp(max->num, deltas[i].serial.num) < 0)
			return pr_val_err(
			    "Deltas: Serial '%s' is out of bounds. (max:%s)",
			    deltas[i].serial.str, max->str);

		if (!BN_sub(target_slot, deltas[i].serial.num, min))
			return val_crypto_err("BN_sub() returned error.");
		_target_slot = BN_get_word(target_slot);
		if (i == _target_slot)
			return 0;
		if (BN_cmp(deltas[_target_slot].serial.num, deltas[i].serial.num) == 0) {
			return pr_val_err("Deltas: Serial '%s' is not unique.",
			    deltas[i].serial.str);
		}

		/* Simple swap */
		tmp = deltas[_target_slot];
		deltas[_target_slot] = deltas[i];
		deltas[i] = tmp;
	}
}

static int
sort_deltas(struct update_notification *notif)
{
	struct notification_deltas *deltas;
	BIGNUM *min_serial;
	struct rrdp_serial *max_serial;
	BIGNUM *aux;
	array_index i;
	int error;

	/*
	 * Note: The RFC explicitly states that the serials have to be
	 * a "contiguous sequence."
	 * Effective linear sort FTW.
	 */

	deltas = &notif->deltas;
	if (deltas->len == 0)
		return 0;

	max_serial = &notif->session.serial;
	min_serial = BN_dup(max_serial->num);
	if (min_serial == NULL)
		return val_crypto_err("BN_dup() returned NULL.");
	if (!BN_sub_word(min_serial, deltas->len - 1)) {
		error = pr_val_err("Could not subtract %s - %zu; unknown cause.",
		    notif->session.serial.str, deltas->len - 1);
		goto end;
	}
	if (BN_is_negative(min_serial)) {
		error = pr_val_err("Too many deltas (%zu) for serial %s. (Negative serials not implemented.)",
		    deltas->len, max_serial->str);
		goto end;
	}

	aux = BN_create();

	error = 0;
	ARRAYLIST_FOREACH_IDX(deltas, i) {
		error = swap_until_sorted(deltas->array, i, min_serial,
		    max_serial, aux);
		if (error)
			break;
	}

	BN_free(aux);
end:	BN_free(min_serial);
	return error;
}

static int
xml_read_notif(xmlTextReaderPtr reader, void *arg)
{
	struct update_notification *notif = arg;
	xmlChar const *name;

	name = xmlTextReaderConstLocalName(reader);
	switch (xmlTextReaderNodeType(reader)) {
	case XML_READER_TYPE_ELEMENT:
		if (xmlStrEqual(name, BAD_CAST RRDP_ELEM_DELTA)) {
			return parse_notification_delta(reader, notif);
		} else if (xmlStrEqual(name, BAD_CAST RRDP_ELEM_SNAPSHOT)) {
			return parse_file_metadata(reader, NULL, HR_MANDATORY,
			    &notif->snapshot);
		} else if (xmlStrEqual(name, BAD_CAST RRDP_ELEM_NOTIFICATION)) {
			/* No need to validate session ID and serial */
			return parse_session(reader, &notif->session);
		}

		return pr_val_err("Unexpected '%s' element", name);

	case XML_READER_TYPE_END_ELEMENT:
		if (xmlStrEqual(name, BAD_CAST RRDP_ELEM_NOTIFICATION))
			return sort_deltas(notif);
		break;
	}

	return 0;
}

static int
parse_notification(struct rpki_uri *uri, struct update_notification *result)
{
	int error;

	update_notification_init(result, uri);

	error = relax_ng_parse(uri_get_local(uri), xml_read_notif, result);
	if (error)
		update_notification_cleanup(result);

	return error;
}

static void
delete_rpp(char const *tal, struct rpki_uri *notif)
{
	char *path = uri_get_rrdp_workspace(tal, notif);
	pr_val_debug("Snapshot: Deleting cached RPP '%s'.", path);
	file_rm_rf(path);
	free(path);
}

static int
xml_read_snapshot(xmlTextReaderPtr reader, void *arg)
{
	struct rrdp_ctx *ctx = arg;
	xmlReaderTypes type;
	xmlChar const *name;
	int error;

	name = xmlTextReaderConstLocalName(reader);
	type = xmlTextReaderNodeType(reader);
	switch (type) {
	case XML_READER_TYPE_ELEMENT:
		if (xmlStrEqual(name, BAD_CAST RRDP_ELEM_PUBLISH))
			error = handle_publish(reader, ctx->notif, HR_IGNORE);
		else if (xmlStrEqual(name, BAD_CAST RRDP_ELEM_SNAPSHOT))
			error = validate_session(reader, &ctx->session);
		else
			return pr_val_err("Unexpected '%s' element", name);
		if (error)
			return error;
		break;
	default:
		break;
	}

	return 0;
}

static int
parse_snapshot(struct update_notification *notif)
{
	struct rrdp_ctx ctx;
	int error;

	error = validate_hash(&notif->snapshot);
	if (error)
		return error;

	ctx.notif = notif->uri;
	ctx.session = notif->session;

	return relax_ng_parse(uri_get_local(notif->snapshot.uri),
	    xml_read_snapshot, &ctx);
}

static int
handle_snapshot(struct update_notification *notif)
{
	struct validation *state;
	struct rpki_uri *uri;
	int error;

	state = state_retrieve();

	delete_rpp(tal_get_file_name(validation_tal(state)), notif->uri);

	uri = notif->snapshot.uri;

	pr_val_debug("Processing snapshot '%s'.", uri_val_get_printable(uri));
	fnstack_push_uri(uri);

	error = cache_download(validation_cache(state), uri, NULL);
	if (error)
		goto end;
	error = parse_snapshot(notif);
	delete_file(uri);

end:
	fnstack_pop();
	return error;
}

static int
xml_read_delta(xmlTextReaderPtr reader, void *arg)
{
	struct rrdp_ctx *ctx = arg;
	xmlReaderTypes type;
	xmlChar const *name;
	int error;

	name = xmlTextReaderConstLocalName(reader);
	type = xmlTextReaderNodeType(reader);
	switch (type) {
	case XML_READER_TYPE_ELEMENT:
		if (xmlStrEqual(name, BAD_CAST RRDP_ELEM_PUBLISH))
			error = handle_publish(reader, ctx->notif, HR_OPTIONAL);
		else if (xmlStrEqual(name, BAD_CAST RRDP_ELEM_WITHDRAW))
			error = handle_withdraw(reader, ctx->notif);
		else if (xmlStrEqual(name, BAD_CAST RRDP_ELEM_DELTA))
			error = validate_session(reader, &ctx->session);
		else
			return pr_val_err("Unexpected '%s' element", name);
		if (error)
			return error;
		break;
	default:
		break;
	}

	return 0;
}

static int
parse_delta(struct update_notification *notif, struct notification_delta *delta)
{
	struct rrdp_ctx ctx;
	int error;

	error = validate_hash(&delta->meta);
	if (error)
		return error;

	ctx.notif = notif->uri;
	ctx.session.session_id = notif->session.session_id;
	ctx.session.serial = delta->serial;

	return relax_ng_parse(uri_get_local(delta->meta.uri), xml_read_delta,
	    &ctx);
}

static int
handle_delta(struct update_notification *notif, struct notification_delta *delta)
{
	struct rpki_uri *uri;
	int error;

	uri = delta->meta.uri;

	pr_val_debug("Processing delta '%s'.", uri_val_get_printable(uri));
	fnstack_push_uri(uri);

	error = cache_download(validation_cache(state_retrieve()), uri, NULL);
	if (error)
		goto end;
	error = parse_delta(notif, delta);
	delete_file(uri);

end:
	fnstack_pop();
	return error;
}

static int
handle_deltas(struct update_notification *notif, struct rrdp_serial *serial)
{
	BIGNUM *diff_bn;
	BN_ULONG diff;
	array_index d;
	int error;

	/* No elements, send error so that the snapshot is processed */
	if (notif->deltas.len == 0) {
		pr_val_warn("There's no delta list to process.");
		return -ENOENT;
	}

	pr_val_debug("Handling RRDP delta serials %s-%s.", serial->str,
	    notif->session.serial.str);

	diff_bn = BN_create();
	if (!BN_sub(diff_bn, notif->session.serial.num, serial->num)) {
		BN_free(diff_bn);
		return pr_val_err("Could not subtract %s - %s; unknown cause.",
		    notif->session.serial.str, serial->str);
	}
	if (BN_is_negative(diff_bn)) {
		BN_free(diff_bn);
		return pr_val_err("Cached delta's serial [%s] is larger than Notification's current serial [%s].",
		    serial->str, notif->session.serial.str);
	}
	diff = BN_get_word(diff_bn);
	BN_free(diff_bn);
	/* TODO (fine) 64 may be too much; optimize it. */
	if (diff > 64ul || diff > notif->deltas.len)
		return pr_val_err("Cached RPP is too old. (Cached serial: %s; current serial: %s)",
		    serial->str, notif->session.serial.str);

	for (d = notif->deltas.len - diff; d < notif->deltas.len; d++) {
		error = handle_delta(notif, &notif->deltas.array[d]);
		if (error)
			return error;
	}

	return 0;
}

static int
get_metadata(struct rpki_uri *uri, struct rrdp_session *result)
{
	struct stat st;
	struct update_notification notification;
	int error;

	if (stat(uri_get_local(uri), &st) != 0) {
		error = errno;
		return (error == ENOENT) ? 0 : error;
	}

	/*
	 * TODO (fine) optimize by not reading everything,
	 * or maybe keep it if it doesn't change.
	 */
	error = parse_notification(uri, &notification);
	if (error)
		return error;

	*result = notification.session;
	memset(&notification.session, 0, sizeof(notification.session));
	update_notification_cleanup(&notification);
	return 0;
}

/*
 * Downloads the Update Notification pointed by @uri, and updates the cache
 * accordingly.
 *
 * "Updates the cache accordingly" means it downloads the missing deltas or
 * snapshot, and explodes them into the corresponding RPP's local directory.
 */
int
rrdp_update(struct rpki_uri *uri)
{
	struct rrdp_session old = { 0 };
	struct update_notification new;
	bool changed;
	int error;

	fnstack_push_uri(uri);
	pr_val_debug("Processing notification.");

	error = get_metadata(uri, &old);
	if (error)
		goto end;
	pr_val_debug("Old session/serial: %s/%s", old.session_id,
	    old.serial.str);

	error = cache_download(validation_cache(state_retrieve()), uri, &changed);
	if (error)
		goto end;
	if (!changed) {
		pr_val_debug("The Notification has not changed.");
		goto end;
	}

	error = parse_notification(uri, &new);
	if (error)
		goto end;
	pr_val_debug("New session/serial: %s/%s", new.session.session_id,
	    new.session.serial.str);

	if (old.session_id == NULL || old.serial.num == NULL) {
		pr_val_debug("This is a new Notification.");
		error = handle_snapshot(&new);
		goto revert_notification;
	}

	if (xmlStrcmp(old.session_id, new.session.session_id) != 0) {
		pr_val_debug("The Notification's session ID changed.");
		error = handle_snapshot(&new);
		goto revert_notification;
	}

	if (BN_cmp(old.serial.num, new.session.serial.num) != 0) {
		pr_val_debug("The Notification's serial changed.");
		error = handle_deltas(&new, &old.serial);
		if (error) {
			pr_val_debug("Falling back to snapshot.");
			error = handle_snapshot(&new);
		}
		goto revert_notification;
	}

	pr_val_debug("The Notification changed, but the session ID and serial didn't.");

revert_notification:
	update_notification_cleanup(&new);
end:
	session_cleanup(&old);
	fnstack_pop();
	return error;
}
