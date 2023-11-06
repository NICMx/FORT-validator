#include "rrdp/rrdp_parser.h"

#include <ctype.h>
#include <openssl/evp.h>

#include "crypto/base64.h"
#include "crypto/hash.h"
#include "xml/relax_ng.h"
#include "alloc.h"
#include "common.h"
#include "file.h"
#include "log.h"
#include "thread_var.h"
#include "cache/local_cache.h"

/* XML Common Namespace of files */
#define RRDP_NAMESPACE		"http://www.ripe.net/rpki/rrdp"

/* XML Elements */
#define RRDP_ELEM_NOTIFICATION	"notification"
#define RRDP_ELEM_SNAPSHOT	"snapshot"
#define RRDP_ELEM_DELTA		"delta"
#define RRDP_ELEM_PUBLISH	"publish"
#define RRDP_ELEM_WITHDRAW	"withdraw"

/* XML Attributes */
#define RRDP_ATTR_VERSION	"version"
#define RRDP_ATTR_SESSION_ID	"session_id"
#define RRDP_ATTR_SERIAL	"serial"
#define RRDP_ATTR_URI		"uri"
#define RRDP_ATTR_HASH		"hash"

/* Context while reading a snapshot */
struct rdr_snapshot_ctx {
	/* Parent data to validate session ID and serial */
	struct update_notification *notif;
};

/* Context while reading a delta */
struct rdr_delta_ctx {
	/* Parent data to validate session ID */
	struct update_notification *notif;
	/* Current serial loaded from update notification deltas list */
	unsigned long expected_serial;
};

typedef enum {
	HR_MANDATORY,
	HR_OPTIONAL,
	HR_IGNORE,
} hash_requirement;

/* Left trim @from, setting the result at @result pointer */
static int
ltrim(char *from, char **result, size_t *result_size)
{
	char *start;
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
base64_sanitize(char *content, char **out)
{
#define BUF_SIZE 65
	char *result;
	char *tmp;
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
base64_read(char *content, unsigned char **out, size_t *out_len)
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

	error = base64_decode(encoded, result, true, alloc_size, &result_len);
	if (error)
		goto release_result;

	free(sanitized);
	BIO_free(encoded);

	*out = result;
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
parse_string(xmlTextReaderPtr reader, char const *attr, char **result)
{
	xmlChar *xml_value;
	char *tmp;

	if (attr == NULL) {
		xml_value = xmlTextReaderValue(reader);
		if (xml_value == NULL)
			return pr_val_err("RRDP file: Couldn't find string content from '%s'",
			    xmlTextReaderConstLocalName(reader));
	} else {
		xml_value = xmlTextReaderGetAttribute(reader, BAD_CAST attr);
		if (xml_value == NULL)
			return pr_val_err("RRDP file: Couldn't find xml attribute '%s' from tag '%s'",
			    attr, xmlTextReaderConstLocalName(reader));
	}

	tmp = pmalloc(xmlStrlen(xml_value) + 1);
	memcpy(tmp, xml_value, xmlStrlen(xml_value));
	tmp[xmlStrlen(xml_value)] = '\0';
	xmlFree(xml_value);

	*result = tmp;
	return 0;
}

static int
parse_long(xmlTextReaderPtr reader, char const *attr, unsigned long *result)
{
	xmlChar *xml_value;
	unsigned long tmp;
	int error;

	xml_value = xmlTextReaderGetAttribute(reader, BAD_CAST attr);
	if (xml_value == NULL)
		return pr_val_err("RRDP file: Couldn't find xml attribute '%s'",
		    attr);

	errno = 0;
	tmp = strtoul((char *) xml_value, NULL, 10);
	error = errno;
	if (error) {
		xmlFree(xml_value);
		pr_val_err("RRDP file: Invalid long value '%s': %s",
		    xml_value, strerror(error));
		return -EINVAL;
	}
	xmlFree(xml_value);

	(*result) = tmp;
	return 0;
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
	unsigned long version;
	int error;

	error = parse_long(reader, RRDP_ATTR_VERSION, &version);
	if (error)
		return error;

	if (version != expected)
		return pr_val_err("Invalid version, must be '%lu' and is '%lu'.",
		    expected, version);

	return 0;
}

static int
parse_metadata(xmlTextReaderPtr reader, struct notification_metadata *meta)
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

	meta->serial = 0;
	error = parse_long(reader, RRDP_ATTR_SERIAL, &meta->serial);
	if (error)
		return error;

	return parse_string(reader, RRDP_ATTR_SESSION_ID, &meta->session_id);
}

static int
validate_metadata(xmlTextReaderPtr reader, char const *expected_session,
    unsigned long expected_serial)
{
	struct notification_metadata meta;
	int error;

	notification_metadata_init(&meta);

	error = parse_metadata(reader, &meta);
	if (error)
		return error;

	if (strcmp(expected_session, meta.session_id) != 0) {
		/* FIXME why are these not error messages */
		pr_val_info("File session id [%s] doesn't match parent's session id [%s]",
		    expected_session, meta.session_id);
		goto fail;
	}

	if (meta.serial != expected_serial) {
		pr_val_info("File serial '%lu' doesn't match expected serial '%lu'",
		    meta.serial, expected_serial);
		goto fail;
	}

	notification_metadata_cleanup(&meta);
	return 0;

fail:
	notification_metadata_cleanup(&meta);
	return EINVAL;
}

/*
 * Extracts the following two attributes from @reader's current tag:
 *
 * 1. "uri"
 * 2. "hash" (optional, depending on @hr)
 */
static int
parse_doc_data(xmlTextReaderPtr reader, struct rpki_uri *notif,
    hash_requirement hr, struct file_metadata *data)
{
	char *uri_str;
	struct rpki_uri *uri;
	unsigned char *hash;
	size_t hash_len;
	int error;

	uri_str = NULL;
	uri = NULL;
	hash = NULL;
	hash_len = 0;

	error = parse_string(reader, RRDP_ATTR_URI, &uri_str);
	if (error)
		return error;
	error = uri_create(&uri, (notif != NULL) ? UT_CAGED : UT_HTTPS, notif,
	    uri_str);
	free(uri_str);
	if (error)
		return error;

	if (hr == HR_IGNORE)
		goto end;

	error = parse_hex_string(reader, hr, RRDP_ATTR_HASH, &hash, &hash_len);
	if (error) {
		free(uri);
		return error;
	}
end:
	data->uri = uri;
	data->hash = hash;
	data->hash_len = hash_len;
	return 0;
}

static int
parse_publish(xmlTextReaderPtr reader, struct rpki_uri *notif,
    hash_requirement hr, struct publish *tag)
{
	char *base64_str;
	int error;

	publish_init(tag);

	error = parse_doc_data(reader, notif, hr, &tag->meta);
	if (error)
		goto release_tmp;

	/* Read the text */
	if (xmlTextReaderRead(reader) != 1) {
		error = pr_val_err("Couldn't read publish content of element '%s'",
		    uri_get_global(tag->meta.uri));
		goto release_tmp;
	}

	error = parse_string(reader, NULL, &base64_str);
	if (error)
		goto release_tmp;

	error = base64_read(base64_str, &tag->content, &tag->content_len);
	if (error)
		goto release_base64;

	/* rfc8181#section-2.2 but considering optional hash */
	if (tag->meta.hash_len > 0) {
		/* Get the current file from the uri */
		error = hash_validate_file(tag->meta.uri, tag->meta.hash,
		    tag->meta.hash_len);
		if (error) {
			pr_val_info("Hash of base64 decoded element from URI '%s' doesn't match <publish> element hash",
			    uri_get_global(tag->meta.uri));
			error = EINVAL;
			goto release_base64;
		}
	}

	free(base64_str);
	return 0;
release_base64:
	free(base64_str);
release_tmp:
	publish_cleanup(tag);
	return error;
}

static int
parse_withdraw(xmlTextReaderPtr reader, struct rpki_uri *notif,
    struct withdraw *tag)
{
	int error;

	withdraw_init(tag);

	error = parse_doc_data(reader, notif, HR_MANDATORY, &tag->meta);
	if (error)
		goto fail;

	error = hash_validate_file(tag->meta.uri, tag->meta.hash,
	    tag->meta.hash_len);
	if (error)
		goto fail;

	return 0;

fail:
	withdraw_cleanup(tag);
	return error;
}

static int
write_from_uri(struct rpki_uri *uri, unsigned char *content, size_t content_len)
{
	FILE *out;
	size_t written;
	int error;

	error = create_dir_recursive(uri_get_local(uri), false);
	if (error)
		return error;

	error = file_write(uri_get_local(uri), &out);
	if (error)
		return error;

	written = fwrite(content, sizeof(unsigned char), content_len, out);
	if (written != content_len) {
		file_close(out);
		return pr_val_err(
		    "Couldn't write file '%s' (error code not available)",
		    uri_get_local(uri)
		);
	}

	file_close(out);
	return 0;
}

/* Remove a local file and its directory tree (if empty) */
static int
delete_from_uri(struct rpki_uri *uri)
{
	/* Delete parent dirs only if empty. */
	return delete_dir_recursive_bottom_up(uri_get_local(uri));
}

/*
 * This function will call 'xmlTextReaderRead' so there's no need to expect any
 * other type at the caller.
 */
static int
parse_publish_elem(xmlTextReaderPtr reader, struct rpki_uri *notif,
    hash_requirement hr)
{
	struct publish tag;
	int error;

	error = parse_publish(reader, notif, hr, &tag);
	if (error)
		return error;

	error = write_from_uri(tag.meta.uri, tag.content, tag.content_len);

	publish_cleanup(&tag);
	return error;
}

/*
 * This function will call 'xmlTextReaderRead' so there's no need to expect any
 * other type at the caller.
 */
static int
parse_withdraw_elem(xmlTextReaderPtr reader, struct rpki_uri *notif)
{
	struct withdraw tag;
	int error;

	error = parse_withdraw(reader, notif, &tag);
	if (error)
		return error;

	error = delete_from_uri(tag.meta.uri);

	withdraw_cleanup(&tag);
	return error;
}

static int
parse_notification_delta(xmlTextReaderPtr reader,
    struct update_notification *notif)
{
	struct delta_head delta;
	int error;

	error = parse_long(reader, RRDP_ATTR_SERIAL, &delta.serial);
	if (error)
		return error;
	error = parse_doc_data(reader, NULL, HR_MANDATORY, &delta.meta);
	if (error)
		return error;

	deltas_head_add(&notif->deltas_list, &delta);
	return 0;
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
			return parse_doc_data(reader, NULL, HR_MANDATORY,
			    &notif->snapshot);
		} else if (xmlStrEqual(name, BAD_CAST RRDP_ELEM_NOTIFICATION)) {
			/* No need to validate session ID and serial */
			return parse_metadata(reader, &notif->meta);
		}

		return pr_val_err("Unexpected '%s' element", name);

	case XML_READER_TYPE_END_ELEMENT:
		if (xmlStrEqual(name, BAD_CAST RRDP_ELEM_NOTIFICATION))
			return deltas_head_sort(&notif->deltas_list,
			    notif->meta.serial);
		break;
	}

	return 0;
}

int
rrdp_parse_notification(struct rpki_uri *uri,
    struct update_notification *result)
{
	int error;

	update_notification_init(result, uri);

	error = relax_ng_parse(uri_get_local(uri), xml_read_notif, result);
	if (error)
		update_notification_cleanup(result);

	return error;
}

static int
xml_read_snapshot(xmlTextReaderPtr reader, void *arg)
{
	struct rdr_snapshot_ctx *ctx = arg;
	xmlReaderTypes type;
	xmlChar const *name;
	int error;

	name = xmlTextReaderConstLocalName(reader);
	type = xmlTextReaderNodeType(reader);
	switch (type) {
	case XML_READER_TYPE_ELEMENT:
		if (xmlStrEqual(name, BAD_CAST RRDP_ELEM_PUBLISH))
			error = parse_publish_elem(reader, ctx->notif->uri,
			    HR_IGNORE);
		else if (xmlStrEqual(name, BAD_CAST RRDP_ELEM_SNAPSHOT))
			error = validate_metadata(reader,
			    ctx->notif->meta.session_id,
			    ctx->notif->meta.serial);
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
parse_snapshot(struct rpki_uri *uri, struct update_notification *notif)
{
	struct rdr_snapshot_ctx ctx;
	int error;

	fnstack_push_uri(uri);
	/* Hash validation */
	error = hash_validate_file(uri, notif->snapshot.hash,
	    notif->snapshot.hash_len);
	if (error)
		goto pop;

	ctx.notif = notif;

	error = relax_ng_parse(uri_get_local(uri), xml_read_snapshot, &ctx);

pop:	fnstack_pop();
	return error;
}

static int
xml_read_delta(xmlTextReaderPtr reader, void *arg)
{
	struct rdr_delta_ctx *ctx = arg;
	xmlReaderTypes type;
	xmlChar const *name;
	int error;

	name = xmlTextReaderConstLocalName(reader);
	type = xmlTextReaderNodeType(reader);
	switch (type) {
	case XML_READER_TYPE_ELEMENT:
		if (xmlStrEqual(name, BAD_CAST RRDP_ELEM_PUBLISH))
			error = parse_publish_elem(reader, ctx->notif->uri,
			    HR_OPTIONAL);
		else if (xmlStrEqual(name, BAD_CAST RRDP_ELEM_WITHDRAW))
			error = parse_withdraw_elem(reader, ctx->notif->uri);
		else if (xmlStrEqual(name, BAD_CAST RRDP_ELEM_DELTA))
			error = validate_metadata(reader,
			    ctx->notif->meta.session_id,
			    ctx->expected_serial);
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
parse_delta(struct rpki_uri *uri, struct delta_head *parents_data,
    struct update_notification *notif)
{
	struct rdr_delta_ctx ctx;
	struct file_metadata *expected_data;
	int error;

	expected_data = &parents_data->meta;

	fnstack_push_uri(uri);
	error = hash_validate_file(uri, expected_data->hash,
	    expected_data->hash_len);
	if (error)
		goto pop_fnstack;

	ctx.notif = notif;
	ctx.expected_serial = parents_data->serial;

	error = relax_ng_parse(uri_get_local(uri), xml_read_delta, &ctx);

pop_fnstack:
	fnstack_pop();
	return error;
}

static int
process_delta(struct delta_head *delta, void *arg)
{
	struct rpki_uri *uri;
	int error;

	uri = delta->meta.uri;

	pr_val_debug("Processing delta '%s'.", uri_val_get_printable(uri));
	fnstack_push_uri(uri);

	error = cache_download(uri, NULL);
	if (error)
		goto end;
	error = parse_delta(uri, delta, arg);
	delete_from_uri(uri);

end:
	fnstack_pop();
	return error;
}

int
rrdp_parse_snapshot(struct update_notification *notif)
{
	struct rpki_uri *uri;
	int error;

	uri = notif->snapshot.uri;

	pr_val_debug("Processing snapshot '%s'.", uri_val_get_printable(uri));
	fnstack_push_uri(uri);

	error = cache_download(uri, NULL);
	if (error)
		goto end;
	error = parse_snapshot(uri, notif);
	delete_from_uri(uri);

end:
	fnstack_pop();
	return error;
}

int
rrdp_process_deltas(struct update_notification *notif, unsigned long serial)
{
	return deltas_head_for_each(&notif->deltas_list, notif->meta.serial,
	    serial, process_delta, notif);
}
