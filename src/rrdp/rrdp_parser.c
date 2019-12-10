#include "rrdp_parser.h"

#include <libxml/xmlreader.h>
#include <openssl/evp.h>
#include <sys/stat.h>
#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "crypto/base64.h"
#include "crypto/hash.h"
#include "http/http.h"
#include "rrdp/rrdp_handler.h"
#include "xml/relax_ng.h"
#include "common.h"
#include "file.h"
#include "log.h"
#include "thread_var.h"

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

/* Array list to get deltas from notification file */
DEFINE_ARRAY_LIST_STRUCT(deltas_parsed, struct delta_head *);
DEFINE_ARRAY_LIST_FUNCTIONS(deltas_parsed, struct delta_head *, static)

/* Context while reading an update notification */
struct rdr_notification_ctx {
	/* Data being parsed */
	struct update_notification *notification;
	/* Global URI of the notification */
	char const *uri;
	/* The snapshot must be allocated? */
	bool create_snapshot;
	/* Unordered list of deltas */
	struct deltas_parsed deltas;
};

/* Context while reading a snapshot */
struct rdr_snapshot_ctx {
	/* Data being parsed */
	struct snapshot *snapshot;
	/* Parent data to validate session ID and serial */
	struct update_notification *parent;
};

/* Context while reading a delta */
struct rdr_delta_ctx {
	/* Data being parsed */
	struct delta *delta;
	/* Parent data to validate session ID */
	struct update_notification *parent;
	/* Current serial loaded from update notification deltas list */
	unsigned long expected_serial;
};

static size_t
write_local(unsigned char *content, size_t size, size_t nmemb, void *arg)
{
	FILE *fd = arg;
	size_t read = size * nmemb;
	size_t written;

	written = fwrite(content, size, nmemb, fd);
	if (written != nmemb)
		return -EINVAL;

	return read;
}

/* Trim @from, setting the result at @result pointer */
static int
trim(char *from, char **result, size_t *result_size)
{
	char *start, *end;
	size_t tmp_size;

	start = from;
	tmp_size = strlen(from);
	while (isspace(*start)) {
		start++;
		tmp_size--;
	}
	if (*start == '\0')
		return pr_err("Invalid base64 encoded string (seems to be empty or full of spaces).");

	end = start;
	while (*end != '\0') {
		if (!isspace(*end)) {
			end++;
			continue;
		}
		/* No middle spaces, newlines, etc. allowed */
		*end = '\0';
		tmp_size = end - start;
		break;
	}

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
	error = trim(content, &tmp, &original_size);
	if (error)
		return error;

	if (original_size <= BUF_SIZE) {
		result = malloc(original_size + 1);
		if (result == NULL)
			return pr_enomem();
		result[original_size] = '\0';
		*out = result;
		return 0;
	}

	new_size = original_size + (original_size / BUF_SIZE);
	result = malloc(new_size + 1);
	if (result == NULL)
		return pr_enomem();

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
	if (offset != new_size + 1) {
		tmp = realloc(result, offset + 1);
		if (tmp == NULL) {
			free(result);
			return pr_enomem();
		}
		result = tmp;
	}

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
		error = crypto_err("BIO_new_mem_buf() returned NULL");
		goto release_sanitized;
	}

	alloc_size = EVP_DECODE_LENGTH(strlen(content));
	result = malloc(alloc_size);
	if (result == NULL) {
		error = pr_enomem();
		goto release_bio;
	}

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
release_bio:
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

	if (attr == NULL)
		xml_value = xmlTextReaderValue(reader);
	else
		xml_value = xmlTextReaderGetAttribute(reader, BAD_CAST attr);

	if (xml_value == NULL)
		return pr_err("RRDP file: Couldn't find %s from '%s'",
		    (attr == NULL ? "string content" : "xml attribute"),
		    xmlTextReaderConstLocalName(reader));

	tmp = malloc(xmlStrlen(xml_value) + 1);
	if (tmp == NULL) {
		xmlFree(xml_value);
		return pr_enomem();
	}

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

	xml_value = xmlTextReaderGetAttribute(reader, BAD_CAST attr);
	if (xml_value == NULL)
		return pr_err("RRDP file: Couldn't find xml attribute '%s'",
		    attr);

	errno = 0;
	tmp = strtoul((char *) xml_value, NULL, 10);
	if (errno) {
		xmlFree(xml_value);
		pr_errno(errno, "RRDP file: Invalid long value '%s'",
		   xml_value);
		return -EINVAL;
	}
	xmlFree(xml_value);

	(*result) = tmp;
	return 0;
}

static int
parse_hex_string(xmlTextReaderPtr reader, bool required, char const *attr,
    unsigned char **result, size_t *result_len)
{
	xmlChar *xml_value;
	unsigned char *tmp, *ptr;
	char *xml_cur;
	char buf[2];
	size_t tmp_len;

	xml_value = xmlTextReaderGetAttribute(reader, BAD_CAST attr);
	if (xml_value == NULL)
		return required ?
		    pr_err("RRDP file: Couldn't find xml attribute '%s'", attr)
		    : 0;

	/* The rest of the checks are done at the schema */
	if (xmlStrlen(xml_value) % 2 != 0) {
		xmlFree(xml_value);
		return pr_err("RRDP file: Attribute %s isn't a valid hex string",
		    attr);
	}

	tmp_len = xmlStrlen(xml_value) / 2;
	tmp = malloc(tmp_len);
	if (tmp == NULL) {
		xmlFree(xml_value);
		return pr_enomem();
	}
	memset(tmp, 0, tmp_len);

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
		return pr_err("Invalid version, must be '%lu' and is '%lu'.",
		    expected, version);

	return 0;
}

/* @gdata elements are allocated */
static int
parse_global_data(xmlTextReaderPtr reader, struct global_data *gdata,
    char const *expected_session, unsigned long expected_serial)
{
	char *session_id;
	unsigned long serial;
	int error;

	/*
	 * The following rule appies to all files:
	 * - The XML namespace MUST be "http://www.ripe.net/rpki/rrdp".
	 * - The version attribute MUST be "1".
	 */
	if (!xmlStrEqual(xmlTextReaderConstNamespaceUri(reader),
	    BAD_CAST RRDP_NAMESPACE))
		return pr_err("Namespace isn't '%s', current value is '%s'",
		    RRDP_NAMESPACE, xmlTextReaderConstNamespaceUri(reader));

	error = validate_version(reader, 1);
	if (error)
		return error;

	error = parse_string(reader, RRDP_ATTR_SESSION_ID, &session_id);
	if (error)
		return error;

	serial = 0;
	error = parse_long(reader, RRDP_ATTR_SERIAL, &serial);
	if (error) {
		free(session_id);
		return error;
	}

	if (expected_session == NULL)
		goto return_val; /* Error O is OK */

	/*
	 * FIXME (now) Prepare the callers to receive positive error values,
	 * which means the file was successfully parsed but is has a logic error
	 * (in this case, session ID doesn't match parent's).
	 */
	if (strcmp(expected_session, session_id) != 0) {
		pr_info("File session id [%s] doesn't match parent's session id [%s]",
		    expected_session, session_id);
		error = EINVAL;
		goto return_val;
	}

	/* ...and the serial must match to what's expected at the parent */
	if (serial != expected_serial) {
		pr_info("File serial '%lu' doesn't match expected serial '%lu'",
		    serial, expected_serial);
		error = EINVAL;
	}

return_val:
	gdata->session_id = session_id;
	gdata->serial = serial;
	return error;
}

/* @data elements are allocated */
static int
parse_doc_data(xmlTextReaderPtr reader, bool parse_hash, bool hash_req,
    struct doc_data *data)
{
	char *uri;
	unsigned char *hash;
	size_t hash_len;
	int error;

	uri = NULL;
	hash = NULL;
	hash_len = 0;

	error = parse_string(reader, RRDP_ATTR_URI, &uri);
	if (error)
		return error;

	if (!parse_hash)
		goto end;

	error = parse_hex_string(reader, hash_req, RRDP_ATTR_HASH, &hash,
	    &hash_len);
	if (error) {
		free(uri);
		return error;
	}
end:
	/* Function called just to do the validation */
	if (data == NULL) {
		doc_data_init(data);
		free(hash);
		free(uri);
		return 0;
	}
	data->uri = uri;
	data->hash = hash;
	data->hash_len = hash_len;
	return 0;
}

static int
parse_publish(xmlTextReaderPtr reader, bool parse_hash, bool hash_required,
    struct publish **publish)
{
	struct publish *tmp;
	char *base64_str;
	int error;

	error = publish_create(&tmp);
	if (error)
		return error;

	error = parse_doc_data(reader, parse_hash, hash_required,
	    &tmp->doc_data);
	if (error)
		goto release_tmp;

	/* Read the text */
	if (xmlTextReaderRead(reader) != 1) {
		error = pr_err("Couldn't read publish content of element '%s'",
		    tmp->doc_data.uri);
		goto release_tmp;
	}

	error = parse_string(reader, NULL, &base64_str);
	if (error)
		goto release_tmp;

	error = base64_read(base64_str, &tmp->content, &tmp->content_len);
	if (error)
		goto release_base64;

	/* rfc8181#section-2.2 but considering optional hash */
	if (tmp->doc_data.hash_len > 0) {
		if (!hash_validate("sha256",
		    tmp->doc_data.hash, tmp->doc_data.hash_len,
		    tmp->content, tmp->content_len)) {
			error = pr_err("Hash of base64 decoded element from URI '%s' doesn't match <publish> element hash",
			    tmp->doc_data.uri);
			goto release_base64;
		}
	}

	free(base64_str);
	*publish = tmp;
	return 0;
release_base64:
	free(base64_str);
release_tmp:
	publish_destroy(tmp);
	return error;
}

static int
parse_withdraw(xmlTextReaderPtr reader, struct withdraw **withdraw)
{
	struct withdraw *tmp;
	struct rpki_uri *uri;
	int error;

	error = withdraw_create(&tmp);
	if (error)
		return error;

	error = parse_doc_data(reader, true, true, &tmp->doc_data);
	if (error)
		goto release_tmp;

	/* rfc8181#section-2.2, get the file from the uri */
	error = uri_create_mixed_str(&uri, tmp->doc_data.uri,
	    strlen(tmp->doc_data.uri));
	if (error)
		goto release_tmp;

	error = hash_validate_file("sha256", uri,
	    tmp->doc_data.hash, tmp->doc_data.hash_len);
	if (error)
		goto release_uri;

	uri_refput(uri);
	*withdraw = tmp;
	return 0;
release_uri:
	uri_refput(uri);
release_tmp:
	withdraw_destroy(tmp);
	return error;
}

static int
write_from_uri(char const *location, unsigned char *content, size_t content_len)
{
	struct rpki_uri *uri;
	struct stat stat;
	FILE *out;
	size_t written;
	int error;

	error = uri_create_mixed_str(&uri, location, strlen(location));
	if (error)
		return error;

	error = create_dir_recursive(uri_get_local(uri));
	if (error) {
		uri_refput(uri);
		return error;
	}

	error = file_write(uri_get_local(uri), &out, &stat);
	if (error) {
		uri_refput(uri);
		return error;
	}

	written = fwrite(content, sizeof(unsigned char), content_len, out);
	if (written != content_len) {
		uri_refput(uri);
		file_close(out);
		return pr_err("Coudln't write bytes to file %s",
		    uri_get_local(uri));
	}

	uri_refput(uri);
	file_close(out);
	return 0;
}

static int
delete_from_uri(char const *location)
{
	struct rpki_uri *uri;
	char *local_uri, *work_loc, *tmp;
	int error;

	error = uri_create_mixed_str(&uri, location, strlen(location));
	if (error)
		return error;

	local_uri = strdup(uri_get_local(uri));
	if (local_uri == NULL) {
		error = pr_enomem();
		goto release_uri;
	}

	errno = 0;
	error = remove(local_uri);
	if (error) {
		error = pr_errno(errno, "Couldn't delete %s", local_uri);
		goto release_str;
	}

	/*
	 * Delete parent dirs only if empty.
	 *
	 * The algorithm is a bit aggressive, but rmdir() won't delete
	 * something unless is empty, so in case the dir still has something in
	 * it the cycle is finished.
	 */
	work_loc = local_uri;
	do {
		tmp = strrchr(work_loc, '/');
		if (tmp == NULL)
			break;
		*tmp = '\0';

		/* FIXME (now) use a lock, what if the root dir is reached? */

		errno = 0;
		error = rmdir(work_loc);
		if (!error)
			continue; /* Keep deleting up */

		/* Stop if there's content in the dir */
		if (errno == ENOTEMPTY || errno == EEXIST)
			break;

		error = pr_errno(errno, "Couldn't delete dir %s", work_loc);
		goto release_str;
	} while (true);

	uri_refput(uri);
	free(local_uri);
	return 0;
release_str:
	free(local_uri);
release_uri:
	uri_refput(uri);
	return error;
}

/*
 * This function will call 'xmlTextReaderRead' so there's no need to expect any
 * other type at the caller.
 */
static int
parse_publish_elem(xmlTextReaderPtr reader, bool parse_hash, bool hash_required)
{
	struct publish *tmp;
	int error;

	tmp = NULL;
	error = parse_publish(reader, parse_hash, hash_required, &tmp);
	if (error)
		return error;

	error = write_from_uri(tmp->doc_data.uri, tmp->content,
	    tmp->content_len);
	publish_destroy(tmp);
	if (error)
		return error;

	return 0;
}

/*
 * This function will call 'xmlTextReaderRead' so there's no need to expect any
 * other type at the caller.
 */
static int
parse_withdraw_elem(xmlTextReaderPtr reader)
{
	struct withdraw *tmp;
	int error;

	error = parse_withdraw(reader, &tmp);
	if (error)
		return error;

	error = delete_from_uri(tmp->doc_data.uri);
	withdraw_destroy(tmp);
	if (error)
		return error;

	return 0;
}

static int
rdr_notification_ctx_init(struct rdr_notification_ctx *ctx)
{
	rrdp_uri_cmp_result_t res;

	ctx->create_snapshot = false;

	res = rhandler_uri_cmp(ctx->uri,
	    ctx->notification->global_data.session_id,
	    ctx->notification->global_data.serial);
	switch (res) {
	case RRDP_URI_EQUAL:
		/* Just validate content */
		break;
	case RRDP_URI_DIFF_SERIAL:
		/* Get the deltas to process and the snapshot */
	case RRDP_URI_DIFF_SESSION:
		/* Get only the snapshot */
	case RRDP_URI_NOTFOUND:
		ctx->create_snapshot = true;
		break;
	default:
		pr_crit("Unexpected RRDP URI comparison result");
	}

	deltas_parsed_init(&ctx->deltas);
	return 0;
}

static void
__delta_head_destroy(struct delta_head **delta_head)
{
	delta_head_destroy(*delta_head);
}

static void
rdr_notification_ctx_cleanup(struct rdr_notification_ctx *ctx)
{
	if (ctx->deltas.array != NULL)
		deltas_parsed_cleanup(&ctx->deltas, __delta_head_destroy);
}

static int
parse_notification_delta(xmlTextReaderPtr reader,
    struct rdr_notification_ctx *ctx)
{
	struct delta_head *tmp;
	unsigned long serial;
	int error;

	error = delta_head_create(&tmp);
	if (error)
		return error;

	error = parse_long(reader, RRDP_ATTR_SERIAL, &serial);
	if (error)
		goto delta_destroy;
	tmp->serial = serial;

	error = parse_doc_data(reader, true, true, &tmp->doc_data);
	if (error)
		goto delta_destroy;

	error = deltas_parsed_add(&ctx->deltas, &tmp);
	if (error)
		goto delta_destroy;

	return 0;
delta_destroy:
	delta_head_destroy(tmp);
	return error;
}

static int
order_notification_deltas(struct rdr_notification_ctx *ctx)
{
	struct delta_head **ptr;
	array_index i;
	int error;

	error = deltas_head_set_size(ctx->notification->deltas_list,
	    ctx->deltas.len);
	if (error)
		return error;

	ARRAYLIST_FOREACH(&ctx->deltas, ptr, i) {
		error = deltas_head_add(ctx->notification->deltas_list,
		    ctx->notification->global_data.serial,
		    (*ptr)->serial,
		    (*ptr)->doc_data.uri,
		    (*ptr)->doc_data.hash,
		    (*ptr)->doc_data.hash_len);

		if (!error)
			continue;

		if (error == -EINVAL)
			return pr_err("Serial '%lu' at delta elements isn't part of a contiguous list of serials.",
			    (*ptr)->serial);

		if (error == -EEXIST)
			return pr_err("Duplicated serial '%lu' at delta elements.",
			    (*ptr)->serial);

		return error;
	}

	/*
	 * "If delta elements are included, they MUST form a contiguous
	 * sequence of serial numbers starting at a revision determined by
	 * the Repository Server, up to the serial number mentioned in the
	 * notification element."
	 *
	 * If all expected elements are set, everything is ok.
	 */
	if (!deltas_head_values_set(ctx->notification->deltas_list))
		return pr_err("Deltas listed don't have a contiguous sequence of serial numbers");

	return 0;
}

static int
xml_read_notification(xmlTextReaderPtr reader, void *arg)
{
	struct rdr_notification_ctx *ctx = arg;
	xmlReaderTypes type;
	xmlChar const *name;
	int error;

	error = 0;
	name = xmlTextReaderConstLocalName(reader);
	type = xmlTextReaderNodeType(reader);
	switch (type) {
	case XML_READER_TYPE_ELEMENT:
		if (xmlStrEqual(name, BAD_CAST RRDP_ELEM_DELTA)) {
			error = parse_notification_delta(reader, ctx);
		} else if (xmlStrEqual(name, BAD_CAST RRDP_ELEM_SNAPSHOT)) {
			error = parse_doc_data(reader, true, true,
			    (ctx->create_snapshot ?
			    &ctx->notification->snapshot : NULL));
		} else if (xmlStrEqual(name, BAD_CAST RRDP_ELEM_NOTIFICATION)) {
			/* No need to validate session ID and serial */
			error = parse_global_data(reader,
			    &ctx->notification->global_data, NULL, 0);
			/* Init context for deltas and snapshot */
			rdr_notification_ctx_init(ctx);
		} else {
			return pr_err("Unexpected '%s' element", name);
		}
		break;
	case XML_READER_TYPE_END_ELEMENT:
		if (xmlStrEqual(name, BAD_CAST RRDP_ELEM_NOTIFICATION)) {
			error = order_notification_deltas(ctx);
			rdr_notification_ctx_cleanup(ctx);
			return error; /* Error 0 is ok */
		}
		break;
	default:
		return 0;
	}

	if (error) {
		rdr_notification_ctx_cleanup(ctx);
		return error;
	}

	return 0;
}

static int
parse_notification(struct rpki_uri *uri, struct update_notification **file)
{
	struct rdr_notification_ctx ctx;
	struct update_notification *tmp;
	int error;

	error = update_notification_create(&tmp);
	if (error)
		return error;

	ctx.notification = tmp;
	ctx.uri = uri_get_global(uri);
	error = relax_ng_parse(uri_get_local(uri), xml_read_notification,
	    &ctx);
	if (error) {
		update_notification_destroy(tmp);
		return error;
	}

	*file = tmp;
	return 0;
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
			error = parse_publish_elem(reader, false, false);
		else if (xmlStrEqual(name, BAD_CAST RRDP_ELEM_SNAPSHOT))
			error = parse_global_data(reader,
			    &ctx->snapshot->global_data,
			    ctx->parent->global_data.session_id,
			    ctx->parent->global_data.serial);
		else
			return pr_err("Unexpected '%s' element", name);

		if (error)
			return error;
		break;
	default:
		break;
	}

	return 0;
}

static int
parse_snapshot(struct rpki_uri *uri, struct update_notification *parent)
{
	struct rdr_snapshot_ctx ctx;
	struct snapshot *snapshot;
	int error;

	fnstack_push_uri(uri);
	/* Hash validation */
	error = hash_validate_file("sha256", uri, parent->snapshot.hash,
	    parent->snapshot.hash_len);
	if (error)
		goto pop;

	error = snapshot_create(&snapshot);
	if (error)
		goto pop;

	ctx.snapshot = snapshot;
	ctx.parent = parent;
	error = relax_ng_parse(uri_get_local(uri), xml_read_snapshot, &ctx);

	/* Error 0 is ok */
	snapshot_destroy(snapshot);
pop:
	fnstack_pop();
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
			error = parse_publish_elem(reader, true, false);
		else if (xmlStrEqual(name, BAD_CAST RRDP_ELEM_WITHDRAW))
			error = parse_withdraw_elem(reader);
		else if (xmlStrEqual(name, BAD_CAST RRDP_ELEM_DELTA))
			error = parse_global_data(reader,
			    &ctx->delta->global_data,
			    ctx->parent->global_data.session_id,
			    ctx->expected_serial);
		else
			return pr_err("Unexpected '%s' element", name);

		if (error)
			return error;
		break;
	default:
		break;
	}

	return 0;
}

static int
parse_delta(struct rpki_uri *uri, struct update_notification *parent,
    struct delta_head *parents_data)
{
	struct rdr_delta_ctx ctx;
	struct delta *delta;
	struct doc_data *expected_data;
	int error;

	expected_data = &parents_data->doc_data;

	fnstack_push_uri(uri);
	error = hash_validate_file("sha256", uri, expected_data->hash,
	    expected_data->hash_len);
	if (error)
		goto pop_fnstack;

	error = delta_create(&delta);
	if (error)
		goto pop_fnstack;

	ctx.delta = delta;
	ctx.parent = parent;
	ctx.expected_serial = parents_data->serial;
	error = relax_ng_parse(uri_get_local(uri), xml_read_delta, &ctx);

	/* Error 0 is ok */
	delta_destroy(delta);
pop_fnstack:
	fnstack_pop();
	return error;
}

static int
process_delta(struct delta_head *delta_head, void *arg)
{
	struct update_notification *parent = arg;
	struct rpki_uri *uri;
	struct doc_data *head_data;
	int error;

	head_data = &delta_head->doc_data;

	error = uri_create_https_str(&uri, head_data->uri,
	    strlen(head_data->uri));
	if (error)
		return error;

	error = http_download_file(uri, write_local);
	if (error)
		goto release_uri;

	error = parse_delta(uri, parent, delta_head);

	/* Error 0 its ok */
release_uri:
	uri_refput(uri);
	return error;
}

/*
 * Download from @uri and set result file contents to @result, the file name
 * is pushed into fnstack, so don't forget to do the pop when done working
 * with the file.
 *
 * If the server didn't sent the file, due to the validation of
 * 'If-Modified-Since' header, return 0 and set @result to NULL.
 */
int
rrdp_parse_notification(struct rpki_uri *uri, long last_update,
    struct update_notification **result)
{
	int error;

	if (uri == NULL || uri_is_rsync(uri))
		pr_crit("Wrong call, trying to parse a non HTTPS URI");

	error = http_download_file_with_ims(uri, write_local, last_update);
	if (error < 0)
		return error;

	/* No updates yet */
	if (error > 0) {
		*result = NULL;
		return 0;
	}

	fnstack_push_uri(uri);
	error = parse_notification(uri, result);
	if (error) {
		fnstack_pop();
		return error;
	}

	return 0;
}

int
rrdp_parse_snapshot(struct update_notification *parent)
{
	struct rpki_uri *uri;
	int error;

	error = uri_create_https_str(&uri, parent->snapshot.uri,
	    strlen(parent->snapshot.uri));
	if (error)
		return error;

	error = http_download_file(uri, write_local);
	if (error)
		goto release_uri;

	error = parse_snapshot(uri, parent);

	/* Error 0 is ok */
release_uri:
	uri_refput(uri);
	return error;
}

int
rrdp_process_deltas(struct update_notification *parent,
    unsigned long cur_serial)
{
	return deltas_head_for_each(parent->deltas_list,
	    parent->global_data.serial, cur_serial, process_delta, parent);
}