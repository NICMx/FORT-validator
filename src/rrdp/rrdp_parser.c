#include "rrdp_parser.h"

#include <libxml/xmlreader.h>
#include <openssl/evp.h>
#include <sys/stat.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "rrdp/db/db_rrdp_uris.h"
#include "crypto/base64.h"
#include "crypto/hash.h"
#include "http/http.h"
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

/* Context while reading a snapshot */
struct rdr_snapshot_ctx {
	/* Data being parsed */
	struct snapshot *snapshot;
	/* Parent data to validate session ID and serial */
	struct update_notification *parent;
	/* Visited URIs related to this thread */
	struct visited_uris *visited_uris;
};

/* Context while reading a delta */
struct rdr_delta_ctx {
	/* Data being parsed */
	struct delta *delta;
	/* Parent data to validate session ID */
	struct update_notification *parent;
	/* Current serial loaded from update notification deltas list */
	unsigned long expected_serial;
	/* Visited URIs related to this thread */
	struct visited_uris *visited_uris;
};

/* Args to send on update (snapshot/delta) files parsing */
struct proc_upd_args {
	struct update_notification *parent;
	struct visited_uris *visited_uris;
	bool log_operation;
};

static int
add_mft_to_list(struct visited_uris *visited_uris, char const *uri)
{
	if (strcmp(".mft", strrchr(uri, '.')) != 0)
		return 0;

	return visited_uris_add(visited_uris, uri);
}

static int
rem_mft_from_list(struct visited_uris *visited_uris, char const *uri)
{
	if (strcmp(".mft", strrchr(uri, '.')) != 0)
		return 0;

	return visited_uris_remove(visited_uris, uri);
}

static int
download_file(struct rpki_uri *uri, long last_update, bool log_operation)
{
	int error;

	if (last_update > 0)
		error = http_download_file_with_ims(uri, last_update,
		    log_operation);
	else
		error = http_download_file(uri, log_operation);

	/*
	 * Since distinct files can be downloaded (notification, snapshot,
	 * delta) just return the error and let the caller to add only the
	 * update notification URI to the request errors DB.
	 */
	if (error == -EREQFAILED)
		return EREQFAILED;

	/* Remember: positive values are expected */
	return error;
}

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
		error = val_crypto_err("BIO_new_mem_buf() returned NULL");
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
		return pr_val_err("RRDP file: Couldn't find xml attribute '%s'",
		    attr);

	errno = 0;
	tmp = strtoul((char *) xml_value, NULL, 10);
	if (errno) {
		xmlFree(xml_value);
		pr_val_errno(errno, "RRDP file: Invalid long value '%s'",
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
		    pr_val_err("RRDP file: Couldn't find xml attribute '%s'", attr)
		    : 0;

	/* The rest of the checks are done at the schema */
	if (xmlStrlen(xml_value) % 2 != 0) {
		xmlFree(xml_value);
		return pr_val_err("RRDP file: Attribute %s isn't a valid hex string",
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
		return pr_val_err("Invalid version, must be '%lu' and is '%lu'.",
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
		return pr_val_err("Namespace isn't '%s', current value is '%s'",
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
	 * Positive error value means the file was successfully parsed but it
	 * has a logic error (in this case, session ID doesn't match parent's).
	 */
	if (strcmp(expected_session, session_id) != 0) {
		pr_val_info("File session id [%s] doesn't match parent's session id [%s]",
		    expected_session, session_id);
		error = EINVAL;
		goto return_val;
	}

	/* ...and the serial must match to what's expected at the parent */
	if (serial != expected_serial) {
		pr_val_info("File serial '%lu' doesn't match expected serial '%lu'",
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
	struct rpki_uri *uri;
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
		error = pr_val_err("Couldn't read publish content of element '%s'",
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
	uri = NULL;
	if (tmp->doc_data.hash_len > 0) {
		/* Get the current file from the uri */
		error = uri_create_rsync_str_rrdp(&uri, tmp->doc_data.uri,
		    strlen(tmp->doc_data.uri));
		if (error)
			goto release_base64;

		error = hash_validate_file("sha256", uri, tmp->doc_data.hash,
		    tmp->doc_data.hash_len);
		uri_refput(uri);
		if (error != 0) {
			pr_val_info("Hash of base64 decoded element from URI '%s' doesn't match <publish> element hash",
			    tmp->doc_data.uri);
			error = EINVAL;
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
	error = uri_create_rsync_str_rrdp(&uri, tmp->doc_data.uri,
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
write_from_uri(char const *location, unsigned char *content, size_t content_len,
    struct visited_uris *visited_uris)
{
	struct rpki_uri *uri;
	struct stat stat;
	FILE *out;
	size_t written;
	int error;

	/* rfc8181#section-2.2 must be an rsync URI */
	error = uri_create_rsync_str_rrdp(&uri, location, strlen(location));
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
		return pr_val_err("Couldn't write bytes to file %s",
		    uri_get_local(uri));
	}

	error = add_mft_to_list(visited_uris, uri_get_global(uri));
	if (error) {
		uri_refput(uri);
		file_close(out);
		return error;
	}

	uri_refput(uri);
	file_close(out);
	return 0;
}

/* Remove a local file and its directory tree (if empty) */
static int
delete_from_uri(struct rpki_uri *uri, struct visited_uris *visited_uris)
{
	int error;

	if (visited_uris) {
		error = rem_mft_from_list(visited_uris, uri_get_global(uri));
		if (error)
			return error;
	}

	/* Delete parent dirs only if empty. */
	return delete_dir_recursive_bottom_up(uri_get_local(uri));
}

static int
__delete_from_uri(char const *location, struct visited_uris *visited_uris)
{
	struct rpki_uri *uri;
	int error;

	/* rfc8181#section-2.2 must be an rsync URI */
	error = uri_create_rsync_str_rrdp(&uri, location, strlen(location));
	if (error)
		return error;

	error = delete_from_uri(uri, visited_uris);

	/* Error 0 is ok */
	uri_refput(uri);
	return error;
}

/*
 * This function will call 'xmlTextReaderRead' so there's no need to expect any
 * other type at the caller.
 */
static int
parse_publish_elem(xmlTextReaderPtr reader, bool parse_hash, bool hash_required,
    struct visited_uris *visited_uris)
{
	struct publish *tmp;
	int error;

	tmp = NULL;
	error = parse_publish(reader, parse_hash, hash_required, &tmp);
	if (error)
		return error;

	error = write_from_uri(tmp->doc_data.uri, tmp->content,
	    tmp->content_len, visited_uris);
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
parse_withdraw_elem(xmlTextReaderPtr reader, struct visited_uris *visited_uris)
{
	struct withdraw *tmp;
	int error;

	error = parse_withdraw(reader, &tmp);
	if (error)
		return error;

	error = __delete_from_uri(tmp->doc_data.uri, visited_uris);
	withdraw_destroy(tmp);
	if (error)
		return error;

	return 0;
}

static int
parse_notification_delta(xmlTextReaderPtr reader,
    struct update_notification *update)
{
	struct delta_head delta;
	int error;

	error = parse_long(reader, RRDP_ATTR_SERIAL, &delta.serial);
	if (error)
		return error;
	error = parse_doc_data(reader, true, true, &delta.doc_data);
	if (error)
		return error;

	error = deltas_head_add(&update->deltas_list, &delta);
	if (error)
		doc_data_cleanup(&delta.doc_data);

	return error;
}

static int
xml_read_notification(xmlTextReaderPtr reader, void *arg)
{
	struct update_notification *update = arg;
	xmlChar const *name;

	name = xmlTextReaderConstLocalName(reader);
	switch (xmlTextReaderNodeType(reader)) {
	case XML_READER_TYPE_ELEMENT:
		if (xmlStrEqual(name, BAD_CAST RRDP_ELEM_DELTA)) {
			return parse_notification_delta(reader, update);
		} else if (xmlStrEqual(name, BAD_CAST RRDP_ELEM_SNAPSHOT)) {
			return parse_doc_data(reader, true, true,
			    &update->snapshot);
		} else if (xmlStrEqual(name, BAD_CAST RRDP_ELEM_NOTIFICATION)) {
			/* No need to validate session ID and serial */
			return parse_global_data(reader,
			    &update->global_data, NULL, 0);
		}

		return pr_val_err("Unexpected '%s' element", name);

	case XML_READER_TYPE_END_ELEMENT:
		if (xmlStrEqual(name, BAD_CAST RRDP_ELEM_NOTIFICATION))
			return deltas_head_sort(&update->deltas_list,
			    update->global_data.serial);
		break;
	}

	return 0;
}

static int
parse_notification(struct rpki_uri *uri, struct update_notification **file)
{
	struct update_notification *result;
	int error;

	result = update_notification_create(uri_get_global(uri));
	if (result == NULL)
		return pr_enomem();

	error = relax_ng_parse(uri_get_local(uri), xml_read_notification,
	    result);
	if (error) {
		update_notification_destroy(result);
		return error;
	}

	*file = result;
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
			error = parse_publish_elem(reader, false, false,
			    ctx->visited_uris);
		else if (xmlStrEqual(name, BAD_CAST RRDP_ELEM_SNAPSHOT))
			error = parse_global_data(reader,
			    &ctx->snapshot->global_data,
			    ctx->parent->global_data.session_id,
			    ctx->parent->global_data.serial);
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
parse_snapshot(struct rpki_uri *uri, struct proc_upd_args *args)
{
	struct rdr_snapshot_ctx ctx;
	struct snapshot *snapshot;
	int error;

	fnstack_push_uri(uri);
	/* Hash validation */
	error = hash_validate_file("sha256", uri, args->parent->snapshot.hash,
	    args->parent->snapshot.hash_len);
	if (error)
		goto pop;

	error = snapshot_create(&snapshot);
	if (error)
		goto pop;

	ctx.snapshot = snapshot;
	ctx.parent = args->parent;
	ctx.visited_uris = args->visited_uris;
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
			error = parse_publish_elem(reader, true, false,
			    ctx->visited_uris);
		else if (xmlStrEqual(name, BAD_CAST RRDP_ELEM_WITHDRAW))
			error = parse_withdraw_elem(reader, ctx->visited_uris);
		else if (xmlStrEqual(name, BAD_CAST RRDP_ELEM_DELTA))
			error = parse_global_data(reader,
			    &ctx->delta->global_data,
			    ctx->parent->global_data.session_id,
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
    struct proc_upd_args *args)
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
	ctx.parent = args->parent;
	ctx.visited_uris = args->visited_uris;
	ctx.expected_serial = parents_data->serial;
	error = relax_ng_parse(uri_get_local(uri), xml_read_delta, &ctx);

	delta_destroy(delta);
	/* Error 0 is ok */

pop_fnstack:
	fnstack_pop();
	return error;
}

static int
process_delta(struct delta_head *delta_head, void *arg)
{
	struct proc_upd_args *args = arg;
	struct rpki_uri *uri;
	struct doc_data *head_data;
	int error;

	head_data = &delta_head->doc_data;

	pr_val_debug("Processing delta '%s'.", delta_head->doc_data.uri);
	error = uri_create_https_str_rrdp(&uri, head_data->uri,
	    strlen(head_data->uri));
	if (error)
		return error;

	error = download_file(uri, 0, args->log_operation);
	if (error)
		goto release_uri;

	error = parse_delta(uri, delta_head, args);

	delete_from_uri(uri, NULL);
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
 *
 * Set @force to true to omit 'If-Modified-Since' header.
 */
int
rrdp_parse_notification(struct rpki_uri *uri, bool log_operation, bool force,
    struct update_notification **result)
{
	long last_update;
	int error, vis_err;

	if (uri == NULL || uri_is_rsync(uri))
		pr_crit("Wrong call, trying to parse a non HTTPS URI");

	pr_val_debug("Processing notification '%s'.", uri_get_global(uri));
	last_update = 0;
	if (!force) {
		error = db_rrdp_uris_get_last_update(uri_get_global(uri), &last_update);
		if (error && error != -ENOENT)
			return error;
	}

	error = download_file(uri, last_update, log_operation);
	if (error < 0)
		return error;

	/* Request error, stop processing to handle as such */
	if (error == EREQFAILED)
		return error;

	/*
	 * Mark as visited, if it doesn't exists yet, there's no problem since
	 * this is probably the first time is visited (first run), so it will
	 * be marked as visited when the URI is stored at DB.
	 */
	vis_err = db_rrdp_uris_set_request_status(uri_get_global(uri),
	    RRDP_URI_REQ_VISITED);
	if (vis_err && vis_err != -ENOENT)
		return pr_val_err("Couldn't mark '%s' as visited",
		    uri_get_global(uri));

	/* No updates yet */
	if (error > 0) {
		delete_from_uri(uri, NULL);
		*result = NULL;
		return 0;
	}

	fnstack_push_uri(uri);
	error = parse_notification(uri, result);
	delete_from_uri(uri, NULL);
	if (error) {
		fnstack_pop();
		return error;
	}

	return 0;
}

int
rrdp_parse_snapshot(struct update_notification *parent,
    struct visited_uris *visited_uris, bool log_operation)
{
	struct proc_upd_args args;
	struct rpki_uri *uri;
	int error;

	args.parent = parent;
	args.visited_uris = visited_uris;

	pr_val_debug("Processing snapshot '%s'.", parent->snapshot.uri);
	error = uri_create_https_str_rrdp(&uri, parent->snapshot.uri,
	    strlen(parent->snapshot.uri));
	if (error)
		return error;

	error = download_file(uri, 0, log_operation);
	if (error)
		goto release_uri;

	error = parse_snapshot(uri, &args);

	delete_from_uri(uri, NULL);
	/* Error 0 is ok */
release_uri:
	uri_refput(uri);
	return error;
}

int
rrdp_process_deltas(struct update_notification *parent,
    unsigned long cur_serial, struct visited_uris *visited_uris,
    bool log_operation)
{
	struct proc_upd_args args;

	args.parent = parent;
	args.visited_uris = visited_uris;
	args.log_operation = log_operation;

	return deltas_head_for_each(&parent->deltas_list,
	    parent->global_data.serial, cur_serial, process_delta, &args);
}
