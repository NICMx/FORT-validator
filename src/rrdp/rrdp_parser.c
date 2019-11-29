#include "rrdp_parser.h"

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <openssl/evp.h>
#include <sys/stat.h>
#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "crypto/base64.h"
#include "http/http.h"
#include "xml/relax_ng.h"
#include "common.h"
#include "file.h"
#include "log.h"
#include "thread_var.h"

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

struct deltas_proc_args {
	struct delta_head **deltas;
	unsigned long serial;
	size_t deltas_set;
};

static int
get_root_element(xmlDoc *doc, xmlNode **result)
{
	xmlNode *tmp;

	tmp = xmlDocGetRootElement(doc);
	if (tmp == NULL)
		return pr_err("XML file doesn't have a root element");

	*result = tmp;
	return 0;
}

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
parse_string(xmlNode *root, char const *attr, char **result)
{
	xmlChar *xml_value;
	char *tmp;

	if (attr == NULL)
		xml_value = xmlNodeGetContent(root);
	else
		xml_value = xmlGetProp(root, BAD_CAST attr);

	if (xml_value == NULL)
		return pr_err("RRDP file: Couldn't find %s from '%s'",
		    (attr == NULL ? "string content" : "xml attribute"),
		    root->name);

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
parse_long(xmlNode *root, char const *attr, unsigned long *result)
{
	xmlChar *xml_value;
	unsigned long tmp;

	xml_value = xmlGetProp(root, BAD_CAST attr);
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
parse_hex_string(xmlNode *root, bool required, char const *attr,
    unsigned char **result, size_t *result_len)
{
	xmlChar *xml_value;
	unsigned char *tmp, *ptr;
	char *xml_cur;
	char buf[2];
	size_t tmp_len;

	xml_value = xmlGetProp(root, BAD_CAST attr);
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

/* @gdata elements are allocated */
static int
parse_global_data(xmlNode *root, struct global_data *gdata,
    struct global_data *parent_data, bool validate_serial)
{
	char *session_id;
	unsigned long serial;
	int error;

	error = parse_string(root, RRDP_ATTR_SESSION_ID, &session_id);
	if (error)
		return error;

	error = parse_long(root, RRDP_ATTR_SERIAL, &serial);
	if (error) {
		free(session_id);
		return error;
	}

	if (parent_data == NULL)
		goto return_val; /* Error O is OK */

	/*
	 * FIXME (now) Prepare the callers to receive positive error values,
	 * which means the file was successfully parsed but is has a logic error
	 * (in this case, session ID or serial don't match parent's).
	 */
	if (strcmp(parent_data->session_id, session_id) != 0) {
		pr_info("Object session id doesn't match parent's session id");
		error = EINVAL;
		goto return_val;
	}

	if (!validate_serial)
		goto return_val;

	if (parent_data->serial != serial) {
		pr_info("Object serial doesn't match parent's serial");
		error = EINVAL;
	}

return_val:
	gdata->session_id = session_id;
	gdata->serial = serial;
	return error;
}

/* @data elements are allocated */
static int
parse_doc_data(xmlNode *root, bool parse_hash, bool hash_req,
    struct doc_data *data)
{
	char *uri;
	unsigned char *hash;
	size_t hash_len;
	int error;

	uri = NULL;
	hash = NULL;
	hash_len = 0;

	error = parse_string(root, RRDP_ATTR_URI, &uri);
	if (error)
		return error;

	if (!parse_hash) {
		data->uri = uri;
		return 0;
	}

	error = parse_hex_string(root, hash_req, RRDP_ATTR_HASH, &hash,
	    &hash_len);
	if (error) {
		free(uri);
		return error;
	}

	data->uri = uri;
	data->hash = hash;
	data->hash_len = hash_len;
	return 0;
}

static int
parse_notification_deltas(xmlNode *root, struct deltas_head *deltas)
{
	struct doc_data doc_data;
	unsigned long serial;
	int error;

	error = parse_long(root, RRDP_ATTR_SERIAL, &serial);
	if (error)
		return error;

	doc_data_init(&doc_data);
	error = parse_doc_data(root, true, true, &doc_data);
	if (error) {
		doc_data_cleanup(&doc_data);
		return error;
	}

	error = deltas_head_add(deltas, serial, doc_data.uri, doc_data.hash,
	    doc_data.hash_len);

	/* Always release data */
	doc_data_cleanup(&doc_data);
	if (error)
		return error;

	return 0;
}

/* Get the notification data. In case of error, the caller must cleanup @file */
static int
parse_notification_data(xmlNode *root, struct update_notification *file)
{
	xmlNode *cur_node;
	int error;

	for (cur_node = root->children; cur_node; cur_node = cur_node->next) {
		if (xmlStrEqual(cur_node->name, BAD_CAST RRDP_ELEM_DELTA))
			error = parse_notification_deltas(cur_node,
			    file->deltas_list);
		else if (xmlStrEqual(cur_node->name,
		    BAD_CAST RRDP_ELEM_SNAPSHOT))
			error = parse_doc_data(cur_node, true, true,
			    &file->snapshot);

		if (error)
			return error;
	}

	return 0;
}

static int
parse_publish(xmlNode *root, bool parse_hash, bool hash_required,
    struct publish **publish)
{
	struct publish *tmp;
	char *base64_str;
	int error;

	error = publish_create(&tmp);
	if (error)
		return error;

	error = parse_doc_data(root, parse_hash, hash_required, &tmp->doc_data);
	if (error)
		goto release_tmp;

	error = parse_string(root, NULL, &base64_str);
	if (error)
		goto release_tmp;

	error = base64_read(base64_str, &tmp->content, &tmp->content_len);
	if (error)
		goto release_base64;

	/* FIXME (now) validate hash of base64str vs doc_data->hash */

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
parse_withdraw(xmlNode *root, struct withdraw **withdraw)
{
	struct withdraw *tmp;
	int error;

	error = withdraw_create(&tmp);
	if (error)
		return error;

	error = parse_doc_data(root, true, true, &tmp->doc_data);
	if (error)
		goto release_tmp;

	*withdraw = tmp;
	return 0;
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

	/* FIXME (now) validate hash, must come from withdraw element */
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

static int
parse_publish_list(xmlNode *root)
{
	struct publish *tmp;
	xmlNode *cur_node;
	int error;

	/* Only publish elements are expected, already validated by syntax */
	for (cur_node = root->children; cur_node; cur_node = cur_node->next) {
		if (xmlStrEqual(cur_node->name, BAD_CAST RRDP_ELEM_PUBLISH)) {
			tmp = NULL;
			error = parse_publish(cur_node, false, false, &tmp);
			if (error)
				return error;

			error = write_from_uri(tmp->doc_data.uri, tmp->content,
			    tmp->content_len);
			publish_destroy(tmp);
			if (error)
				return error;
 		}
	}

	return 0;
}

static int
parse_delta_element_list(xmlNode *root)
{
	struct publish *pub;
	struct withdraw *wit;
	xmlNode *cur_node;
	int error;

	/* Elements already validated by syntax */
	for (cur_node = root->children; cur_node; cur_node = cur_node->next) {
		if (xmlStrEqual(cur_node->name, BAD_CAST RRDP_ELEM_PUBLISH)) {
			pub = NULL;
			error = parse_publish(cur_node, true, false, &pub);
			if (error)
				return error;

			error = write_from_uri(pub->doc_data.uri, pub->content,
			    pub->content_len);
			publish_destroy(pub);
			if (error)
				return error;
 		} else if (xmlStrEqual(cur_node->name,
 		    BAD_CAST RRDP_ELEM_WITHDRAW)) {
 			wit = NULL;
			error = parse_withdraw(cur_node, &wit);
			if (error)
				return error;

			error = delete_from_uri(wit->doc_data.uri);
			withdraw_destroy(wit);
			if (error)
				return error;
		}
	}

	return 0;
}

static int
parse_notification(const char *path, struct update_notification **file)
{
	xmlDoc *doc;
	xmlNode *root;
	struct update_notification *tmp;
	int error;

	root = NULL;

	error = relax_ng_validate(path, &doc);
	if (error)
		return error;

	error = update_notification_create(&tmp);
	if (error)
		goto release_doc;

	error = get_root_element(doc, &root);
	if (error)
		goto release_update;

	/* FIXME (now) validate version, namespace, etc. */
	error = parse_global_data(root, &tmp->global_data, NULL, false);
	if (error)
		goto release_update;

	error = parse_notification_data(root, tmp);
	if (error)
		goto release_update;

	*file = tmp;
	/* Error 0 is ok */
	goto release_doc;

release_update:
	update_notification_destroy(tmp);
release_doc:
	xmlFreeDoc(doc);
	return error;
}

static int
parse_snapshot(const char *path, struct update_notification *parent)
{
	xmlDoc *doc;
	xmlNode *root;
	struct snapshot *snapshot;
	struct xml_source *source;
	int error;

	root = NULL;

	error = relax_ng_validate(path, &doc);
	if (error)
		return error;

	error = snapshot_create(&snapshot);
	if (error)
		goto release_doc;

	error = get_root_element(doc, &root);
	if (error)
		goto release_snapshot;

	/* FIXME (now) validate hash, version, namespace, etc. */
	error = xml_source_create(&source);
	if (error)
		goto release_snapshot;

	snapshot->source = source;
	error = xml_source_set(source, doc);
	if (error)
		goto release_snapshot;

	error = parse_global_data(root, &snapshot->global_data,
	    &parent->global_data, true);
	if (error)
		goto release_snapshot;

	error = parse_publish_list(root);

	/* Error 0 is ok */
release_snapshot:
	snapshot_destroy(snapshot);
release_doc:
	xmlFreeDoc(doc);
	return error;
}

static int
parse_delta(const char *path, struct update_notification *parent)
{
	xmlDoc *doc;
	xmlNode *root;
	struct delta *delta;
	struct xml_source *source;
	int error;

	root = NULL;

	error = relax_ng_validate(path, &doc);
	if (error)
		return error;

	error = delta_create(&delta);
	if (error)
		goto release_doc;

	error = get_root_element(doc, &root);
	if (error)
		goto release_delta;

	/* FIXME (now) validate hash, version, namespace, etc. */
	error = xml_source_create(&source);
	if (error)
		goto release_delta;

	delta->source = source;
	error = xml_source_set(source, doc);
	if (error)
		goto release_delta;

	error = parse_global_data(root, &delta->global_data,
	    &parent->global_data, false);
	if (error)
		goto release_delta;

	error = parse_delta_element_list(root);
	/* Error 0 is ok */
release_delta:
	delta_destroy(delta);
release_doc:
	xmlFreeDoc(doc);
	return error;
}

static int
get_pending_delta(struct delta_head **delta_head, unsigned long pos,
    struct deltas_proc_args *args)
{
	/* Ref to the delta element */
	args->deltas[pos] = *delta_head;
	args->deltas_set++;
	delta_head_refget(*delta_head);

	return 0;
}

static int
__get_pending_delta(struct delta_head *delta_head, void *arg)
{
	struct deltas_proc_args *args = arg;
	unsigned long serial;

	serial = delta_head_get_serial(delta_head);
	if (serial <= args->serial)
		return 0;

	return get_pending_delta(&delta_head, serial - args->serial - 1, args);
}

static int process_delta(struct delta_head *delta_head,
    struct update_notification *parent)
{
	struct rpki_uri *uri;
	struct doc_data *head_data;
	int error;

	head_data = delta_head_get_doc_data(delta_head);

	error = uri_create_https_str(&uri, head_data->uri,
	    strlen(head_data->uri));
	if (error)
		return error;

	error = http_download_file(uri, write_local);
	if (error)
		goto release_uri;

	fnstack_push_uri(uri);
	error = parse_delta(uri_get_local(uri), parent);
	if (error) {
		fnstack_pop();
		goto release_uri;
	}

	fnstack_pop();
	uri_refput(uri);

	return 0;
release_uri:
	uri_refput(uri);
	return error;
}

/*
 * Download from @uri and set result file contents to @result, the file name
 * is pushed into fnstack, so don't forget to do the pop when done working
 * with the file.
 */
int
rrdp_parse_notification(struct rpki_uri *uri,
    struct update_notification **result)
{
	int error;

	if (uri == NULL || uri_is_rsync(uri))
		pr_crit("Wrong call, trying to parse a non HTTPS URI");

	/*
	 * FIXME (now) Add "If-Modified-Since" header (see rfc8182#section-4.2)
	 */
	error = http_download_file(uri, write_local);
	if (error)
		return error;

	fnstack_push_uri(uri);
	error = parse_notification(uri_get_local(uri), result);
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

	fnstack_push_uri(uri);
	error = parse_snapshot(uri_get_local(uri), parent);
	if (error) {
		fnstack_pop();
		goto release_uri;
	}

	fnstack_pop();
	uri_refput(uri);

	return 0;
release_uri:
	uri_refput(uri);
	return error;
}

int
rrdp_process_deltas(struct update_notification *parent, unsigned long serial)
{
	struct delta_head *deltas[parent->global_data.serial - serial];
	struct deltas_proc_args args;
	size_t deltas_len;
	size_t index;
	int error;

	deltas_len = parent->global_data.serial - serial;
	for (index = 0; index < deltas_len; index++)
		deltas[index] = NULL;

	args.deltas = deltas;
	args.serial = serial;
	args.deltas_set = 0;

	error = deltas_head_for_each(parent->deltas_list, __get_pending_delta,
	    &args);
	if (error)
		goto release_deltas;

	/* Check that all expected deltas are set */
	if (args.deltas_set != deltas_len) {
		error = pr_err("Less deltas than expected: should be from serial %lu to %lu (%lu), but got only %lu",
		    serial, parent->global_data.serial, deltas_len,
		    args.deltas_set);
		goto release_deltas;
	}

	/* Now process each delta in order */
	for (index = 0; index < deltas_len; index++) {
		error = process_delta(deltas[index], parent);
		if (error)
			break;
	}
	/* Error 0 it's ok */
release_deltas:
	for (index = 0; index < deltas_len; index++)
		if (deltas[index] != NULL)
			delta_head_refput(deltas[index]);

	return error;
}
