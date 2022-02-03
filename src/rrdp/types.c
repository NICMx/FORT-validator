#include "rrdp/types.h"

#include <ctype.h>
#include <openssl/x509v3.h>
#include "common.h"
#include "file.h"
#include "log.h"
#include "str_token.h"
#include "crypto/base64.h"
#include "crypto/hash.h"
#include "xml/relax_ng.h"

/* Represents a <publish> element */
struct rrdp_publish {
	struct rrdp_file_metadata target;
	unsigned char *content;
	size_t content_len;
};

static void
rrdp_session_init(struct rrdp_session *session)
{
	session->id = NULL;
}

static void
rrdp_session_cleanup(struct rrdp_session *session)
{
	free(session->id);
}

DEFINE_ARRAY_LIST_FUNCTIONS(rrdp_notification_deltas,
    struct rrdp_notification_delta, )

void
rrdp_notification_init(struct rrdp_notification *notification,
    struct rpki_uri *uri)
{
	notification->uri = uri;
	rrdp_session_init(&notification->session);
	rrdp_file_metadata_init(&notification->snapshot);
	rrdp_notification_deltas_init(&notification->deltas_list);
}

void
rrdp_file_metadata_init(struct rrdp_file_metadata *meta)
{
	memset(meta, 0, sizeof(*meta));
}

void
rrdp_file_metadata_cleanup(struct rrdp_file_metadata *meta)
{
	free(meta->hash);
	uri_refput(meta->uri);
}

int
rrdp_file_metadata_validate_hash(struct rrdp_file_metadata *meta)
{
	return hash_validate_file("sha256", meta->uri, meta->hash,
	    meta->hash_len);
}

static void
rrdp_notification_delta_destroy(struct rrdp_notification_delta *delta)
{
	rrdp_file_metadata_cleanup(&delta->meta);
}

void
rrdp_notification_cleanup(struct rrdp_notification *notification)
{
	rrdp_session_cleanup(&notification->session);
	rrdp_file_metadata_cleanup(&notification->snapshot);
	rrdp_notification_deltas_cleanup(&notification->deltas_list,
	    rrdp_notification_delta_destroy);
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
		result = strdup(content);
		if (result == NULL)
			return pr_enomem();
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
	int error;

	*result = NULL;

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

	error = string_clone(xml_value, xmlStrlen(xml_value), result);
	xmlFree(xml_value);
	return error;
}

/*
 * required `true` means "mandatory," `false` means "forbidden."
 * (Not "optional.")
 */
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
	if (required) {
		if (xml_value == NULL) {
			return pr_val_err("RRDP file: xml attribute '%s' is mandatory.",
			    attr);
		}
	} else {
		if (xml_value != NULL) {
			return pr_val_err("RRDP file: Unexpected attribute '%s'",
			    attr);
		}
		*result = NULL;
		*result_len = 0;
		return 0;
	}

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
validate_version(xmlTextReaderPtr reader)
{
	unsigned long version;
	int error;

	error = xml_parse_long(reader, "version", &version);
	if (error)
		return error;

	if (version != 1ul)
		return pr_val_err("Invalid version. Expected '1', got '%lu'.",
		    version);

	return 0;
}

int
parse_header_tag(xmlTextReaderPtr reader, struct rrdp_session *result)
{
	static const xmlChar *NAMESPACE = BAD_CAST "http://www.ripe.net/rpki/rrdp";

	const xmlChar *namespace;
	int error;

	namespace = xmlTextReaderConstNamespaceUri(reader);
	if (!xmlStrEqual(namespace, NAMESPACE))
		return pr_val_err("Unknown namespace: '%s'", namespace);
	error = validate_version(reader);
	if (error)
		return error;

	error = parse_string(reader, "session_id", &result->id);
	if (error)
		return error;
	error = xml_parse_long(reader, "serial", &result->serial);
	if (error)
		free(result->id);

	return error;
}

int
parse_simple_uri_attribute(xmlTextReaderPtr reader,
    struct rrdp_file_metadata *meta)
{
	char *guri;
	int error;

	error = parse_string(reader, "uri", &guri);
	if (error)
		return error;

	return uri_create(guri, URI_TYPE_HTTP_SIMPLE, &meta->uri);
}

int
parse_caged_uri_attribute(xmlTextReaderPtr reader,
    struct rrdp_notification *notif,
    struct rrdp_file_metadata *meta)
{
	char *guri;
	int error;

	error = parse_string(reader, "uri", &guri);
	if (error)
		return error;

	return uri_create_caged(guri, notif->uri, &meta->uri);
}

int
parse_hash_attribute(xmlTextReaderPtr reader, bool required,
    struct rrdp_file_metadata *meta)
{
	return parse_hex_string(reader, required, "hash", &meta->hash,
	    &meta->hash_len);
}

/*
 * Returns:
 *
 * - 0: session is valid
 * - ENOENT: session is invalid
 * - else: bad file
 */
int
validate_header_tag(xmlTextReaderPtr reader, struct rrdp_session *session)
{
	struct rrdp_session current;
	int error;

	rrdp_session_init(&current);

	error = parse_header_tag(reader, &current);
	if (error)
		return error;

	if (strcmp(session->id, current.id) != 0) {
		pr_val_info("session_id [%s] doesn't match notification's session_id [%s].",
		    current.id, session->id);
		goto invalid;
	}
	if (session->serial != current.serial) {
		pr_val_info("serial '%lu' doesn't match notification's serial '%lu'.",
		    current.serial, session->serial);
		goto invalid;
	}

	rrdp_session_cleanup(&current);
	return 0;

invalid:
	rrdp_session_cleanup(&current);
	return ENOENT;
}

static int
write_from_uri(struct rrdp_publish *publish)
{
	char const *file;
	FILE *out;
	size_t written;
	int error;

	file = uri_get_local(publish->target.uri);

	error = create_dir_recursive(file);
	if (error)
		return error;
	error = file_write(file, &out);
	if (error)
		return error;

	written = fwrite(publish->content, sizeof(unsigned char),
	    publish->content_len, out);

	file_close(out);

	/* fwrite does not yield an error message... */
	if (written != (sizeof(unsigned char) * publish->content_len))
		return pr_val_err("Couldn't write bytes to file '%s'", file);

	return 0;
}

static int
parse_publish_tag(xmlTextReaderPtr reader, struct rrdp_notification *notif,
    bool require_hash, struct rrdp_publish *publish)
{
	char *base64_str;
	int error;

	/* Target */
	error = parse_caged_uri_attribute(reader, notif, &publish->target);
	if (error)
		return error;
	error = parse_hash_attribute(reader, require_hash, &publish->target);
	if (error)
		return error;

	/* Content */
	if (xmlTextReaderRead(reader) != 1)
		return pr_val_err("Couldn't read publish content of element '%s'",
		    uri_get_global(publish->target.uri));
	error = parse_string(reader, NULL, &base64_str);
	if (error)
		return error;

	error = base64_read(base64_str, &publish->content,
	    &publish->content_len);

	free(base64_str);
	return error;
}

int
handle_publish_tag(xmlTextReaderPtr reader, struct rrdp_notification *notif,
    bool require_hash)
{
	struct rrdp_publish publish;
	int error;

	rrdp_file_metadata_init(&publish.target);
	publish.content = NULL;
	publish.content_len = 0;

	error = parse_publish_tag(reader, notif, require_hash, &publish);
	if (error)
		goto end;

	/* rfc8181#section-2.2, paragraph 3 */
	if (publish.target.hash != NULL) {
		error = rrdp_file_metadata_validate_hash(&publish.target);
		if (error)
			goto end;
	}

	error = write_from_uri(&publish);

end:	rrdp_file_metadata_cleanup(&publish.target);
	free(publish.content);
	return error;
}
