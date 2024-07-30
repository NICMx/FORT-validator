#include "rrdp.h"

#include <ctype.h>
#include <openssl/evp.h>

#include "alloc.h"
#include "base64.h"
#include "cache.h"
#include "common.h"
#include "config.h"
#include "file.h"
#include "hash.h"
#include "http.h"
#include "json_util.h"
#include "log.h"
#include "relax_ng.h"
#include "thread_var.h"
#include "types/url.h"

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

struct file_metadata {
	char *uri;
	unsigned char *hash; /* Array. Sometimes omitted. */
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
	char const *url;
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

struct parser_args {
	struct rrdp_session *session;
	struct cache_node *rpp;
};

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
	free(serial->str);
	serial->str = NULL;
}

static void
session_cleanup(struct rrdp_session *meta)
{
	free(meta->session_id);
	BN_free(meta->serial.num);
	free(meta->serial.str);
}

static void
metadata_cleanup(struct file_metadata *meta)
{
	free(meta->hash);
	free(meta->uri);
}

static void
notification_delta_cleanup(struct notification_delta *delta)
{
	serial_cleanup(&delta->serial);
	metadata_cleanup(&delta->meta);
}

static void
update_notification_init(struct update_notification *notif, char const *url)
{
	memset(&notif->session, 0, sizeof(notif->session));
	memset(&notif->snapshot, 0, sizeof(notif->snapshot));
	notification_deltas_init(&notif->deltas);
	notif->url = url;
}

static void
__update_notification_cleanup(struct update_notification *notif)
{
	metadata_cleanup(&notif->snapshot);
	notification_deltas_cleanup(&notif->deltas, notification_delta_cleanup);
}

static void
update_notification_cleanup(struct update_notification *notif)
{
	session_cleanup(&notif->session);
	__update_notification_cleanup(notif);
}

static int
validate_hash(struct file_metadata *meta, char const *path)
{
	return hash_validate_file(hash_get_sha256(), path,
	    meta->hash, meta->hash_len);
}

static int
parse_ulong(xmlTextReaderPtr reader, char const *attr, unsigned long *result)
{
	xmlChar *str;
	int error;

	str = xmlTextReaderGetAttribute(reader, BAD_CAST attr);
	if (str == NULL)
		return pr_val_err("Couldn't find xml attribute '%s'", attr);

	errno = 0;
	*result = strtoul((char const *) str, NULL, 10);
	error = errno;
	xmlFree(str);
	if (error) {
		pr_val_err("Invalid long value '%s': %s", str, strerror(error));
		return error;
	}

	return 0;
}

/*
 * Few notes:
 *
 * - From my reading of it, the whole reason (awkward abstraction aside) why
 *   libxml2 replaces char* with xmlChar* is UTF-8 support. Which isn't really
 *   useful for us; the RRDP RFC explicitely boils its XMLs' character sets down
 *   to ASCII.
 * - I call it "awkward" because I'm not a big fan of the API. The library
 *   doesn't provide tools to convert them to char*s, and seems to expect us to
 *   cast them when we know it's safe. However...
 * - I can't find a contract that states that xmlChar*s are NULL-terminated.
 *   (Though this is very obvious from the implementation.) However, see the
 *   test_xmlChar_NULL_assumption unit test.
 * - The API also doesn't provide a means to retrieve the actual size (in bytes)
 *   of the xmlChar*, so not relying on the NULL character is difficult.
 * - libxml2 automatically performs validations defined by the grammar's
 *   constraints. (At time of writing, you can find the grammar at relax_ng.h.)
 *   If you're considering adding some sort of string sanitization, check if the
 *   grammar isn't already doing it for you.
 * - The grammar already effectively enforces printable ASCII.
 *
 * So... until some sort of bug or corner case shows up, it seems you can assume
 * that the result will be safely-casteable to a dumb char*. (NULL-terminated,
 * 100% printable ASCII.)
 *
 * However, you should still deallocate it with xmlFree().
 */
static xmlChar *
parse_string(xmlTextReaderPtr reader, char const *attr)
{
	xmlChar *result;

	if (attr == NULL) {
		result = xmlTextReaderValue(reader);
		if (result == NULL)
			pr_val_err("Tag '%s' seems to be empty.",
			    xmlTextReaderConstLocalName(reader));
	} else {
		result = xmlTextReaderGetAttribute(reader, BAD_CAST attr);
		if (result == NULL)
			pr_val_err("Tag '%s' is missing attribute '%s'.",
			    xmlTextReaderConstLocalName(reader), attr);
	}

	return result;
}

static char *
parse_uri(xmlTextReaderPtr reader)
{
	xmlChar *xmlattr;
	char *result;

	xmlattr = parse_string(reader, RRDP_ATTR_URI);
	if (xmlattr == NULL)
		return NULL;

	result = pstrdup((char const *)xmlattr);

	xmlFree(xmlattr);
	return result;
}

static unsigned int
hexchar2uint(xmlChar xmlchar)
{
	if ('0' <= xmlchar && xmlchar <= '9')
		return xmlchar - '0';
	if ('a' <= xmlchar && xmlchar <= 'f')
		return xmlchar - 'a' + 10;
	if ('A' <= xmlchar && xmlchar <= 'F')
		return xmlchar - 'A' + 10;
	return 32;
}

static int
hexstr2sha256(xmlChar *hexstr, unsigned char **result, size_t *hash_len)
{
	unsigned char *hash;
	unsigned int digit;
	size_t i;

	if (xmlStrlen(hexstr) != 2 * RRDP_HASH_LEN)
		return EINVAL;

	hash = pmalloc(RRDP_HASH_LEN);

	for (i = 0; i < RRDP_HASH_LEN; i++) {
		digit = hexchar2uint(hexstr[2 * i]);
		if (digit > 15)
			goto fail;
		hash[i] = digit << 4;

		digit = hexchar2uint(hexstr[2 * i + 1]);
		if (digit > 15)
			goto fail;
		hash[i] |= digit;
	}

	*result = hash;
	*hash_len = RRDP_HASH_LEN;
	return 0;

fail:
	free(hash);
	return EINVAL;
}

static int
parse_hash(xmlTextReaderPtr reader, unsigned char **result, size_t *result_len)
{
	xmlChar *xmlattr;
	int error;

	xmlattr = xmlTextReaderGetAttribute(reader, BAD_CAST RRDP_ATTR_HASH);
	if (xmlattr == NULL)
		return 0;

	error = hexstr2sha256(xmlattr, result, result_len);

	xmlFree(xmlattr);
	if (error)
		return pr_val_err("The '" RRDP_ATTR_HASH "' xml attribute does not appear to be a SHA-256 hash.");
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
	xmlChar *xmlserial;

	xmlserial = parse_string(reader, RRDP_ATTR_SERIAL);
	if (xmlserial == NULL)
		return EINVAL;
	serial->str = pstrdup((const char *) xmlserial);
	xmlFree(xmlserial);

	serial->num = BN_create();
	if (BN_dec2bn(&serial->num, serial->str) == 0)
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
	xmlChar *xmlsession;
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

	xmlsession = parse_string(reader, RRDP_ATTR_SESSION_ID);
	if (xmlsession == NULL)
		return EINVAL;
	meta->session_id = pstrdup((const char *) xmlsession);
	xmlFree(xmlsession);

	error = parse_serial(reader, &meta->serial);
	if (error) {
		free(meta->session_id);
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

	if (strcmp(expected->session_id, actual.session_id) != 0) {
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
parse_file_metadata(xmlTextReaderPtr reader, struct file_metadata *meta)
{
	int error;

	memset(meta, 0, sizeof(*meta));

	meta->uri = parse_uri(reader);
	if (meta->uri == NULL)
		return -EINVAL;

	error = parse_hash(reader, &meta->hash, &meta->hash_len);
	if (error) {
		free(meta->uri);
		meta->uri = NULL;
		return error;
	}

	return 0;
}

/* Does not clean @tag on failure. */
static int
parse_publish(xmlTextReaderPtr reader, struct publish *tag)
{
	xmlChar *base64_str;
	int error;

	error = parse_file_metadata(reader, &tag->meta);
	if (error)
		return error;

	/* Read the text */
	if (xmlTextReaderRead(reader) != 1)
		return pr_val_err(
		    "Couldn't read publish content of element '%s'",
		    tag->meta.uri
		);

	base64_str = parse_string(reader, NULL);
	if (base64_str == NULL)
		return -EINVAL;
	if (!base64_decode((char *)base64_str, 0, &tag->content, &tag->content_len))
		error = pr_val_err("Cannot decode publish tag's base64.");
	xmlFree(base64_str);

	return error;
}

/* Does not clean @tag on failure. */
static int
parse_withdraw(xmlTextReaderPtr reader, struct withdraw *tag)
{
	int error;

	error = parse_file_metadata(reader, &tag->meta);
	if (error)
		return error;

	if (!tag->meta.hash)
		return pr_val_err("Withdraw '%s' is missing a hash.",
		    tag->meta.uri);

	return 0;
}

/* Remove a local file and its directory tree (if empty) */
static int
delete_file(char const *path)
{
	/* Delete parent dirs only if empty. */
	return delete_dir_recursive_bottom_up(path);
}

static int
handle_publish(xmlTextReaderPtr reader, struct cache_node *rpp)
{
	struct publish tag = { 0 };
	struct cache_node *node;
	int error;

	error = parse_publish(reader, &tag);
	if (error)
		goto end;

	// XXX Not going to pass URL validation.
	node = cachent_provide(rpp, tag.meta.uri);
	if (!node) {
		error = pr_val_err("Broken RRDP: <publish> is attempting to create file '%s' outside of its publication point '%s'.",
		    tag.meta.uri, rpp->url);
		goto end;
	}

	/* rfc8181#section-2.2 */
	if (node->flags & CNF_CACHED) {
		if (tag.meta.hash == NULL) {
			// XXX watch out for this in the log before release
			error = pr_val_err("RRDP desync: <publish> is attempting to create '%s', but the file is already cached.",
			    tag.meta.uri);
			goto end;
		}

		error = validate_hash(&tag.meta, node->path);
		if (error)
			goto end;

	} else if (tag.meta.hash != NULL) {
		// XXX watch out for this in the log before release
		error = pr_val_err("RRDP desync: <publish> is attempting to overwrite '%s', but the file is absent in the cache.",
		    tag.meta.uri);
		goto end;
	}

	error = file_write_full(node->tmppath, tag.content, tag.content_len);

end:	metadata_cleanup(&tag.meta);
	free(tag.content);
	return error;
}

static int
handle_withdraw(xmlTextReaderPtr reader, struct cache_node *rpp)
{
	struct withdraw tag = { 0 };
	struct cache_node *node;
	int error;

	error = parse_withdraw(reader, &tag);
	if (error)
		goto end;

	// XXX Not going to pass URL validation.
	node = cachent_provide(rpp, tag.meta.uri);
	if (!node) {
		error = pr_val_err("Broken RRDP: <withdraw> is attempting to delete file '%s' outside of its publication point '%s'.",
		    tag.meta.uri, rpp->url);
		goto end;
	}

	/*
	 * XXX CNF_CACHED's comment suggests I should check parents,
	 * but this is not rsync.
	 */
	if (!(node->flags & CNF_CACHED)) {
		/* XXX May want to query the actualy filesystem, to be sure */
		error = pr_val_err("RRDP desync: <withdraw> is attempting to delete file '%s', but it doesn't appear to exist.",
		    tag.meta.uri);
		goto end;
	}

	error = validate_hash(&tag.meta, node->path);
	if (error)
		goto end;

	node->flags |= CNF_WITHDRAWN;

end:	metadata_cleanup(&tag.meta);
	return error;
}

static int
parse_notification_snapshot(xmlTextReaderPtr reader,
    struct update_notification *notif)
{
	int error;

	error = parse_file_metadata(reader, &notif->snapshot);
	if (error)
		return error;

	if (!notif->snapshot.hash)
		return pr_val_err("Snapshot '%s' is missing a hash.",
		    notif->snapshot.uri);

	if (!url_same_origin(notif->url, notif->snapshot.uri))
		return pr_val_err("Notification '%s' and Snapshot '%s' are not hosted by the same origin.",
		    notif->url, notif->snapshot.uri);

	return 0;
}

static int
parse_notification_delta(xmlTextReaderPtr reader,
    struct update_notification *notif)
{
	struct notification_delta delta = { 0 };
	int error;

	error = parse_serial(reader, &delta.serial);
	if (error)
		return error;

	error = parse_file_metadata(reader, &delta.meta);
	if (error)
		goto fail;

	if (!delta.meta.hash) {
		error = pr_val_err("Delta '%s' is missing a hash.",
		    delta.meta.uri);
		goto fail;
	}

	if (!url_same_origin(notif->url, delta.meta.uri)) {
		error = pr_val_err("Notification %s and Delta %s are not hosted by the same origin.",
		    notif->url, delta.meta.uri);
		goto fail;
	}

	notification_deltas_add(&notif->deltas, &delta);
	return 0;

fail:	serial_cleanup(&delta.serial);
	metadata_cleanup(&delta.meta);
	return error;
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
			return parse_notification_snapshot(reader, notif);
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
parse_notification(struct cache_node *notif, struct update_notification *result)
{
	int error;

	update_notification_init(result, notif->url);

	error = relax_ng_parse(notif->tmppath, xml_read_notif, result);
	if (error)
		update_notification_cleanup(result);

	return error;
}

static int
xml_read_snapshot(xmlTextReaderPtr reader, void *arg)
{
	struct parser_args *args = arg;
	xmlReaderTypes type;
	xmlChar const *name;
	int error;

	name = xmlTextReaderConstLocalName(reader);
	type = xmlTextReaderNodeType(reader);
	switch (type) {
	case XML_READER_TYPE_ELEMENT:
		if (xmlStrEqual(name, BAD_CAST RRDP_ELEM_PUBLISH))
			error = handle_publish(reader, args->rpp);
		else if (xmlStrEqual(name, BAD_CAST RRDP_ELEM_SNAPSHOT))
			error = validate_session(reader, args->session);
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
parse_snapshot(struct rrdp_session *session, char const *path,
    struct cache_node *rpp)
{
	struct parser_args args = { .session = session, .rpp = rpp };
	return relax_ng_parse(path, xml_read_snapshot, &args);
}

static int
validate_session_desync(struct cachefile_notification *old_notif,
    struct update_notification *new_notif)
{
	struct rrdp_hash *old_delta;
	struct file_metadata *new_delta;
	size_t i;
	size_t delta_threshold;

	if (strcmp(old_notif->session.session_id, new_notif->session.session_id) != 0) {
		pr_val_debug("The Notification's session ID changed.");
		return EINVAL;
	}

	old_delta = STAILQ_FIRST(&old_notif->delta_hashes);
	delta_threshold = config_get_rrdp_delta_threshold();

	for (i = 0; i < delta_threshold; i++) {
		if (old_delta == NULL)
			return 0; /* Cache has few deltas */
		if (i >= new_notif->deltas.len)
			return 0; /* Notification has few deltas */

		new_delta = &new_notif->deltas.array[i].meta;
		if (memcmp(old_delta->bytes, new_delta->hash, RRDP_HASH_LEN) != 0) {
			pr_val_debug("Notification delta hash does not match cached delta hash; RRDP session desynchronization detected.");
			return EINVAL;
		}

		old_delta = STAILQ_NEXT(old_delta, hook);
	}

	return 0; /* First $delta_threshold delta hashes match */
}

/* TODO (performance) Stream instead of caching notifs, snapshots & deltas. */
static int
dl_tmp(char const *url, char **path)
{
	int error;

	error = cache_tmpfile(path);
	if (error)
		return error;

	error = http_download(url, *path, 0, NULL);
	if (error)
		free(*path);

	return error;
}

static int
handle_snapshot(struct update_notification *notif, struct cache_node *rpp)
{
	char *tmppath;
	int error;

	pr_val_debug("Processing snapshot '%s'.", notif->snapshot.uri);
	fnstack_push(notif->snapshot.uri);

	error = dl_tmp(notif->snapshot.uri, &tmppath);
	if (error)
		goto end1;
	error = validate_hash(&notif->snapshot, tmppath);
	if (error)
		goto end2;
	error = parse_snapshot(&notif->session, tmppath, rpp);
	delete_file(tmppath);

end2:	free(tmppath);
end1:	fnstack_pop();
	return error;
}

static int
xml_read_delta(xmlTextReaderPtr reader, void *arg)
{
	struct parser_args *args = arg;
	xmlReaderTypes type;
	xmlChar const *name;
	int error;

	name = xmlTextReaderConstLocalName(reader);
	type = xmlTextReaderNodeType(reader);
	switch (type) {
	case XML_READER_TYPE_ELEMENT:
		if (xmlStrEqual(name, BAD_CAST RRDP_ELEM_PUBLISH))
			error = handle_publish(reader, args->rpp);
		else if (xmlStrEqual(name, BAD_CAST RRDP_ELEM_WITHDRAW))
			error = handle_withdraw(reader, args->rpp);
		else if (xmlStrEqual(name, BAD_CAST RRDP_ELEM_DELTA))
			error = validate_session(reader, args->session);
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
parse_delta(struct update_notification *notif, struct notification_delta *delta,
    char const *path, struct cache_node *node)
{
	struct parser_args args;
	struct rrdp_session session;
	int error;

	error = validate_hash(&delta->meta, path);
	if (error)
		return error;

	session.session_id = notif->session.session_id;
	session.serial = delta->serial;
	args.session = &session;
	args.rpp = node;

	return relax_ng_parse(path, xml_read_delta, &args);
}

static int
handle_delta(struct update_notification *notif,
    struct notification_delta *delta, struct cache_node *node)
{
	char *tmppath;
	int error;

	pr_val_debug("Processing delta '%s'.", delta->meta.uri);
	fnstack_push(delta->meta.uri);

	error = dl_tmp(delta->meta.uri, &tmppath);
	if (error)
		goto end;
	error = parse_delta(notif, delta, tmppath, node);
	delete_file(tmppath);

	free(tmppath);
end:	fnstack_pop();
	return error;
}

static int
handle_deltas(struct update_notification *notif, struct cache_node *node)
{
	struct rrdp_serial *old;
	struct rrdp_serial *new;
	BIGNUM *diff_bn;
	BN_ULONG diff;
	array_index d;
	int error;

	if (notif->deltas.len == 0) {
		pr_val_warn("There's no delta list to process.");
		return -ENOENT;
	}

	old = &node->notif.session.serial;
	new = &notif->session.serial;

	pr_val_debug("Handling RRDP delta serials %s-%s.", old->str, new->str);

	diff_bn = BN_create();
	if (!BN_sub(diff_bn, new->num, old->num)) {
		BN_free(diff_bn);
		return pr_val_err("Could not subtract %s - %s; unknown cause.",
		    new->str, old->str);
	}
	if (BN_is_negative(diff_bn)) {
		BN_free(diff_bn);
		return pr_val_err("Cached delta's serial [%s] is larger than Notification's current serial [%s].",
		   old->str, new->str);
	}
	diff = BN_get_word(diff_bn);
	BN_free(diff_bn);
	if (diff > config_get_rrdp_delta_threshold() || diff > notif->deltas.len)
		return pr_val_err("Cached RPP is too old. (Cached serial: %s; current serial: %s)",
		    old->str, new->str);

	for (d = notif->deltas.len - diff; d < notif->deltas.len; d++) {
		error = handle_delta(notif, &notif->deltas.array[d], node);
		if (error)
			return error;
	}

	return 0;
}

/*
 * Initializes @old by extracting relevant data from @new.
 * Consumes @new.
 */
static void
init_notif(struct cachefile_notification *old, struct update_notification *new)
{
	size_t dn;
	size_t i;
	struct rrdp_hash *hash;

	old->session = new->session;
	STAILQ_INIT(&old->delta_hashes);

	dn = config_get_rrdp_delta_threshold();
	if (new->deltas.len < dn)
		dn = new->deltas.len;

	for (i = 0; i < dn; i++) {
		hash = pmalloc(sizeof(struct rrdp_hash));
		memcpy(hash->bytes, new->deltas.array[i].meta.hash, RRDP_HASH_LEN);
		STAILQ_INSERT_TAIL(&old->delta_hashes, hash, hook);
	}

	__update_notification_cleanup(new);
}

static void
drop_notif(struct cachefile_notification *notif)
{
	struct rrdp_hash *hash;

	session_cleanup(&notif->session);
	while (!STAILQ_EMPTY(&notif->delta_hashes)) {
		hash = STAILQ_FIRST(&notif->delta_hashes);
		STAILQ_REMOVE_HEAD(&notif->delta_hashes, hook);
		free(hash);
	}
}

/*
 * Updates @old with the new information carried by @new.
 * Consumes @new on success.
 */
static int
update_notif(struct cachefile_notification *old, struct update_notification *new)
{
	BIGNUM *diff_bn;
	BN_ULONG diff; /* difference between the old and new serials */
	size_t d, dn; /* delta counter, delta "num" (total) */
	struct rrdp_hash *hash;

	diff_bn = BN_create();
	if (!BN_sub(diff_bn, new->session.serial.num, old->session.serial.num))
		return val_crypto_err("OUCH! libcrypto cannot subtract %s - %s",
		    new->session.serial.str, old->session.serial.str);
	if (BN_is_negative(diff_bn))
		/* The validation was the BN_cmp() in the caller. */
		pr_crit("%s - %s < 0 despite validations.",
		    new->session.serial.str, old->session.serial.str);

	diff = BN_get_word(diff_bn);
	if (diff > new->deltas.len)
		/* Should be <= because it was already compared to the delta threshold. */
		pr_crit("%lu > %zu despite validations.",
		    diff, new->deltas.len);

	BN_free(old->session.serial.num);
	free(old->session.serial.str);
	old->session.serial = new->session.serial;

	dn = diff;
	STAILQ_FOREACH(hash, &old->delta_hashes, hook)
		dn++;

	for (d = new->deltas.len - diff; d < new->deltas.len; d++) {
		hash = pmalloc(sizeof(struct rrdp_hash));
		memcpy(hash->bytes, new->deltas.array[d].meta.hash, RRDP_HASH_LEN);
		STAILQ_INSERT_TAIL(&old->delta_hashes, hash, hook);
	}

	while (dn > config_get_rrdp_delta_threshold()) {
		hash = STAILQ_FIRST(&old->delta_hashes);
		STAILQ_REMOVE_HEAD(&old->delta_hashes, hook);
		free(hash);
		dn--;
	}

	free(new->session.session_id);
	__update_notification_cleanup(new);
	return 0;
}

static int
dl_notif(struct cache_node *notif)
{
	char *tmppath;
	bool changed;
	int error;

	error = cache_tmpfile(&tmppath);
	if (error)
		return error;

	error = http_download(notif->url, tmppath, notif->mtim, &changed);
	if (error) {
		free(tmppath);
		return error;
	}

	// XXX notif->flags |= CNF_CACHED | CNF_FRESH;
	if (changed) {
		notif->mtim = time(NULL); // XXX
		notif->tmppath = tmppath;
	} else {
		free(tmppath);
	}

	return 0;
}

/*
 * Downloads the Update Notification @notif, and updates the cache accordingly.
 *
 * "Updates the cache accordingly" means it downloads the missing deltas or
 * snapshot, and explodes them into @rpp's tmp directory.
 */
int
rrdp_update(struct cache_node *notif)
{
	struct cachefile_notification *old;
	struct update_notification new;
	int serial_cmp;
	int error;

	fnstack_push(notif->url);
	pr_val_debug("Processing notification.");

	///////////////////////////////////////////////////////////////////////

	error = dl_notif(notif);
	if (error)
		goto end;

	if (!notif->tmppath) {
		pr_val_debug("The Notification has not changed.");
		goto end;
	}

	error = parse_notification(notif, &new);
	if (error)
		goto end;

	remove(notif->tmppath); // XXX
	if (mkdir(notif->tmppath, 0777) == -1) {
		error = errno;
		pr_val_err("Can't create notification's temporal directory: %s",
		    strerror(error));
		goto clean_notif;
	}

	///////////////////////////////////////////////////////////////////////

	pr_val_debug("New session/serial: %s/%s", new.session.session_id,
	    new.session.serial.str);

	if (!(notif->flags & CNF_NOTIFICATION)) {
		pr_val_debug("This is a new Notification.");
		error = handle_snapshot(&new, notif);
		if (error)
			goto clean_notif;

		notif->flags |= CNF_NOTIFICATION;
		init_notif(&notif->notif, &new);
		goto end;
	}

	old = &notif->notif;
	serial_cmp = BN_cmp(old->session.serial.num, new.session.serial.num);
	if (serial_cmp < 0) {
		pr_val_debug("The Notification's serial changed.");
		error = validate_session_desync(old, &new);
		if (error)
			goto snapshot_fallback;
		error = handle_deltas(&new, notif);
		if (error)
			goto snapshot_fallback;
		error = update_notif(old, &new);
		if (!error)
			goto end;
		/*
		 * The files are exploded and usable, but @cached is not
		 * updatable. So drop and create it anew.
		 * We might lose some delta hashes, but it's better than
		 * re-snapshotting the next time the notification changes.
		 * Not sure if it matters. This looks so unlikely, it's
		 * practically dead code.
		 */
		goto reset_notif;

	} else if (serial_cmp > 0) {
		pr_val_debug("Cached serial is higher than notification serial.");
		goto snapshot_fallback;

	} else {
		pr_val_debug("The Notification changed, but the session ID and serial didn't, and no session desync was detected.");
		goto clean_notif;
	}

snapshot_fallback:
	pr_val_debug("Falling back to snapshot.");
	error = handle_snapshot(&new, notif);
	if (error)
		goto clean_notif;

reset_notif:
	drop_notif(old);
	init_notif(old, &new);
	goto end;

clean_notif:
	update_notification_cleanup(&new);

end:
	fnstack_pop();
	return error;
}

#define TAGNAME_SESSION "session_id"
#define TAGNAME_SERIAL "serial"
#define TAGNAME_DELTAS "deltas"

/* binary to char */
static char
hash_b2c(unsigned char bin)
{
	bin &= 0xF;
	return (bin < 10) ? (bin + '0') : (bin + 'a' - 10);
}

json_t *
rrdp_notif2json(struct cachefile_notification *notif)
{
	json_t *json;
	json_t *deltas;
	char hash_str[2 * RRDP_HASH_LEN + 1];
	struct rrdp_hash *hash;
	size_t i;

	if (notif == NULL)
		return NULL;

	json = json_object();
	if (json == NULL)
		enomem_panic();

	if (json_add_str(json, TAGNAME_SESSION, notif->session.session_id))
		goto fail;
	if (json_add_str(json, TAGNAME_SERIAL, notif->session.serial.str))
		goto fail;

	if (STAILQ_EMPTY(&notif->delta_hashes))
		return json; /* Happy path, but unlikely. */

	deltas = json_array();
	if (deltas == NULL)
		enomem_panic();
	if (json_object_add(json, TAGNAME_DELTAS, deltas))
		goto fail;

	hash_str[2 * RRDP_HASH_LEN] = '\0';
	STAILQ_FOREACH(hash, &notif->delta_hashes, hook) {
		for (i = 0; i < RRDP_HASH_LEN; i++) {
			hash_str[2 * i    ] = hash_b2c(hash->bytes[i] >> 4);
			hash_str[2 * i + 1] = hash_b2c(hash->bytes[i]     );
		}
		if (json_array_append(deltas, json_string(hash_str)))
			goto fail;
	}

	return json;

fail:
	json_decref(json);
	return NULL;
}

static char
hash_c2b(char chara)
{
	if ('a' <= chara && chara <= 'f')
		return chara - 'a' + 10;
	if ('A' <= chara && chara <= 'F')
		return chara - 'A' + 10;
	if ('0' <= chara && chara <= '9')
		return chara - '0';
	return -1;
}

static int
json2dh(json_t *json, struct rrdp_hash **result)
{
	char const *src;
	size_t srclen;
	struct rrdp_hash *dst;
	char digit;
	size_t i;

	src = json_string_value(json);
	if (src == NULL)
		return pr_op_err("Hash is not a string.");

	srclen = strlen(src);
	if (srclen != 2 * RRDP_HASH_LEN)
		return pr_op_err("Hash is not %d characters long.", 2 * RRDP_HASH_LEN);

	dst = pmalloc(sizeof(struct rrdp_hash));
	for (i = 0; i < RRDP_HASH_LEN; i++) {
		digit = hash_c2b(src[2 * i]);
		if (digit == -1)
			goto bad_char;
		dst->bytes[i] = digit << 4;
		digit = hash_c2b(src[2 * i + 1]);
		if (digit == -1)
			goto bad_char;
		dst->bytes[i] |= digit;
	}

	*result = dst;
	return 0;

bad_char:
	free(dst);
	return pr_op_err("Invalid characters in hash: %c%c", src[2 * i], src[2 * i] + 1);
}

static void
clear_delta_hashes(struct cachefile_notification *notif)
{
	struct rrdp_hash *hash;

	while (!STAILQ_EMPTY(&notif->delta_hashes)) {
		hash = STAILQ_FIRST(&notif->delta_hashes);
		STAILQ_REMOVE_HEAD(&notif->delta_hashes, hook);
		free(hash);
	}
}

int
rrdp_json2notif(json_t *json, struct cachefile_notification **result)
{
	struct cachefile_notification *notif;
	char const *str;
	json_t *jdeltas;
	size_t d, dn;
	struct rrdp_hash *hash;
	int error;

	notif = pzalloc(sizeof(struct cachefile_notification));
	STAILQ_INIT(&notif->delta_hashes);

	error = json_get_str(json, TAGNAME_SESSION, &str);
	if (error) {
		if (error > 0)
			pr_op_err("Node is missing the '" TAGNAME_SESSION "' tag.");
		goto revert_notif;
	}
	notif->session.session_id = pstrdup(str);

	error = json_get_str(json, TAGNAME_SERIAL, &str);
	if (error) {
		if (error > 0)
			pr_op_err("Node is missing the '" TAGNAME_SERIAL "' tag.");
		goto revert_session;
	}
	notif->session.serial.str = pstrdup(str);

	notif->session.serial.num = BN_create();
	if (!BN_dec2bn(&notif->session.serial.num, notif->session.serial.str)) {
		error = pr_op_err("Not a serial number: %s", notif->session.serial.str);
		goto revert_serial;
	}

	error = json_get_array(json, TAGNAME_DELTAS, &jdeltas);
	if (error) {
		if (error > 0)
			goto success;
		goto revert_serial;
	}

	dn = json_array_size(jdeltas);
	if (dn == 0)
		goto success;
	if (dn > config_get_rrdp_delta_threshold())
		dn = config_get_rrdp_delta_threshold();

	for (d = 0; d < dn; d++) {
		error = json2dh(json_array_get(jdeltas, d), &hash);
		if (error)
			goto revert_deltas;
		STAILQ_INSERT_TAIL(&notif->delta_hashes, hash, hook);
	}

success:
	*result = notif;
	return 0;

revert_deltas:
	clear_delta_hashes(notif);
revert_serial:
	BN_free(notif->session.serial.num);
	free(notif->session.serial.str);
revert_session:
	free(notif->session.session_id);
revert_notif:
	free(notif);
	return error;
}

void
rrdp_notif_free(struct cachefile_notification *notif)
{
	if (notif == NULL)
		return;

	session_cleanup(&notif->session);
	clear_delta_hashes(notif);
	free(notif);
}
