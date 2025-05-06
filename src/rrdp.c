#include "rrdp.h"

#include <openssl/bn.h>
#include <openssl/sha.h>
#include <sys/queue.h>

#include "base64.h"
#include "cache.h"
#include "cachetmp.h"
#include "common.h"
#include "config.h"
#include "file.h"
#include "hash.h"
#include "http.h"
#include "json_util.h"
#include "log.h"
#include "relax_ng.h"
#include "thread_var.h"
#include "types/arraylist.h"
#include "types/path.h"
#include "types/str.h"
#include "types/uri.h"
#include "types/uthash.h"

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

struct rrdp_serial {
	BIGNUM *num;
	char *str;			/* String version of @num. */
};

struct rrdp_session {
	char *session_id;
	struct rrdp_serial serial;
};

#define RRDP_HASH_LEN SHA256_DIGEST_LENGTH

struct rrdp_hash {
	unsigned char bytes[RRDP_HASH_LEN];
	STAILQ_ENTRY(rrdp_hash) hook;
};

struct cache_file {
	struct cache_mapping map;
	UT_hash_handle hh;		/* Hash table hook */
};

/* Subset of the notification that is relevant to the TAL's cachefile */
struct rrdp_state {
	struct rrdp_session session;

	struct cache_file *files;	/* Hash table */
	struct cache_sequence seq;

	/*
	 * The 1st one contains the hash of the session.serial delta.
	 * The 2nd one contains the hash of the session.serial - 1 delta.
	 * The 3rd one contains the hash of the session.serial - 2 delta.
	 * And so on.
	 */
	STAILQ_HEAD(, rrdp_hash) delta_hashes;
};

struct file_metadata {
	struct uri uri;
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
	struct uri const *url;
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
	struct rrdp_state *state;
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

static struct cache_file *
state_find_file(struct rrdp_state const *state, struct uri const *url)
{
	char const *str;
	size_t len;
	struct cache_file *file;

	str = uri_str(url);
	len = uri_len(url);

	HASH_FIND(hh, state->files, str, len, file);

	return file;
}

static void
state_add_file(struct rrdp_state *state, struct cache_file *file)
{
	char const *url;
	size_t urlen;

	url = uri_str(&file->map.url);
	urlen = uri_len(&file->map.url);

	HASH_ADD_KEYPTR(hh, state->files, url, urlen, file);
}

static struct cache_file *
cache_file_add(struct rrdp_state *state, struct uri const *url, char *path)
{
	struct cache_file *file;

	file = pzalloc(sizeof(struct cache_file));
	uri_copy(&file->map.url, url);
	file->map.path = path;

	state_add_file(state, file);

	return file;
}

static void
metadata_cleanup(struct file_metadata *meta)
{
	uri_cleanup(&meta->uri);
	free(meta->hash);
}

static void
notification_delta_cleanup(struct notification_delta *delta)
{
	serial_cleanup(&delta->serial);
	metadata_cleanup(&delta->meta);
}

static void
update_notification_init(struct update_notification *notif,
    struct uri const *url)
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
validate_session(xmlTextReaderPtr reader, struct parser_args *args)
{
	struct rrdp_session actual = { 0 };
	int error;

	error = parse_session(reader, &actual);
	if (error)
		return error;

	if (strcmp(args->session->session_id, actual.session_id) != 0) {
		error = pr_val_err("File session id [%s] doesn't match notification's session id [%s]",
		    args->session->session_id, actual.session_id);
		goto end;
	}

	if (BN_cmp(actual.serial.num, args->session->serial.num) != 0) {
		error = pr_val_err("File serial [%s] doesn't match notification's serial [%s]",
		    actual.serial.str, args->session->serial.str);
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
	xmlChar *xmlattr;
	int error;

	memset(meta, 0, sizeof(*meta));

	xmlattr = parse_string(reader, RRDP_ATTR_URI);
	if (xmlattr == NULL)
		return -EINVAL;
	error = uri_init(&meta->uri, (char const *)xmlattr);
	xmlFree(xmlattr);
	if (error)
		return -EINVAL;

	error = parse_hash(reader, &meta->hash, &meta->hash_len);
	if (error) {
		uri_cleanup(&meta->uri);
		return error;
	}

	return 0;
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
handle_publish(xmlTextReaderPtr reader, struct parser_args *args)
{
	struct publish tag = { 0 };
	xmlChar *base64_str;
	struct cache_file *file;
	char *path;
	int error;

	/* Parse tag itself */
	error = parse_file_metadata(reader, &tag.meta);
	if (error)
		return error;
	if (xmlTextReaderRead(reader) != 1) {
		error = pr_val_err(
		    "Couldn't read publish content of element '%s'",
		    uri_str(&tag.meta.uri)
		);
		goto end;
	}
	if (!is_known_extension(&tag.meta.uri))
		goto end; /* Mirror rsync filters */

	/* Parse tag content */
	base64_str = parse_string(reader, NULL);
	if (base64_str == NULL) {
		error = -EINVAL;
		goto end;
	}
	if (!base64_decode((char *)base64_str, 0, &tag.content, &tag.content_len)) {
		xmlFree(base64_str);
		error = pr_val_err("Cannot decode publish tag's base64.");
		goto end;
	}
	xmlFree(base64_str);

	/* Parsing done */

	pr_clutter("Publish %s", logv_filename(uri_str(&tag.meta.uri)));

	file = state_find_file(args->state, &tag.meta.uri);

	/* rfc8181#section-2.2 */
	if (file) {
		if (tag.meta.hash == NULL) {
			// XXX watch out for this in the log before release
			error = pr_val_err("RRDP desync: "
			    "<publish> is attempting to create '%s', "
			    "but the file is already cached.",
			    uri_str(&tag.meta.uri));
			goto end;
		}

		error = validate_hash(&tag.meta, file->map.path);
		if (error)
			goto end;

		/*
		 * Reminder: This is needed because the file might be
		 * hard-linked. Our repo file write should not propagate
		 * to the fallback.
		 */
		if (remove(file->map.path) < 0) {
			error = errno;
			pr_val_err("Cannot delete %s: %s",
			    file->map.path, strerror(error));
			if (error != ENOENT)
				goto end;
		}

	} else {
		if (tag.meta.hash != NULL) {
			// XXX watch out for this in the log before release
			error = pr_val_err("RRDP desync: "
			    "<publish> is attempting to overwrite '%s', "
			    "but the file is absent in the cache.",
			    uri_str(&tag.meta.uri));
			goto end;
		}

		path = cseq_next(&args->state->seq);
		if (!path) {
			error = -EINVAL;
			goto end;
		}
		file = cache_file_add(args->state, &tag.meta.uri, path);
	}

	error = file_write_bin(file->map.path, tag.content, tag.content_len);

end:	metadata_cleanup(&tag.meta);
	free(tag.content);
	return error;
}

static int
handle_withdraw(xmlTextReaderPtr reader, struct parser_args *args)
{
	struct withdraw tag = { 0 };
	struct cache_file *file;
	int error;

	error = parse_file_metadata(reader, &tag.meta);
	if (error)
		return error;
	if (!is_known_extension(&tag.meta.uri))
		goto end; /* Mirror rsync filters */
	if (!tag.meta.hash) {
		error = pr_val_err("Withdraw '%s' is missing a hash.",
		    uri_str(&tag.meta.uri));
		goto end;
	}

	pr_clutter("Withdraw %s", logv_filename(uri_str(&tag.meta.uri)));

	file = state_find_file(args->state, &tag.meta.uri);

	if (!file) {
		error = pr_val_err("Broken RRDP: "
		    "<withdraw> is attempting to delete unknown file '%s'.",
		    uri_str(&tag.meta.uri));
		goto end;
	}

	error = validate_hash(&tag.meta, file->map.path);
	if (error)
		goto end;

	if (remove(file->map.path) < 0) {
		pr_val_warn("Cannot delete %s: %s", file->map.path,
		    strerror(errno));
		/* It's fine; keep going. */
	}

	HASH_DEL(args->state->files, file);
	map_cleanup(&file->map);
	free(file);

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
		    uri_str(&notif->snapshot.uri));

	if (!uri_same_origin(notif->url, &notif->snapshot.uri))
		return pr_val_err("Notification '%s' and Snapshot '%s' are not hosted by the same origin.",
		    uri_str(notif->url), uri_str(&notif->snapshot.uri));

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
		goto srl;

	if (!delta.meta.hash) {
		error = pr_val_err("Delta '%s' is missing a hash.",
		    uri_str(&delta.meta.uri));
		goto mta;
	}

	if (!uri_same_origin(notif->url, &delta.meta.uri)) {
		error = pr_val_err("Notification %s and Delta %s are not hosted by the same origin.",
		    uri_str(notif->url), uri_str(&delta.meta.uri));
		goto mta;
	}

	notification_deltas_add(&notif->deltas, &delta);
	return 0;

mta:	metadata_cleanup(&delta.meta);
srl:	serial_cleanup(&delta.serial);
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
parse_notification(struct uri const *url, char const *path,
    struct update_notification *result)
{
	int error;

	update_notification_init(result, url);

	error = relax_ng_parse(path, xml_read_notif, result);
	if (error)
		update_notification_cleanup(result);

	return error;
}

static int
xml_read_snapshot(xmlTextReaderPtr reader, void *arg)
{
	xmlReaderTypes type;
	xmlChar const *name;
	int error;

	name = xmlTextReaderConstLocalName(reader);
	type = xmlTextReaderNodeType(reader);
	switch (type) {
	case XML_READER_TYPE_ELEMENT:
		if (xmlStrEqual(name, BAD_CAST RRDP_ELEM_PUBLISH))
			error = handle_publish(reader, arg);
		else if (xmlStrEqual(name, BAD_CAST RRDP_ELEM_SNAPSHOT))
			error = validate_session(reader, arg);
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
    struct rrdp_state *state)
{
	struct parser_args args = { .session = session, .state = state };
	return relax_ng_parse(path, xml_read_snapshot, &args);
}

static int
validate_session_desync(struct rrdp_state *old_notif,
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
dl_tmp(struct uri const *url, char *path)
{
	cache_tmpfile(path);
	return http_download(url, path, 0, NULL);
}

static int
handle_snapshot(struct update_notification *new, struct rrdp_state *state)
{
	char tmppath[CACHE_TMPFILE_BUFLEN];
	struct uri *url;
	int error;

	url = &new->snapshot.uri;
	pr_val_debug("Processing snapshot '%s'.", uri_str(url));
	fnstack_push(uri_str(url));

	error = dl_tmp(url, tmppath);
	if (error)
		goto end;
	error = validate_hash(&new->snapshot, tmppath);
	if (error)
		goto end;
	error = parse_snapshot(&new->session, tmppath, state);
//	delete_file(tmppath); XXX

end:	fnstack_pop();
	return error;
}

static int
xml_read_delta(xmlTextReaderPtr reader, void *arg)
{
	xmlReaderTypes type;
	xmlChar const *name;
	int error;

	name = xmlTextReaderConstLocalName(reader);
	type = xmlTextReaderNodeType(reader);
	switch (type) {
	case XML_READER_TYPE_ELEMENT:
		if (xmlStrEqual(name, BAD_CAST RRDP_ELEM_PUBLISH))
			error = handle_publish(reader, arg);
		else if (xmlStrEqual(name, BAD_CAST RRDP_ELEM_WITHDRAW))
			error = handle_withdraw(reader, arg);
		else if (xmlStrEqual(name, BAD_CAST RRDP_ELEM_DELTA))
			error = validate_session(reader, arg);
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
    char const *path, struct rrdp_state *state)
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
	args.state = state;

	return relax_ng_parse(path, xml_read_delta, &args);
}

static int
handle_delta(struct update_notification *notif,
    struct notification_delta *delta, struct rrdp_state *state)
{
	char tmppath[CACHE_TMPFILE_BUFLEN];
	struct uri const *url;
	int error;

	url = &delta->meta.uri;

	pr_val_debug("Processing delta '%s'.", uri_str(url));
	fnstack_push(uri_str(url));

	error = dl_tmp(url, tmppath);
	if (error)
		goto end;
	error = parse_delta(notif, delta, tmppath, state);
//	delete_file(tmppath); XXX

end:	fnstack_pop();
	return error;
}

static int
handle_deltas(struct update_notification *notif, struct rrdp_state *state)
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

	old = &state->session.serial;
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
		error = handle_delta(notif, &notif->deltas.array[d], state);
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
init_notif(struct rrdp_state *old, struct update_notification *new)
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
drop_notif(struct rrdp_state *state)
{
	struct rrdp_hash *hash;

	session_cleanup(&state->session);
	while (!STAILQ_EMPTY(&state->delta_hashes)) {
		hash = STAILQ_FIRST(&state->delta_hashes);
		STAILQ_REMOVE_HEAD(&state->delta_hashes, hook);
		free(hash);
	}
}

/*
 * Updates @old with the new information carried by @new.
 * Consumes @new on success.
 */
static int
update_notif(struct rrdp_state *old, struct update_notification *new)
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
dl_notif(struct uri const *url, time_t mtim, bool *changed,
    struct update_notification *new)
{
	char tmppath[CACHE_TMPFILE_BUFLEN];
	int error;

	cache_tmpfile(tmppath);

	*changed = false;
	error = http_download(url, tmppath, mtim, changed);
	if (error)
		return error;
	if (!(*changed)) {
		pr_val_debug("The Notification has not changed.");
		return 0;
	}

	error = parse_notification(url, tmppath, new);
	if (error)
		return error;

	if (remove(tmppath) < 0) {
		pr_val_warn("Can't remove notification's temporal file: %s",
		   strerror(errno));
		update_notification_cleanup(new);
		/* Nonfatal; fall through */
	}

	return 0;
}

/*
 * Downloads the Update Notification @notif->url, and updates the cache
 * accordingly.
 *
 * "Updates the cache accordingly" means it downloads the missing deltas or
 * snapshot, and explodes them into @notif->path.
 */
int
rrdp_update(struct uri const *notif, char const *path, time_t mtim,
    bool *changed, struct rrdp_state **state)
{
	struct rrdp_state *old;
	struct update_notification new;
	int serial_cmp;
	int error;

	fnstack_push(uri_str(notif));
	pr_val_debug("Processing notification.");

	error = dl_notif(notif, mtim, changed, &new);
	if (error)
		goto end;
	if (!(*changed))
		goto end;

	pr_val_debug("New session/serial: %s/%s",
	    new.session.session_id,
	    new.session.serial.str);

	if ((*state) == NULL) {
		pr_val_debug("This is a new Notification.");

		old = pzalloc(sizeof(struct rrdp_state));
		/* session postponed! */
		cseq_init(&old->seq, pstrdup(path), 0, true);
		STAILQ_INIT(&old->delta_hashes);

		error = file_mkdir(path, false);
		if (error) {
			rrdp_state_free(old);
			goto clean_notif;
		}

		error = handle_snapshot(&new, old);
		if (error) {
			rrdp_state_free(old);
			goto clean_notif;
		}

		init_notif(old, &new);
		*state = old;
		goto end;
	}

	old = *state;
	serial_cmp = BN_cmp(old->session.serial.num, new.session.serial.num);
	if (serial_cmp < 0) {
		pr_val_debug("The Notification's serial changed.");

		error = validate_session_desync(old, &new);
		if (error)
			goto snapshot_fallback;
		error = handle_deltas(&new, old);
		if (error)
			goto snapshot_fallback;
		error = update_notif(old, &new);
		if (!error)
			goto end;
		/*
		 * The files are exploded and usable, but @old is not updatable.
		 * So drop and create it anew.
		 * We might lose some delta hashes, but it's better than
		 * re-snapshotting the next time the notification changes.
		 * Not sure if it matters. This looks so unlikely, it's
		 * practically dead code.
		 */
		goto reset_notif;

	} else if (serial_cmp > 0) {
		pr_val_debug("Cached serial is higher than notification serial.");
		goto end;

	} else {
		pr_val_debug("The Notification changed, but the session ID and serial didn't, and no session desync was detected.");
		*changed = false;
		goto end;
	}

snapshot_fallback:
	pr_val_debug("Falling back to snapshot.");
	error = handle_snapshot(&new, old);
	if (error)
		goto clean_notif;

reset_notif:
	drop_notif(old);
	init_notif(old, &new);
	goto end;

clean_notif:
	update_notification_cleanup(&new);

end:	fnstack_pop();
	return error;
}

char const *
rrdp_file(struct rrdp_state const *state, struct uri const *url)
{
	struct cache_file *file;
	file = state_find_file(state, url);
	return file ? file->map.path : NULL;
}

char const *
rrdp_create_fallback(char *cage, struct rrdp_state **_state,
    struct uri const *url)
{
	struct rrdp_state *state;
	struct cache_file *file;
	char const *str;
	size_t len;

	state = *_state;
	if (state == NULL) {
		*_state = state = pzalloc(sizeof(struct rrdp_state));
		cseq_init(&state->seq, cage, 0, false);
	}

	file = pzalloc(sizeof(struct cache_file));
	uri_copy(&file->map.url, url);
	file->map.path = cseq_next(&state->seq);
	if (!file->map.path) {
		uri_cleanup(&file->map.url);
		free(file);
		return NULL;
	}

	str = uri_str(&file->map.url);
	len = uri_len(&file->map.url);
	HASH_ADD_KEYPTR(hh, state->files, str, len, file);

	return file->map.path;
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

static json_t *
files2json(struct rrdp_state *state)
{
	json_t *json;
	struct cache_file *file, *tmp;

	json = json_obj_new();
	if (json == NULL)
		return NULL;

	HASH_ITER(hh, state->files, file, tmp)
		if (json_add_str(json, uri_str(&file->map.url), file->map.path))
			goto fail;

	return json;

fail:	json_decref(json);
	return NULL;
}

static json_t *
dh2json(struct rrdp_state *state)
{
	json_t *json;
	char hash_str[2 * RRDP_HASH_LEN + 1];
	struct rrdp_hash *hash;
	array_index i;

	json = json_array_new();
	if (json == NULL)
		return NULL;

	hash_str[2 * RRDP_HASH_LEN] = '\0';
	STAILQ_FOREACH(hash, &state->delta_hashes, hook) {
		for (i = 0; i < RRDP_HASH_LEN; i++) {
			hash_str[2 * i    ] = hash_b2c(hash->bytes[i] >> 4);
			hash_str[2 * i + 1] = hash_b2c(hash->bytes[i]     );
		}
		if (json_array_add(json, json_string(hash_str)))
			goto fail;
	}

	return json;

fail:	json_decref(json);
	return NULL;
}

json_t *
rrdp_state2json(struct rrdp_state *state)
{
	json_t *json;

	json = json_object();
	if (json == NULL)
		enomem_panic();

	if (state->session.session_id &&
	    json_add_str(json, TAGNAME_SESSION, state->session.session_id))
		goto fail;
	if (state->session.serial.str &&
	    json_add_str(json, TAGNAME_SERIAL, state->session.serial.str))
		goto fail;
	if (state->files)
		if (json_object_add(json, "files", files2json(state)))
			goto fail;
	if (!STAILQ_EMPTY(&state->delta_hashes))
		if (json_object_add(json, TAGNAME_DELTAS, dh2json(state)))
			goto fail;

	return json;

fail:	json_decref(json);
	return NULL;
}

static int
json2session(json_t *parent, char **session)
{
	char const *str;
	int error;

	error = json_get_str(parent, TAGNAME_SESSION, &str);
	*session = error ? NULL : pstrdup(str);
	return error;
}

static int
json2serial(json_t *parent, struct rrdp_serial *serial)
{
	char const *str;
	int error;

	error = json_get_str(parent, TAGNAME_SERIAL, &str);
	if (error < 0)
		return error;
	if (error > 0) {
		serial->num = NULL;
		serial->str = NULL;
		return error;
	}

	serial->num = BN_create();
	serial->str = pstrdup(str);
	if (!BN_dec2bn(&serial->num, serial->str)) {
		error = pr_op_err("Not a serial number: %s", serial->str);
		BN_free(serial->num);
		free(serial->str);
		return error;
	}

	return 0;
}

static int
json2files(json_t *jparent, char *parent, struct rrdp_state *state)
{
	json_t *jfiles;
	char const *jkey;
	json_t *jvalue;
	size_t parent_len;
	struct uri url;
	char const *path;
	unsigned long id, max_id;
	int error;

	error = json_get_object(jparent, "files", &jfiles);
	if (error < 0) {
		pr_op_debug("files: %s", strerror(error));
		return error;
	}
	if (error > 0)
		return 0;

	parent_len = strlen(parent);
	max_id = 0;

	json_object_foreach(jfiles, jkey, jvalue) {
		if (!json_is_string(jvalue)) {
			pr_op_warn("RRDP file URL '%s' is not a string.", jkey);
			continue;
		}
		error = uri_init(&url, jkey);
		if (error) {
			pr_op_warn("Cannot parse '%s' as a URI.", jkey);
			continue;
		}

		// XXX sanitize more?

		path = json_string_value(jvalue);
		if (strncmp(path, parent, parent_len) != 0 || path[parent_len] != '/') {
			pr_op_warn("RRDP path '%s' is not child of '%s'.",
			    path, parent);
			uri_cleanup(&url);
			continue;
		}

		error = hex2ulong(path + parent_len + 1, &id);
		if (error) {
			pr_op_warn("RRDP file '%s' is not a hexadecimal number.", path);
			uri_cleanup(&url);
			continue;
		}
		if (id > max_id)
			max_id = id;

		cache_file_add(state, &url, pstrdup(path));
		uri_cleanup(&url);
	}

	if (HASH_COUNT(state->files) == 0) {
		pr_op_warn("RRDP cage does not index any files.");
		return EINVAL;
	}

	cseq_init(&state->seq, parent, max_id + 1, false);
	return 0;
}

static int
json2dh(json_t *json, struct rrdp_hash **dh)
{
	char const *str;
	struct rrdp_hash *hash;

	str = json_string_value(json);
	if (str == NULL)
		return pr_op_err("Hash is not a string.");

	if (strlen(str) != 2 * RRDP_HASH_LEN)
		return pr_op_err("Hash is not %d characters long.",
		    2 * RRDP_HASH_LEN);

	hash = pmalloc(sizeof(struct rrdp_hash));
	if (str2hex(str, hash->bytes) != 0) {
		free(hash);
		return pr_op_err("Malformed hash: %s", str);
	}

	*dh = hash;
	return 0;
}

static void
clear_delta_hashes(struct rrdp_state *state)
{
	struct rrdp_hash *hash;

	while (!STAILQ_EMPTY(&state->delta_hashes)) {
		hash = STAILQ_FIRST(&state->delta_hashes);
		STAILQ_REMOVE_HEAD(&state->delta_hashes, hook);
		free(hash);
	}
}

static int
json2dhs(json_t *json, struct rrdp_state *state)
{
	json_t *jdeltas;
	size_t d, dn;
	struct rrdp_hash *hash;
	int error;

	STAILQ_INIT(&state->delta_hashes);

	error = json_get_array(json, TAGNAME_DELTAS, &jdeltas);
	if (error)
		return (error > 0) ? 0 : error;

	dn = json_array_size(jdeltas);
	if (dn == 0)
		return 0;
	if (dn > config_get_rrdp_delta_threshold())
		dn = config_get_rrdp_delta_threshold();

	for (d = 0; d < dn; d++) {
		error = json2dh(json_array_get(jdeltas, d), &hash);
		if (error) {
			clear_delta_hashes(state);
			return error;
		}
		STAILQ_INSERT_TAIL(&state->delta_hashes, hash, hook);
	}

	return 0;
}

/* @path is expected to outlive the state. */
int
rrdp_json2state(json_t *json, char *path, struct rrdp_state **result)
{
	struct rrdp_state *state;
	int error;

	state = pzalloc(sizeof(struct rrdp_state));

	error = json2session(json, &state->session.session_id);
	if (error < 0) {
		pr_op_debug("session: %s", strerror(error));
		goto fail;
	}
	error = json2serial(json, &state->session.serial);
	if (error < 0) {
		pr_op_debug("serial: %s", strerror(error));
		goto fail;
	}
	error = json2files(json, path, state);
	if (error) {
		pr_op_debug("files: %s", strerror(error));
		goto fail;
	}
	error = json2dhs(json, state);
	if (error) {
		pr_op_debug("delta hashes: %s", strerror(error));
		goto fail;
	}

	*result = state;
	return 0;

fail:	rrdp_state_free(state);
	return error;
}

void
rrdp_state_free(struct rrdp_state *state)
{
	struct cache_file *file, *tmp;

	if (state == NULL)
		return;

	session_cleanup(&state->session);
	HASH_ITER(hh, state->files, file, tmp) {
		HASH_DEL(state->files, file);
		map_cleanup(&file->map);
		free(file);
	}
	cseq_cleanup(&state->seq);
	clear_delta_hashes(state);
	free(state);
}

void
rrdp_print(struct rrdp_state *rs)
{
	struct cache_file *file, *tmp;
	struct rrdp_hash *hash;
	unsigned int i;

	if (rs == NULL)
		return;

	/* printf("session:%s/%s\n", rs->session.session_id, rs->session.serial.str); */
	printf("\n");
	HASH_ITER(hh, rs->files, file, tmp)
		printf("\t\tfile: %s (%s)\n", file->map.path, uri_str(&file->map.url));
	printf("\t\tseq:  %s/%lx\n", rs->seq.prefix, rs->seq.next_id);

	STAILQ_FOREACH(hash, &rs->delta_hashes, hook) {
		printf("\t\thash: ");
		for (i = 0; i < RRDP_HASH_LEN; i++)
			printf("%c%c",
			    hash_b2c(hash->bytes[i] >> 4),
			    hash_b2c(hash->bytes[i]));
		printf("\n");
	}
}
