#include "rrdp.h"

#include <libxml/globals.h>
#include <libxml/xmlreader.h>
#include <openssl/err.h>
#include <sys/queue.h>

#include "base64.h"
#include "cachefile.h"
#include "cachetmp.h"
#include "common.h"
#include "config.h"
#include "file.h"
#include "hash.h"
#include "http.h"
#include "json_util.h"
#include "log.h"
#include "relax_ng.h"
#include "rtr/db/delta.h"
#include "thread_var.h"
#include "types/str.h"
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

struct rrdp_id {
	char *session_id;
	struct rrdp_serial serial;
};

struct rrdp_step {
	struct rrdp_serial serial;
	struct files_ht files;
	struct rrdp_hash delta_hash;
	TAILQ_ENTRY(rrdp_step) lh;	/* List hook */
};

TAILQ_HEAD(rrdp_steps, rrdp_step);

struct rrdp_session {
	char *id;			/* Known in files as "session_id" */

	/*
	 * The 1st one is the session.serial snap.
	 * The 2nd one is the session.serial - 1 snap.
	 * The 3rd one is the session.serial - 2 snap.
	 * And so on.
	 */
	struct rrdp_steps steps;

	bool fresh;			/* Refreshed during this cycle? */

	struct fallback_ht fbs;		/* Hash table, indexed by caRepo */

	TAILQ_ENTRY(rrdp_session) lh;
};

TAILQ_HEAD(rrdp_sessions, rrdp_session);

/* Subset of the notification that is relevant to the TAL's cachefile */
struct rrdp_ctx {
	struct rrdp_sessions sessions;
	struct cache_sequence seq;	/* For file names */
};

enum rrdp_dao_state {
	RDS_STEP,
	RDS_FB,
	RDS_DONE,
};

struct rrdp_dao {
	struct uri caRepository;
	struct rrdp_ctx *ctx;
	enum rrdp_dao_state state;

	struct {
		struct rrdp_session *session;
		struct rrdp_step *obj;
	} step;

	struct {
		struct rrdp_session *session;
		struct fallback *obj;
	} fb;
};

struct file_metadata {
	struct uri uri;
	struct rrdp_hash hash;
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
	struct rrdp_id session;
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
	struct rrdp_id *sid;
	struct rrdp_step *step;
	struct cache_sequence *seq;
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
serial_copy(struct rrdp_serial *to, struct rrdp_serial *from)
{
	to->num = BN_new();
	BN_copy(to->num, from->num);
	to->str = pstrdup(from->str);
}

static bool
serial_equals(struct rrdp_serial *a, struct rrdp_serial *b)
{
	if (a == b)
		return true;
	if (a == NULL || b == NULL)
		return false;
	return BN_cmp(a->num, b->num) == 0;
}

static int
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

static void
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

static struct rrdp_step *
step_create(struct rrdp_serial *serial)
{
	struct rrdp_step *step;

	step = pmalloc(sizeof(struct rrdp_step));
	serial_copy(&step->serial, serial);
	step->files.ht = NULL;
	step->delta_hash.set = false;

	return step;
}

static void
step_free(struct rrdp_step *step, bool rm_files)
{
	filerefs_clear(&step->files, rm_files);
	serial_cleanup(&step->serial);
	free(step);
}

static void
session_reset(struct rrdp_session *session, bool rm_files)
{
	struct rrdp_step *step;

	while ((step = TAILQ_FIRST(&session->steps)) != NULL) {
		TAILQ_REMOVE(&session->steps, step, lh);
		step_free(step, rm_files);
	}
}

static void
session_cleanup(struct rrdp_session *session)
{
	session_reset(session, true);
	free(session->id);
	free(session);
}

static void
session_free(struct rrdp_session *session)
{
	session_reset(session, false);
	fallbacks_clear(&session->fbs, false);
	free(session->id);
	free(session);
}

static struct rrdp_ctx *
ctx_create(char const *cage)
{
	struct rrdp_ctx *ctx;

	ctx = pzalloc(sizeof(struct rrdp_ctx));
	TAILQ_INIT(&ctx->sessions);
	cseq_init(&ctx->seq, pstrdup(cage), 0, true);

	return ctx;
}

static void
init_steps(struct rrdp_session *session, struct update_notification *notif)
{
	struct notification_delta *delta;
	struct rrdp_step *step;
	unsigned int d;

	TAILQ_INIT(&session->steps);

	d = 0;
	ARRAYLIST_FOREACH(&notif->deltas, delta) {
		if (d++ > config_get_rrdp_delta_threshold())
			break;

		step = pmalloc(sizeof(struct rrdp_step));
		serial_copy(&step->serial, &delta->serial);
		step->files.ht = NULL;
		step->delta_hash = delta->meta.hash;
		TAILQ_INSERT_TAIL(&session->steps, step, lh);
	}
}

static struct rrdp_session *
ctx_add_session(struct rrdp_ctx *ctx, char const *id)
{
	struct rrdp_session *session;

	session = pzalloc(sizeof(struct rrdp_session));
	session->id = pstrdup(id);
	TAILQ_INIT(&session->steps);
	panic_on_fail(pthread_mutex_init(&session->fbs.lock, NULL),
	    "pthread_mutex_init");

	TAILQ_INSERT_HEAD(&ctx->sessions, session, lh);
	return session;
}

void
rrdpctx_free(struct rrdp_ctx *ctx)
{
	struct rrdp_session *session;

	if (ctx == NULL)
		return;

	while ((session = TAILQ_FIRST(&ctx->sessions)) != NULL) {
		TAILQ_REMOVE(&ctx->sessions, session, lh);
		session_free(session);
	}
	cseq_cleanup(&ctx->seq);
	free(ctx);
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
update_notification_init(struct update_notification *notif,
    struct uri const *url)
{
	memset(&notif->session, 0, sizeof(notif->session));
	memset(&notif->snapshot, 0, sizeof(notif->snapshot));
	notification_deltas_init(&notif->deltas);
	notif->url = url;
}

static void
notification_cleanup(struct update_notification *notif)
{
	rrdpid_cleanup(&notif->session);
	metadata_cleanup(&notif->snapshot);
	notification_deltas_cleanup(&notif->deltas, notification_delta_cleanup);
}

static int
validate_hash(struct file_metadata *meta, char const *path)
{
	return hash_validate_file(hash_get_sha256(), path,
	    meta->hash.bytes, RRDP_HASH_LEN);
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

static int
parse_ulong(xmlTextReaderPtr reader, char const *attr, unsigned long *result)
{
	xmlChar *str;
	int error;

	str = xmlTextReaderGetAttribute(reader, BAD_CAST attr);
	if (str == NULL)
		return pr_err("Couldn't find xml attribute '%s'", attr);

	errno = 0;
	*result = strtoul((char const *) str, NULL, 10);
	error = errno;
	xmlFree(str);
	if (error) {
		pr_err("Invalid long value '%s': %s", str, strerror(error));
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
			pr_err("Tag '%s' seems to be empty.",
			    xmlTextReaderConstLocalName(reader));
	} else {
		result = xmlTextReaderGetAttribute(reader, BAD_CAST attr);
		if (result == NULL)
			pr_err("Tag '%s' is missing attribute '%s'.",
			    xmlTextReaderConstLocalName(reader), attr);
	}

	return result;
}

static int
parse_hash(xmlTextReaderPtr reader, struct rrdp_hash *hash)
{
	xmlChar *xmlattr;
	int error;

	xmlattr = xmlTextReaderGetAttribute(reader, BAD_CAST RRDP_ATTR_HASH);
	if (xmlattr == NULL)
		return 0;

	error = str2hash((char const *) xmlattr, hash);

	xmlFree(xmlattr);
	if (error)
		return pr_err("The '" RRDP_ATTR_HASH "' xml attribute does not appear to be a SHA-256 hash.");
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
		return pr_err("Invalid version, must be '%lu' and is '%lu'.",
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
		pr_err("Serial '%s' is negative.", serial->str);
		goto fail;
	}

	return 0;

fail:
	serial_cleanup(serial);
	return EINVAL;
}

static int
parse_sid(xmlTextReaderPtr reader, struct rrdp_id *meta)
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
		return pr_err("Namespace isn't '%s', current value is '%s'",
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
validate_session(xmlTextReaderPtr reader, char const *what,
    struct parser_args *args)
{
	struct rrdp_id actual = { 0 };
	int error;

	error = parse_sid(reader, &actual);
	if (error)
		return error;

	if (strcmp(args->sid->session_id, actual.session_id) != 0) {
		error = pr_err("%s session id [%s] doesn't match Notification session id [%s]",
		    what, args->sid->session_id, actual.session_id);
		goto end;
	}

	if (BN_cmp(actual.serial.num, args->sid->serial.num) != 0) {
		error = pr_err("%s serial [%s] doesn't match Notification serial [%s]",
		    what, actual.serial.str, args->sid->serial.str);
		goto end;
	}

end:	rrdpid_cleanup(&actual);
	return error;
}

/*
 * Extracts the following two attributes from @reader's current tag:
 *
 * 1. "uri"
 * 2. "hash" (optional)
 */
static int
parse_file_metadata(xmlTextReaderPtr reader, struct file_metadata *meta)
{
	xmlChar *xmlattr;
	error_msg errmsg;
	int error;

	memset(meta, 0, sizeof(*meta));

	xmlattr = parse_string(reader, RRDP_ATTR_URI);
	if (xmlattr == NULL)
		return EINVAL;
	errmsg = uri_init(&meta->uri, (char const *)xmlattr);
	xmlFree(xmlattr);
	if (errmsg)
		return pr_err("Cannot parse '%s' as a URI: %s",
		    xmlattr, errmsg);

	error = parse_hash(reader, &meta->hash);
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

/* Steals @path. */
static int
register_fileref(struct rrdp_step *step, struct publish *tag, char *path,
    char const *id)
{
	struct cache_file *file;
	unsigned char hash[EVP_MAX_MD_SIZE];
	int error;

	error = hash_buffer(hash_get_sha256(),
	    tag->content, tag->content_len,
	    hash, SHA256_DIGEST_LENGTH);
	if (error) {
		free(path);
		return error;
	}

	file = cachefile_create(&tag->meta.uri, path, id, hash);
	filerefs_add_uri(&step->files, file, 0);
	return 0;
}

static int
handle_publish(xmlTextReaderPtr reader, struct parser_args *args)
{
	struct publish tag = { 0 };
	xmlChar *base64_str;
	struct cache_file_ref *fileref;
	char *path;
	char const *pathid;
	int error;

	/* Parse tag itself */
	error = parse_file_metadata(reader, &tag.meta);
	if (error)
		return error;
	if (xmlTextReaderRead(reader) != 1) {
		error = pr_err(
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
		error = EINVAL;
		goto end;
	}
	if (!base64_decode((char *)base64_str, 0, &tag.content, &tag.content_len)) {
		xmlFree(base64_str);
		error = pr_err("Cannot decode publish tag's base64.");
		goto end;
	}
	xmlFree(base64_str);

	/* Parsing done */

	pr_clutter("Publish %s", uri_str(&tag.meta.uri));

	fileref = filerefs_find_uri(&args->step->files, &tag.meta.uri);

	/* rfc8181#section-2.2 */
	if (fileref) {
		if (!tag.meta.hash.set) {
			// XXX watch out for this in the log before release
			error = pr_err("RRDP desync: "
			    "<publish> is attempting to create '%s', "
			    "but the file is already cached.",
			    uri_str(&tag.meta.uri));
			goto end;
		}

		error = validate_hash2(&tag.meta, fileref->file->hash);
		if (error)
			goto end;

		HASH_DEL(args->step->files.ht, fileref);
		fileref_free(fileref, true);

	} else {
		if (tag.meta.hash.set) {
			// XXX watch out for this in the log before release
			error = pr_err("RRDP desync: "
			    "<publish> is attempting to overwrite '%s', "
			    "but the file is absent in the cache.",
			    uri_str(&tag.meta.uri));
			goto end;
		}
	}

	path = cseq_next(args->seq, &pathid);
	if (!path) {
		error = EINVAL;
		goto end;
	}

	pr_clutter("echo '$%s' > %s", uri_str(&tag.meta.uri), path);
	error = file_write_bin(path, tag.content, tag.content_len);
	if (error)
		free(path);
	else
		error = register_fileref(args->step, &tag, path, pathid);

end:	metadata_cleanup(&tag.meta);
	free(tag.content);
	return error;
}

static int
handle_withdraw(xmlTextReaderPtr reader, struct parser_args *args)
{
	struct withdraw tag = { 0 };
	struct cache_file_ref *fileref;
	int error;

	error = parse_file_metadata(reader, &tag.meta);
	if (error)
		return error;
	if (!is_known_extension(&tag.meta.uri))
		goto end; /* Mirror rsync filters */
	if (!tag.meta.hash.set) {
		error = pr_err("Withdraw '%s' is missing a hash.",
		    uri_str(&tag.meta.uri));
		goto end;
	}

	pr_clutter("Withdraw %s", uri_str(&tag.meta.uri));

	fileref = filerefs_find_uri(&args->step->files, &tag.meta.uri);

	if (!fileref) {
		error = pr_err("Broken RRDP: "
		    "<withdraw> is attempting to delete unknown file '%s'.",
		    uri_str(&tag.meta.uri));
		goto end;
	}

	error = validate_hash2(&tag.meta, fileref->file->hash);
	if (error)
		goto end;

	HASH_DEL(args->step->files.ht, fileref);
	fileref_free(fileref, true);

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

	if (!notif->snapshot.hash.set)
		return pr_err("Snapshot '%s' is missing a hash.",
		    uri_str(&notif->snapshot.uri));

	if (!uri_same_origin(notif->url, &notif->snapshot.uri))
		return pr_err("Notification '%s' and Snapshot '%s' are not hosted by the same origin.",
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

	if (!delta.meta.hash.set) {
		error = pr_err("Delta '%s' is missing a hash.",
		    uri_str(&delta.meta.uri));
		goto mta;
	}

	if (!uri_same_origin(notif->url, &delta.meta.uri)) {
		error = pr_err("Notification %s and Delta %s are not hosted by the same origin.",
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
swap_until_sorted(struct notification_deltas *deltas, array_index i,
    BIGNUM *min, struct rrdp_serial *max, BIGNUM *diff)
{
	struct notification_delta *array;
	BN_ULONG j;
	struct notification_delta tmp;

	array = deltas->array;

	while (true) {
		if (BN_cmp(array[i].serial.num, min) < 0) {
			char *str = BN_bn2dec(min);
			pr_err(
			    "Deltas: Serial '%s' is out of bounds. (min:%s)",
			    array[i].serial.str, str);
			OPENSSL_free(str);
			return EINVAL;
		}
		if (BN_cmp(max->num, array[i].serial.num) < 0)
			return pr_err(
			    "Deltas: Serial '%s' is out of bounds. (max:%s)",
			    array[i].serial.str, max->str);

		if (!BN_sub(diff, array[i].serial.num, min))
			return pr_crypto_err("BN_sub() returned error.");
		j = deltas->len - BN_get_word(diff) - 1;
		if (i == j)
			return 0;
		if (BN_cmp(array[j].serial.num, array[i].serial.num) == 0) {
			return pr_err("Deltas: Serial '%s' is not unique.",
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
		return pr_crypto_err("BN_dup() returned NULL.");
	if (!BN_sub_word(min_serial, deltas->len - 1)) {
		error = pr_err("Could not subtract %s - %zu; unknown cause.",
		    notif->session.serial.str, deltas->len - 1);
		goto end;
	}
	if (BN_is_negative(min_serial)) {
		error = pr_err("Too many deltas (%zu) for serial %s. (Negative serials not implemented.)",
		    deltas->len, max_serial->str);
		goto end;
	}

	aux = BN_create();

	error = 0;
	ARRAYLIST_FOREACH_IDX(deltas, i) {
		error = swap_until_sorted(deltas, i, min_serial, max_serial, aux);
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
			return parse_sid(reader, &notif->session);
		}

		return pr_err("Unexpected '%s' element", name);

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
		notification_cleanup(result);

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
			error = validate_session(reader, "Snapshot", arg);
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
parse_snapshot(struct rrdp_id *sid,
    char const *path,
    struct rrdp_session *session,
    struct cache_sequence *seq)
{
	struct parser_args args;
	int error;

	pr_trc("Exploding snapshot into %s...", seq->pfx.str);

	args.sid = sid;
	args.step = TAILQ_FIRST(&session->steps);
	args.seq = seq;

	if (!args.step) {
		args.step = step_create(&sid->serial);
		TAILQ_INSERT_HEAD(&session->steps, args.step, lh);

	} else if (!serial_equals(&sid->serial, &args.step->serial)) {
		return pr_err("Notification serial (%s) does not match most recent delta serial (%s)",
		    sid->serial.str, args.step->serial.str);
	}

	error = relax_ng_parse(path, xml_read_snapshot, &args);
	if (error)
		return error;

	pr_trc("Snapshot exploded.");
	session->fresh = true;
	return 0;
}

static int
_serial_diff(struct rrdp_serial *large, struct rrdp_serial *small, int *result)
{
	BIGNUM *diff;
	BIGNUM *max;
	int error2;
	unsigned long error;
	char errmsg[120];

	error2 = EINVAL;

	diff = BN_create();
	if (!BN_sub(diff, large->num, small->num)) {
		pr_err("%s - %s -> BIGNUM Error:", large->str, small->str);
		while ((error = ERR_get_error()) != 0)
			pr_err("  %s", ERR_error_string(error, errmsg));
		goto diff;
	}

	/* TODO (fine) maybe cache max in the config module */
	max = BN_create();
	if (!BN_set_word(max, config_get_rrdp_delta_threshold())) {
		pr_err("BIGNUM assignment (%u) Error:",
		    config_get_rrdp_delta_threshold());
		while ((error = ERR_get_error()) != 0)
			pr_err("  %s", ERR_error_string(error, errmsg));
		goto max;
	}

	/* XXX the threshold needs to be limited to a fairly small number */
	if (BN_cmp(max, diff) < 0) {
		pr_err("Too many deltas; falling back to Snapshot.");
		goto max;
	}

	*result = BN_get_word(diff);
	error2 = 0;

max:	BN_free(max);
diff:	BN_free(diff);
	return error2;
}

static int
get_serial_diff(struct rrdp_serial *cached, struct update_notification *notif,
    int *result)
{
	int cmp;
	int diff;
	int error;

	cmp = BN_cmp(cached->num, notif->session.serial.num);
	if (cmp < 0) {
		/* Normal situation: The notification has new deltas */
		error = _serial_diff(&notif->session.serial, cached, &diff);
		if (!error)
			*result = diff;

	} else if (cmp > 0) {
		/* The notification is older than what we already have */
		error = _serial_diff(cached, &notif->session.serial, &diff);
		if (!error)
			*result = -diff;

	} else {
		/* The notification and cache have the same serial */
		*result = 0;
		error = 0;
	}

	return error;
}

static struct notification_delta *
find_delta(struct update_notification *notif, int serial_diff, int d)
{
	int index;
	index = d + serial_diff;
	return (index < 0 || notif->deltas.len <= index)
	    ? NULL
	    : &notif->deltas.array[index];
}

static int
validate_session_desync(struct rrdp_step *step,
    struct update_notification *notif,
    int serial_diff)
{
	struct notification_delta *delta;
	int i;
	size_t delta_threshold;

	delta_threshold = config_get_rrdp_delta_threshold();

	for (i = 0; i < delta_threshold; i++) {
		if (step == NULL)
			return 0; /* Cache has few deltas */
		/* First step always lacks a hash; there's no delta */
		if (!step->delta_hash.set)
			continue;

		delta = find_delta(notif, serial_diff, i);
		if (!delta)
			continue;
		if (!delta->meta.hash.set)
			continue; /* Probably dead code */

		if (memcmp(step->delta_hash.bytes, delta->meta.hash.bytes, RRDP_HASH_LEN) != 0)
			return pr_err("Notification delta hash for serial %s does not match cached delta hash; "
			    "RRDP session desynchronization detected.",
			    delta->serial.str);

		step = TAILQ_NEXT(step, lh);
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
handle_snapshot(struct update_notification *new,
    struct rrdp_session *session,
    struct cache_sequence *seq)
{
	char tmppath[CACHE_TMPFILE_BUFLEN];
	struct uri *url;
	int error;

	url = &new->snapshot.uri;
	fnstack_push(uri_str(url));

	error = dl_tmp(url, tmppath);
	if (error)
		goto end;
	error = validate_hash(&new->snapshot, tmppath);
	if (error)
		goto end;
	error = parse_snapshot(&new->session, tmppath, session, seq);
	file_rm_f(tmppath);

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
			error = validate_session(reader, "Delta", arg);
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
parse_delta(struct update_notification *notif,
    struct notification_delta *delta,
    char const *path,
    struct rrdp_session *session,
    struct cache_sequence *seq)
{
	struct parser_args args;
	struct rrdp_id sid;
	int error;

	error = validate_hash(&delta->meta, path);
	if (error)
		return error;

	pr_trc("Exploding delta into %s...", seq->pfx.str);

	sid.session_id = notif->session.session_id;
	sid.serial = delta->serial;
	args.sid = &sid;

	args.step = step_create(&delta->serial);
	args.step->files = filerefs_clone(&TAILQ_FIRST(&session->steps)->files);
	args.step->delta_hash = delta->meta.hash;
	TAILQ_INSERT_HEAD(&session->steps, args.step, lh);

	args.seq = seq;

	error = relax_ng_parse(path, xml_read_delta, &args);
	if (error)
		return error;

	pr_trc("Delta exploded.");
	session->fresh = true;
	return error;
}

static int
handle_delta(struct update_notification *notif,
    struct notification_delta *delta,
    struct rrdp_session *session,
    struct cache_sequence *cseq)
{
	char tmppath[CACHE_TMPFILE_BUFLEN];
	struct uri const *url;
	int error;

	url = &delta->meta.uri;

	pr_trc("Processing delta '%s'.", uri_str(url));
	fnstack_push(uri_str(url));

	error = dl_tmp(url, tmppath);
	if (error)
		goto end;
	error = parse_delta(notif, delta, tmppath, session, cseq);
	file_rm_f(tmppath);

end:	fnstack_pop();
	return error;
}

static int
handle_deltas(struct update_notification *notif, struct rrdp_session *session,
    int serial_diff, struct cache_sequence *cseq)
{
	struct rrdp_serial *old;
	struct rrdp_serial *new;
	int d;
	int error;

	if (notif->deltas.len == 0) {
		pr_wrn("There's no delta list to process.");
		return ENOENT;
	}

	old = &TAILQ_FIRST(&session->steps)->serial;
	new = &notif->session.serial;

	pr_trc("Handling RRDP delta serials %s-%s.", old->str, new->str);

	if (serial_diff > config_get_rrdp_delta_threshold())
		return pr_err("Cached RPP is too old. (Cached serial: %s; current serial: %s)",
		    old->str, new->str);
	if (serial_diff > notif->deltas.len)
		return pr_err("We need %d deltas, but the notification only has %zu.",
		    serial_diff, notif->deltas.len);

	for (d = serial_diff - 1; d >= 0; d--) {
		error = handle_delta(notif, &notif->deltas.array[d], session, cseq);
		if (error)
			return error;
	}

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
		pr_trc("The Notification has not changed.");
		return 0;
	}

	error = parse_notification(url, tmppath, new);
	if (error)
		return error;

	if (remove(tmppath) < 0) {
		pr_wrn("Cannot remove %s: %s", tmppath, strerror(errno));
		/* Nonfatal; fall through */
	}

	return 0;
}

static struct rrdp_session *
find_session(struct rrdp_ctx *ctx, char const *session_id)
{
	struct rrdp_session *session;

	TAILQ_FOREACH(session, &ctx->sessions, lh) {
		if (strcmp(session->id, session_id) == 0)
			return session;
	}

	return NULL;
}

/*
 * Downloads the Update Notification @notif_uri, and updates the cache
 * accordingly.
 *
 * "Updates the cache accordingly" means it downloads the missing deltas or
 * snapshot, and explodes them into @cage.
 */
int
rrdp_update(struct uri const *notif_uri, char const *cage, time_t mtim,
    bool *changed, struct rrdp_ctx **result)
{
	struct update_notification notif;
	struct rrdp_ctx *ctx;
	struct rrdp_session *session;
	struct rrdp_step *step;
	int serial_diff;
	int error;

	fnstack_push(uri_str(notif_uri));

	error = dl_notif(notif_uri, mtim, changed, &notif);
	if (error)
		goto pop;
	if (!(*changed))
		goto pop;

	pr_trc("New session/serial: %s/%s",
	    notif.session.session_id,
	    notif.session.serial.str);

	if ((*result) == NULL) {
		pr_trc("This is a new Notification.");

		error = file_mkdir(cage, false);
		if (error)
			goto notif;
		ctx = ctx_create(cage);
		session = ctx_add_session(ctx, notif.session.session_id);
		init_steps(session, &notif);

		error = handle_snapshot(&notif, session, &ctx->seq);
		if (error)
			rrdpctx_free(ctx);
		else
			*result = ctx;
		goto notif;
	}

	ctx = *result;

	session = find_session(ctx, notif.session.session_id);
	if (!session) {
		pr_trc("This is a new session.");
		session = ctx_add_session(ctx, notif.session.session_id);
		init_steps(session, &notif);
		error = handle_snapshot(&notif, session, &ctx->seq);
		goto notif;
	}

	step = TAILQ_FIRST(&session->steps);

	error = get_serial_diff(&step->serial, &notif, &serial_diff);
	if (error)
		goto snapshot;
	error = validate_session_desync(step, &notif, serial_diff);
	if (error)
		goto snapshot;

	if (serial_diff > 0) {
		pr_trc("The Notification's serial changed: %s -> %s",
		    step->serial.str, notif.session.serial.str);

		error = handle_deltas(&notif, session, serial_diff, &ctx->seq);
		if (error) {
snapshot:		pr_trc("Falling back to snapshot.");
			session_reset(session, true);
			init_steps(session, &notif);
			error = handle_snapshot(&notif, session, &ctx->seq);
		}

	} else if (serial_diff < 0) {
		pr_trc("Cached serial is higher than notification serial.");

	} else {
		pr_trc("The Notification changed, but the session ID and serial didn't, and no session desync was detected.");
		*changed = false;
	}

notif:	notification_cleanup(&notif);
pop:	fnstack_pop();
	return error;
}

static void
init_step(struct rrdp_dao *dao)
{
	struct rrdp_session *ss;
	struct rrdp_step *step;

	TAILQ_FOREACH(ss, &dao->ctx->sessions, lh)
		TAILQ_FOREACH(step, &ss->steps, lh)
			/* TODO (fine) when is the hash table empty? */
			/* See twice below at rrdpdao_downgrade_delta(). */
			if (step->files.ht != NULL) {
				dao->step.session = ss;
				dao->step.obj = step;
				return;
			}
}

static void
init_fallback(struct rrdp_dao *dao)
{
	struct rrdp_session *ss;
	struct fallback *fb;

	TAILQ_FOREACH(ss, &dao->ctx->sessions, lh) {
		fb = fallback_find(&ss->fbs, &dao->caRepository);
		if (!dao->fb.obj ||
		    INTEGER_cmp(&dao->fb.obj->mft.num, &fb->mft.num) < 0) {
			dao->fb.session = ss;
			dao->fb.obj = fb;
		}
	}
}

struct rrdp_dao *
rrdpdao_create(struct rrdp_ctx *ctx, struct uri const *caRepository)
{
	struct rrdp_dao *result;

	result = pzalloc(sizeof(struct rrdp_dao));
	uri_copy(&result->caRepository, caRepository);
	result->ctx = ctx;
	result->state = RDS_STEP;
	init_step(result);
	init_fallback(result);

	return result;
}

/* This function assumes querier's sessions are sorted by date, fresh first */
bool
rrdpdao_downgrade_delta(struct rrdp_dao *dao)
{
	struct rrdp_session *ss;
	struct rrdp_step *step;

	if (!dao)
		return false;

	ss = dao->step.session;
	step = dao->step.obj;
	if (!step)
		goto no;

	step = TAILQ_NEXT(step, lh);
	if (step && step->files.ht != NULL)
		goto yes;

	pr_trc("There are no more RRDP steps.");

	while ((ss = TAILQ_NEXT(ss, lh)) != NULL) {
		step = TAILQ_FIRST(&ss->steps);
		if (step && step->files.ht != NULL)
			goto yes;
	}

no:	pr_trc("There are no more RRDP sessions/steps.");
	return false;

yes:	dao->state = RDS_STEP;
	dao->step.session = ss;
	dao->step.obj = step;
	return true;
}

bool
rrdpdao_downgrade_fb(struct rrdp_dao *dao)
{
	if (!dao)
		return false;

	if (dao->state == RDS_STEP && dao->fb.obj != NULL) {
		dao->state = RDS_FB;
		return true;
	}

	return false;
}

struct cache_file *
rrdpdao_map(struct rrdp_dao const *querier, struct uri const *url)
{
	struct files_ht *ht = NULL;
	struct cache_file_ref *ref;

	switch (querier->state) {
	case RDS_STEP:
		if (!querier->step.obj)
			return NULL;
		ht = &querier->step.obj->files;
		break;
	case RDS_FB:
		if (!querier->fb.obj)
			return NULL;
		ht = &querier->fb.obj->files;
		break;
	case RDS_DONE:
		return NULL;
	}

	ref = filerefs_find_uri(ht, url);
	return ref ? ref->file : NULL;
}

struct mft_meta const *
rrdpdao_fallback_mftnum(struct rrdp_dao *dao)
{
	return (dao && dao->fb.obj) ? &dao->fb.obj->mft : NULL;
}

void
rrdpdao_commit(struct rrdp_dao *dao, struct rpp *rpp)
{
	pr_trc("Queuing RPP for commit: %s", uri_str(&dao->caRepository));

	switch (dao->state) {
	case RDS_STEP:
		fallback_add(&dao->step.session->fbs, &dao->caRepository, rpp);
		break;
	case RDS_FB:
		pr_trc("It's already a fallback.");
		fallback_commit(&dao->fb.session->fbs, dao->fb.obj);
		break;
	case RDS_DONE:
		break;
	}
}

void
rrdpdao_free(struct rrdp_dao *dao)
{
	if (dao) {
		uri_cleanup(&dao->caRepository);
		free(dao);
	}
}

static struct fallback *
find_best_commit(struct fallback *first)
{
	struct fallback *fb, *committed;
	INTEGER_t *max;

	committed = NULL;
	max = NULL;
	for (fb = first; fb; fb = fb->next)
		if (fb->committed && INTEGER_cmp(max, &fb->mft.num) < 0) {
			committed = fb;
			max = &fb->mft.num;
		}

	return committed;
}

static void
cleanup_sessions(struct rrdp_ctx *ctx)
{
	struct rrdp_session *session, *tmps;
	struct rrdp_step *step, *next;
	unsigned int s, threshold;

	threshold = config_get_rrdp_delta_threshold() - 1;

	for (session = TAILQ_FIRST(&ctx->sessions); session; session = tmps) {
		tmps = TAILQ_NEXT(session, lh);

		// XXX (!fresh || steps empty) ?
		if (!session->fresh && HASH_COUNT(session->fbs.ht) == 0) {
			TAILQ_REMOVE(&ctx->sessions, session, lh);
			session_cleanup(session);
			continue;
		}

		s = 0;
		TAILQ_FOREACH(step, &session->steps, lh) {
			if (s != 0) {
				filerefs_clear(&step->files, true);
				step->files.ht = NULL;
			}
			if (s == threshold) {
				while ((next = TAILQ_NEXT(step, lh)) != NULL) {
					TAILQ_REMOVE(&session->steps, next, lh);
					step_free(next, true);
				}
			}
			s++;
		}
	}
}

/* Returns whether there's something to salvage. */
bool
rrdpctx_cleanup(struct rrdp_ctx *ctx)
{
	struct rrdp_session *session;

	if (!ctx)
		return false;

	pr_trc("Deleting noncommitted fallbacks.");
	TAILQ_FOREACH(session, &ctx->sessions, lh)
		fallbacks_cleanup(&session->fbs);

	pr_trc("Cleaning up sessions.");
	cleanup_sessions(ctx);

	return !TAILQ_EMPTY(&ctx->sessions);
}

static int
files2json(json_t *json, struct rrdp_ctx const *ctx)
{
	struct rrdp_session *session;
	struct rrdp_step *step;
	struct fallback *fb, *fb2;
	struct cache_file_ref *file, *file2;
	int error;

	TAILQ_FOREACH(session, &ctx->sessions, lh) {
		TAILQ_FOREACH(step, &session->steps, lh)
			filerefs_clear_written(&step->files);
		HASH_ITER(hh, session->fbs.ht, fb, fb2)
			filerefs_clear_written(&fb->files);
	}

	TAILQ_FOREACH(session, &ctx->sessions, lh) {
		TAILQ_FOREACH(step, &session->steps, lh) {
			error = filerefs_write(json, &step->files);
			if (error)
				return error;
		}
		HASH_ITER(hh, session->fbs.ht, fb, fb2) {
			error = filerefs_write(json, &fb->files);
			if (error)
				return error;
		}
	}

	return 0;
}

static json_t *
step2json(struct rrdp_step *step, bool write_files)
{
	json_t *jstep;

	if (!step->delta_hash.set && !write_files)
		return NULL;

	jstep = json_obj_new();

	if (step->delta_hash.set)
		if (json_add_hash(jstep, "hash", step->delta_hash.bytes))
			goto fail;
	if (write_files)
		if (json_object_add(jstep, "files", filerefs2json(&step->files, FHKT_ID)))
			goto fail;

	return jstep;

fail:	json_decref(jstep);
	return NULL;
}

static json_t *
session2json(struct rrdp_session *session)
{
	json_t *jsession, *jsteps, *jfbs, *jstep;
	struct rrdp_step *step;
	struct fallback *fb, *tmp;
	array_index s;

	jsession = json_obj_new();

	jsteps = json_obj_new();
	if (json_object_add(jsession, "steps", jsteps))
		goto fail;
	s = 0;
	TAILQ_FOREACH(step, &session->steps, lh) {
		jstep = step2json(step, s == 0);
		if (jstep && json_object_add(jsteps, step->serial.str, jstep))
			goto fail;
		s++;
		if (s >= config_get_rrdp_delta_threshold())
			break;
	}

	jfbs = json_obj_new();
	if (json_object_add(jsession, "fallbacks", jfbs))
		goto fail;
	HASH_ITER(hh, session->fbs.ht, fb, tmp)
		if (json_object_add(jfbs,
		    uri_str(&fb->caRepository),
		    fallback2json(fb, FHKT_ID)))
			goto fail;

	return jsession;

fail:	json_decref(jsession);
	return NULL;
}

json_t *
rrdp_ctx2json(struct rrdp_ctx const *ctx)
{
	json_t *root, *jfiles, *jsessions;
	struct rrdp_session *session;

	root = json_obj_new();

	jfiles = json_obj_new();
	if (json_object_add(root, "files", jfiles))
		goto fail;
	if (files2json(jfiles, ctx))
		goto fail;

	jsessions = json_obj_new();
	if (json_object_add(root, "sessions", jsessions))
		goto fail;
	TAILQ_FOREACH(session, &ctx->sessions, lh)
		if (json_object_add(jsessions, session->id, session2json(session)))
			goto fail;

	return root;

fail:	json_decref(root);
	return NULL;
}

static int
json2step(json_t *json, char const *serial, struct files_ht *files,
    struct rrdp_step **result)
{
	struct rrdp_step *step;
	int error;

	step = pmalloc(sizeof(struct rrdp_step));

	error = str2serial(serial, &step->serial);
	if (error)
		goto step;
	error = json2filerefs(json, "files", files, &step->files);
	if (error < 0)
		goto serial;
	error = json2hash(json, "hash", step->delta_hash.bytes);
	if (error == ENOENT)
		step->delta_hash.set = false;
	else if (error)
		goto files;
	else
		step->delta_hash.set = true;

	*result = step;
	return 0;

files:	filerefs_clear(&step->files, true);
serial:	serial_cleanup(&step->serial);
step:	free(step);
	return error;
}

static int
json2steps(json_t *jsteps, struct rrdp_session *session, struct files_ht *files)
{
	char const *jkey;
	json_t *child;
	struct rrdp_step *step, *prev;
	BIGNUM *diff;
	array_index s, sn;
	int error;

	prev = NULL;
	diff = BN_create();
	error = 0;

	sn = json_object_size(jsteps);
	if (sn > config_get_rrdp_delta_threshold())
		sn = config_get_rrdp_delta_threshold();

	s = 0;
	json_object_foreach(jsteps, jkey, child) {
		error = json2step(child, jkey, files, &step);
		if (error)
			break;

		if (prev) {
			if (!BN_sub(diff, prev->serial.num, step->serial.num)) {
				error = pr_err("Cannot compute %s - %s; unknown error.",
				    prev->serial.str, step->serial.str);
				break;
			}
			if (!BN_is_one(diff)) {
				error = pr_err("Serial '%s' is not the successor of '%s'",
				    prev->serial.str, step->serial.str);
				break;
			}
		}

		TAILQ_INSERT_TAIL(&session->steps, step, lh);
		prev = step;

		s++;
		if (s >= sn)
			break;
	}

	BN_free(diff);
	return error;
}


static int
json2session(json_t *json, struct rrdp_session *session, struct files_ht *files)
{
	json_t *jchild;
	int error;

	error = json_get_object(json, "steps", &jchild);
	if (error)
		return error;
	error = json2steps(jchild, session, files);
	if (error)
		return error;

	error = json_get_object(json, "fallbacks", &jchild);
	if (error)
		return error;
	error = json2fallbacks(jchild, &session->fbs, files);
	if (error)
		return error;

	return 0;
}

/* @path is expected to outlive the context. */
int
rrdp_json2ctx(json_t *json, char *path, struct rrdp_ctx **result)
{
	struct files_ht files;
	json_t *jfiles, *jsessions;
	struct rrdp_ctx *ctx;
	char const *key;
	json_t *child;
	int error;

	error = json_get_object(json, "files", &jfiles);
	if (error)
		return error;
	error = json_get_object(json, "sessions", &jsessions);
	if (error)
		return error;

	ctx = pzalloc(sizeof(struct rrdp_ctx));

	error = json2files(jfiles, path, &files);
	if (error)
		goto fail1;
	error = json2cseq(&ctx->seq, jfiles, path, false);
	if (error)
		goto fail2;

	json_object_foreach(jsessions, key, child) {
		error = json2session(child, ctx_add_session(ctx, key), &files);
		if (error)
			goto fail2;
	}

	filerefs_clear(&files, true);
	*result = ctx;
	return 0;

fail2:	filerefs_clear(&files, true);
fail1:	rrdpctx_free(ctx);
	return error;
}

static void
rrdpstep_print(struct rrdp_step *step, int indent)
{
	struct cache_file_ref *ref, *tmp;

	printf("%*s[RRDP Step] serial:%s delta-hash:", indent, "",
	    step->serial.str);
	hash_print(&step->delta_hash);
	printf("\n");

	HASH_ITER(hh, step->files.ht, ref, tmp)
		fileref_print(ref, indent + 2);
}

static void
rrdpsteps_print(struct rrdp_steps *steps, int indent)
{
	struct rrdp_step *step;
	TAILQ_FOREACH(step, steps, lh)
		rrdpstep_print(step, indent);
}

static void
rrdpsession_print(struct rrdp_session *session, int indent)
{
	printf("%*s[RRDP Session] id:%s\n", indent, "", session->id);
	rrdpsteps_print(&session->steps, indent + 2);
	fallbacks_print(&session->fbs, indent + 2);
}

void
rrdpctx_print(struct rrdp_ctx *ctx, int indent)
{
	struct rrdp_session *session;

	if (ctx == NULL)
		return;

	printf("%*s[RRDP Context] seq:%lx\n", indent, "", ctx->seq.next_id);
	TAILQ_FOREACH(session, &ctx->sessions, lh)
		rrdpsession_print(session, indent + 2);
}
