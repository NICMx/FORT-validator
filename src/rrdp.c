#include "rrdp.h"

#include <errno.h>
#include <openssl/err.h>
#include <sys/queue.h>

#include "base64.h"
#include "common.h"
#include "config.h"
#include "file.h"
#include "http.h"
#include "json_util.h"
#include "log.h"
#include "rrdp_xml.h"
#include "thread_var.h"

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

	for (d = 0; d < notif->deltas.len; d++) {
		delta = &notif->deltas.arr[d];

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
	    : &notif->deltas.arr[index];
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

static int
handle_snapshot(struct update_notification *notif,
    struct rrdp_session *session,
    struct cache_sequence *seq)
{
	struct rrdp_step *step;
	int error;

	step = TAILQ_FIRST(&session->steps);
	if (!step) {
		step = step_create(&notif->session.serial);
		TAILQ_INSERT_HEAD(&session->steps, step, lh);
	} else if (!serial_equals(&notif->session.serial, &step->serial)) {
		/* XXX what is this? */
		return pr_err("Notification serial (%s) does not match most recent delta serial (%s)",
		    notif->session.serial.str, step->serial.str);
	}

	error = rrdpxml_explode_snapshot(notif, &step->files, seq);
	if (!error)
		session->fresh = true;

	return error;
}

static int
handle_delta(struct update_notification *notif,
    struct notification_delta *delta,
    struct rrdp_session *session,
    struct cache_sequence *seq)
{
	struct rrdp_step *step;
	int error;

	step = step_create(&delta->serial);
	step->files = filerefs_clone(&TAILQ_FIRST(&session->steps)->files);
	step->delta_hash = delta->meta.hash;
	TAILQ_INSERT_HEAD(&session->steps, step, lh);

	error = rrdpxml_explode_delta(notif, delta, &step->files, seq);
	if (!error)
		session->fresh = true;

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
		error = handle_delta(notif, &notif->deltas.arr[d], session, cseq);
		if (error)
			return error;
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

	error = rrdpxml_fetch_notif(notif_uri, mtim, changed, &notif);
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
		if (json_object_add(jstep, "files", filerefs2json(&step->files)))
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
		    fallback2json(fb)))
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
