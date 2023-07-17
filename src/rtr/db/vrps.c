#include "vrps.h"

#include <pthread.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <sys/queue.h>

#include "alloc.h"
#include "common.h"
#include "output_printer.h"
#include "validation_handler.h"
#include "types/router_key.h"
#include "data_structure/array_list.h"
#include "object/tal.h"
#include "rtr/rtr.h"
#include "rtr/db/db_table.h"
#include "slurm/slurm_loader.h"
#include "thread/thread_pool.h"

struct vrp_node {
	struct delta_vrp delta;
	SLIST_ENTRY(vrp_node) next;
};

struct rk_node {
	struct delta_router_key delta;
	SLIST_ENTRY(rk_node) next;
};

/** Sorted list to filter deltas */
SLIST_HEAD(vrp_slist, vrp_node);
SLIST_HEAD(rk_slist, rk_node);

struct sorted_lists {
	struct vrp_slist prefixes;
	struct rk_slist router_keys;
};

struct state {
	/**
	 * All the current valid ROAs.
	 *
	 * Can be NULL, so handle gracefully.
	 * (We use this to know we're supposed to generate a @deltas entry
	 * during the current iteration.)
	 */
	struct db_table *base;
	/** DB changes to @base over time. */
	struct deltas_array *deltas;

	/*
	 * Last valid SLURM applied to base.
	 *
	 * Doesn't need locking, because the only writer is also the only
	 * reader.
	 */
	struct db_slurm *slurm;

	/*
	 * This is the serial number of base.
	 *
	 * At least one RTR client implementation (Cloudflare's rpki-rtr-client)
	 * malfunctions if the validator uses zero as the first serial, so this
	 * value behaves as follows:
	 *
	 * serial = 0. After every successful validation cycle, serial++.
	 *
	 * Do not use this value to check whether we already finished our first
	 * validation. (Use base != NULL for that.) Zero is totally a valid
	 * serial, particularly when the integer wraps.
	 *
	 * TODO (fine) this should probably be moved to struct db_table.
	 */
	serial_t serial;
	uint16_t v0_session_id;
	uint16_t v1_session_id;
};

static struct state state;

/* Thread pool to use when the TALs will be processed */
static struct thread_pool *pool;

/** Protects @state.base, @state.deltas and @state.serial. */
static pthread_rwlock_t state_lock;

/**
 * Lock to protect the ROA table while it's being built up.
 *
 * To be honest, I'm tempted to remove this mutex completely. It currently
 * exists because all the threads store their ROAs in the same table, which is
 * awkward engineering. Each thread should work on its own table, and the main
 * thread should join the tables afterwards. This would render the semaphore
 * redundant, as well as rid the relevant code from any concurrency risks.
 *
 * I'm conflicted about committing to the refactor however, because the change
 * would require about twice as much memory and involve the extra joining step.
 * And the current implementation is working fine...
 *
 * Assuming, that is, that #83/#89 isn't a concurrency problem. But I can't
 * figure out how it could be.
 */
static pthread_mutex_t table_lock = PTHREAD_MUTEX_INITIALIZER;

int
vrps_init(void)
{
	time_t now;
	int error;

	pool = NULL;
	error = thread_pool_create("Validation",
	    config_get_thread_pool_validation_max(), &pool);
	if (error)
		return error;

	state.base = NULL;
	state.deltas = darray_create();

	/*
	 * Use the same start serial, the session ID will avoid
	 * "desynchronization" (more at RFC 6810 'Glossary' and
	 * 'Fields of a PDU')
	 */
	state.serial = 0;

	/* Get the bits that'll fit in session_id */
	now = 0;
	error = get_current_time(&now);
	if (error)
		goto revert_deltas;
	state.v0_session_id = now & 0xFFFF;

	/* Minus 1 to prevent same ID */
	state.v1_session_id = (state.v0_session_id != 0)
	    ? (state.v0_session_id - 1)
	    : (0xFFFFu);

	state.slurm = NULL;

	error = pthread_rwlock_init(&state_lock, NULL);
	if (error) {
		pr_op_err("state pthread_rwlock_init() errored: %s",
		    strerror(error));
		goto revert_deltas;
	}

	return 0;

revert_deltas:
	darray_destroy(state.deltas);
	thread_pool_destroy(pool);
	return error;
}

void
vrps_destroy(void)
{
	thread_pool_destroy(pool);

	pthread_rwlock_destroy(&state_lock);

	if (state.slurm != NULL)
		db_slurm_destroy(state.slurm);

	darray_destroy(state.deltas);
	if (state.base != NULL)
		db_table_destroy(state.base);
}

#define WLOCK_HANDLER(cb)						\
	int error;							\
	mutex_lock(&table_lock);					\
	error = cb;							\
	mutex_unlock(&table_lock);					\
	return error;

int
handle_roa_v4(uint32_t as, struct ipv4_prefix const *prefix,
    uint8_t max_length, void *arg)
{
	WLOCK_HANDLER(rtrhandler_handle_roa_v4(arg, as, prefix, max_length))
}

int
handle_roa_v6(uint32_t as, struct ipv6_prefix const * prefix,
    uint8_t max_length, void *arg)
{
	WLOCK_HANDLER(rtrhandler_handle_roa_v6(arg, as, prefix, max_length))
}

int
handle_router_key(unsigned char const *ski, struct asn_range const *asns,
    unsigned char const *spk, void *arg)
{
	uint64_t asn;
	int error = 0;

	mutex_lock(&table_lock);

	/*
	 * TODO (warning) Umm... this is begging for a limit.
	 * If the issuer gets it wrong, we can iterate up to 2^32 times.
	 * The RFCs don't seem to care about this.
	 */
	for (asn = asns->min; asn <= asns->max; asn++) {
		error = rtrhandler_handle_router_key(arg, ski, asn, spk);
		if (error)
			break;
	}

	mutex_unlock(&table_lock);
	return error;
}

static int
__perform_standalone_validation(struct db_table **result)
{
	struct db_table *db;
	int error;

	db = db_table_create();
	if (db == NULL)
		enomem_panic();

	error = perform_standalone_validation(pool, db);
	if (error) {
		db_table_destroy(db);
		return error;
	}

	*result = db;
	return 0;
}

static int
__compute_deltas(struct db_table *old_base, struct db_table *new_base,
    bool *notify_clients, struct deltas **result)
{
	int error;

	*result = NULL;
	if (notify_clients != NULL)
		*notify_clients = true;

	/* First version of the database = No deltas */
	if (old_base == NULL)
		return 0;

	error = compute_deltas(old_base, new_base, result);
	if (error)
		return error;

	if (deltas_is_empty(*result)) {
		if (notify_clients != NULL)
			*notify_clients = false;
		deltas_refput(*result);
		*result = NULL;
	}

	return 0;
}

static int
__vrps_update(bool *notify_clients)
{
	/*
	 * This function is the only writer, and it runs once at a time.
	 * Therefore, it's going to worry about write locking, but not read
	 * locking.
	 */

	struct db_table *old_base;
	struct db_table *new_base;
	struct deltas *new_deltas;
	int error;

	if (notify_clients)
		*notify_clients = false;
	old_base = state.base;
	new_base = NULL;
	find_bad_vrp("Old base", old_base);

	error = __perform_standalone_validation(&new_base);
	if (error)
		return error;

	find_bad_vrp("After standalone (old)", old_base);
	find_bad_vrp("After standalone (new)", new_base);

	error = slurm_apply(new_base, &state.slurm);
	if (error) {
		db_table_destroy(new_base);
		return error;
	}

	find_bad_vrp("After SLURM (old)", old_base);
	find_bad_vrp("After SLURM (new)", new_base);

	/*
	 * At this point, new_base is completely valid. Even if we error out
	 * later, report the ROAs.
	 *
	 * This is done after the validation, not during it, to prevent
	 * duplicate ROAs.
	 */
	output_print_data(new_base);

	find_bad_vrp("After CSV (old)", old_base);
	find_bad_vrp("After CSV (new)", new_base);

	error = __compute_deltas(old_base, new_base, notify_clients,
	    &new_deltas);
	if (error) {
		/*
		 * Deltas are nice-to haves. As long as state.base is correct,
		 * the validator can continue serving the routers.
		 * (Albeit less efficiently.)
		 * So drop a warning and keep going.
		 */
		pr_op_warn("Deltas could not be computed: %s", strerror(error));
	}

	rwlock_write_lock(&state_lock);

	state.base = new_base;
	state.serial++;
	if (new_deltas != NULL) {
		/* Ownership transferred */
		darray_add(state.deltas, new_deltas);
	} else {
		/*
		 * If the latest base has no deltas, all existing deltas are
		 * rendered useless. This is because clients always want to
		 * reach the latest serial, no matter where they are.
		 */
		darray_clear(state.deltas);
	}

	rwlock_unlock(&state_lock);

	if (old_base != NULL)
		db_table_destroy(old_base);

	return 0;
}

int
vrps_update(bool *changed)
{
	time_t start, finish;
	long int exec_time;
	serial_t serial;
	int error;

	/*
	 * This wrapper is mainly intended to log informational data, so if
	 * there's no need, don't do unnecessary calls.
	 */
	if (!log_op_enabled(LOG_INFO))
		return __vrps_update(changed);

	pr_op_info("Starting validation.");
	if (config_get_mode() == SERVER) {
		error = get_last_serial_number(&serial);
		if (!error)
			pr_op_info("- Serial before validation: %u", serial);
	}

	time(&start);
	error = __vrps_update(changed);
	time(&finish);
	exec_time = finish - start;

	pr_op_info("Validation finished:");
	rwlock_read_lock(&state_lock);
	do {
		if (state.base == NULL) {
			rwlock_unlock(&state_lock);
			pr_op_info("- Valid ROAs: 0");
			pr_op_info("- Valid Router Keys: 0");
			if (config_get_mode() == SERVER)
				pr_op_info("- No serial number.");
			break;
		}

		pr_op_info("- Valid ROAs: %u", db_table_roa_count(state.base));
		pr_op_info("- Valid Router Keys: %u",
		    db_table_router_key_count(state.base));
		if (config_get_mode() == SERVER)
			pr_op_info("- Serial: %u", state.serial);
		rwlock_unlock(&state_lock);
	} while(0);
	pr_op_info("- Real execution time: %ld secs.", exec_time);

	return error;
}

/**
 * Please keep in mind that there is at least one errcode-aware caller. The most
 * important ones are
 * 1. 0: No errors.
 * 2. -EAGAIN: No data available; database still under construction.
 */
int
vrps_foreach_base(vrp_foreach_cb cb_roa, router_key_foreach_cb cb_rk, void *arg)
{
	int error;

	error = rwlock_read_lock(&state_lock);
	if (error)
		return error;

	if (state.base != NULL) {
		error = db_table_foreach_roa(state.base, cb_roa, arg);
		if (error)
			goto end;
		error = db_table_foreach_router_key(state.base, cb_rk, arg);
	} else
		error = -EAGAIN;

end:
	rwlock_unlock(&state_lock);
	return error;
}

/*
 * Remove the announcements/withdrawals that override each other.
 *
 * (Note: We're assuming the array is already duplicateless enough thanks to the
 * hash table.)
 */
static int
vrp_ovrd_remove(struct delta_vrp const *delta, void *arg)
{
	struct sorted_lists *lists = arg;
	struct vrp_node *ptr;
	struct vrp_slist *filtered_vrps;

	filtered_vrps = &lists->prefixes;
	SLIST_FOREACH(ptr, filtered_vrps, next)
		if (vrp_equals(&delta->vrp, &ptr->delta.vrp) &&
		    delta->flags != ptr->delta.flags) {
			SLIST_REMOVE(filtered_vrps, ptr, vrp_node, next);
			free(ptr);
			return 0;
		}

	ptr = pmalloc(sizeof(struct vrp_node));
	ptr->delta = *delta;
	SLIST_INSERT_HEAD(filtered_vrps, ptr, next);

	return 0;
}

static int
router_key_ovrd_remove(struct delta_router_key const *delta, void *arg)
{
	struct sorted_lists *lists = arg;
	struct rk_node *ptr;
	struct rk_slist *filtered_keys;
	struct router_key const *key;

	filtered_keys = &lists->router_keys;
	SLIST_FOREACH(ptr, filtered_keys, next) {
		key = &delta->router_key;
		if (key->as == ptr->delta.router_key.as &&
		    memcmp(key->ski, ptr->delta.router_key.ski, RK_SKI_LEN) == 0
		    && memcmp(key->spk, ptr->delta.router_key.spk,
		    RK_SPKI_LEN) == 0 &&
		    delta->flags != ptr->delta.flags) {
			SLIST_REMOVE(filtered_keys, ptr, rk_node, next);
			free(ptr);
			return 0;
		}
	}

	ptr = pmalloc(sizeof(struct rk_node));
	ptr->delta = *delta;
	SLIST_INSERT_HEAD(filtered_keys, ptr, next);

	return 0;
}

static int
__deltas_foreach(struct deltas *deltas, void *arg)
{
	return deltas_foreach(deltas, vrp_ovrd_remove, router_key_ovrd_remove,
	    arg);
}

/**
 * Runs @vrp_cb and @rk_cb on all the deltas from the database whose
 * serial > @from, excluding those that cancel each other.
 *
 * Please keep in mind that there is at least one errcode-aware caller. The most
 * important ones are
 * 1. 0: No errors.
 * 2. -EAGAIN: No data available; database still under construction.
 * 3. -ESRCH: @from was not found.
 */
int
vrps_foreach_delta_since(serial_t from, serial_t *to,
    delta_vrp_foreach_cb vrp_cb, delta_router_key_foreach_cb rk_cb,
    void *arg)
{
	struct sorted_lists filtered_lists;
	struct vrp_node *vnode;
	struct rk_node *rnode;
	int error;

	error = rwlock_read_lock(&state_lock);
	if (error)
		return error;

	if (state.base == NULL) {
		/* Database still under construction. */
		rwlock_unlock(&state_lock);
		return -EAGAIN;
	}

	if (from == state.serial) {
		/* Client already has the latest serial. */
		rwlock_unlock(&state_lock);
		*to = from;
		return 0;
	}

	/* if from < first serial */
	if (serial_lt(from, state.serial - darray_len(state.deltas)))
		goto cache_reset; /* Delta was already deleted. */
	/* if from > last serial */
	if (serial_lt(state.serial, from))
		goto cache_reset; /* Serial is invalid. */

	/*
	 * TODO (performance) this implementation is naive.
	 * Either use a hash set, or sort the resources.
	 * Also, deltas that share a serial do not need to be compared to each
	 * other. (Corollary: If there's one serial, no comparisons whatsoever
	 * need to be made.)
	 */

	/*
	 * Filter: Remove entries that cancel each other.
	 * (We'll have to build a separate list because the database nodes
	 * are immutable.)
	 */
	SLIST_INIT(&filtered_lists.prefixes);
	SLIST_INIT(&filtered_lists.router_keys);

	error = darray_foreach_since(state.deltas, state.serial - from,
	    __deltas_foreach, &filtered_lists);
	if (error)
		goto release_list;

	/* Now do the corresponding callback on the filtered deltas */
	SLIST_FOREACH(vnode, &filtered_lists.prefixes, next) {
		error = vrp_cb(&vnode->delta, arg);
		if (error)
			break;
	}
	SLIST_FOREACH(rnode, &filtered_lists.router_keys, next) {
		error = rk_cb(&rnode->delta, arg);
		if (error)
			break;
	}

release_list:
	while (!SLIST_EMPTY(&filtered_lists.prefixes)) {
		vnode = filtered_lists.prefixes.slh_first;
		SLIST_REMOVE_HEAD(&filtered_lists.prefixes, next);
		free(vnode);
	}
	while (!SLIST_EMPTY(&filtered_lists.router_keys)) {
		rnode = filtered_lists.router_keys.slh_first;
		SLIST_REMOVE_HEAD(&filtered_lists.router_keys, next);
		free(rnode);
	}

	*to = state.serial;
	rwlock_unlock(&state_lock);
	return 0;

cache_reset:
	rwlock_unlock(&state_lock);
	return -ESRCH;
}

int
get_last_serial_number(serial_t *result)
{
	int error;

	error = rwlock_read_lock(&state_lock);
	if (error)
		return error;

	if (state.base != NULL)
		*result = state.serial;
	else
		error = -EAGAIN;

	rwlock_unlock(&state_lock);

	return error;
}

uint16_t
get_current_session_id(uint8_t rtr_version)
{
	/*
	 * These values are constant after initialization,
	 * so locking isn't needed.
	 */
	if (rtr_version == 1)
		return state.v1_session_id;
	return state.v0_session_id;
}

void
vrps_print_base(void)
{
	vrps_foreach_base(vrp_print, router_key_print, NULL);
}
