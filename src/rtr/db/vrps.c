#include "vrps.h"

#include <pthread.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <sys/queue.h>

#include "clients.h"
#include "common.h"
#include "output_printer.h"
#include "validation_handler.h"
#include "data_structure/array_list.h"
#include "object/router_key.h"
#include "object/tal.h"
#include "rtr/db/db_table.h"
#include "slurm/slurm_loader.h"
#include "thread/thread_pool.h"

DEFINE_ARRAY_LIST_FUNCTIONS(deltas_db, struct delta_group, )

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
	struct deltas_db deltas;

	/* Last valid SLURM applied to base */
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
	 */
	serial_t serial;
	uint16_t v0_session_id;
	uint16_t v1_session_id;
};

static struct state state;

/* Thread pool to use when the TALs will be processed */
static struct thread_pool *pool;

/** Read/write lock, which protects @state and its inhabitants. */
static pthread_rwlock_t state_lock;

/** Lock to protect ROA table during construction. */
static pthread_rwlock_t table_lock;

void
deltagroup_cleanup(struct delta_group *group)
{
	deltas_refput(group->deltas);
}

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

	deltas_db_init(&state.deltas);

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
		goto release_deltas;
	state.v0_session_id = now & 0xFFFF;

	/* Minus 1 to prevent same ID */
	state.v1_session_id = (state.v0_session_id != 0)
	    ? (state.v0_session_id - 1)
	    : (0xFFFFu);

	state.slurm = NULL;

	error = pthread_rwlock_init(&state_lock, NULL);
	if (error) {
		error = pr_op_errno(error, "state pthread_rwlock_init() errored");
		goto release_deltas;
	}

	error = pthread_rwlock_init(&table_lock, NULL);
	if (error) {
		error = pr_op_errno(error, "table pthread_rwlock_init() errored");
		goto release_state_lock;
	}

	return 0;
release_state_lock:
	pthread_rwlock_destroy(&state_lock);
release_deltas:
	deltas_db_cleanup(&state.deltas, deltagroup_cleanup);
	thread_pool_destroy(pool);
	return error;
}

void
vrps_destroy(void)
{
	if (state.base != NULL)
		db_table_destroy(state.base);
	if (state.slurm != NULL)
		db_slurm_destroy(state.slurm);
	deltas_db_cleanup(&state.deltas, deltagroup_cleanup);
	/* Nothing to do with error codes from now on */
	pthread_rwlock_destroy(&state_lock);
	pthread_rwlock_destroy(&table_lock);
	thread_pool_destroy(pool);
}

#define WLOCK_HANDLER(lock, cb)						\
	int error;							\
	rwlock_write_lock(lock);					\
	error = cb;							\
	rwlock_unlock(lock);						\
	return error;

#define RLOCK_HANDLER(lock, cb)						\
	int error;							\
	rwlock_read_lock(lock);						\
	error = cb;							\
	rwlock_unlock(lock);						\
	return error;

int
handle_roa_v4(uint32_t as, struct ipv4_prefix const *prefix,
    uint8_t max_length, void *arg)
{
	WLOCK_HANDLER(&table_lock,
	    rtrhandler_handle_roa_v4(arg, as, prefix, max_length))
}

int
handle_roa_v6(uint32_t as, struct ipv6_prefix const * prefix,
    uint8_t max_length, void *arg)
{
	WLOCK_HANDLER(&table_lock,
	    rtrhandler_handle_roa_v6(arg, as, prefix, max_length))
}

int
handle_router_key(unsigned char const *ski, uint32_t as,
    unsigned char const *spk, void *arg)
{
	WLOCK_HANDLER(&table_lock,
	    rtrhandler_handle_router_key(arg, ski, as, spk))
}

static int
__perform_standalone_validation(struct db_table **result)
{
	struct db_table *db;
	int error;

	db = db_table_create();
	if (db == NULL)
		return pr_enomem();

	error = perform_standalone_validation(pool, db);
	if (error) {
		db_table_destroy(db);
		return error;
	}

	*result = db;
	return 0;
}

/*
 * Remove unnecessary deltas from the database.
 * Unnecessary deltas = those whose serial < min_serial.
 */
static void
cleanup_deltas(serial_t min_serial)
{
	struct delta_group *initial;
	struct delta_group *rm;
	array_index i;

	/*
	 * TODO the array is sorted by serial, but it's supposed to employ
	 * serial arithmetic. > is incorrect.
	 */
	ARRAYLIST_FOREACH(&state.deltas, initial, i)
		if (initial->serial > min_serial)
			break;

	for (rm = state.deltas.array; rm < initial; rm++)
		deltas_refput(rm->deltas);

	state.deltas.len -= (initial - state.deltas.array);
	memmove(state.deltas.array, initial,
	    state.deltas.len * sizeof(struct delta_group));
}

static int
__compute_deltas(struct db_table *old_base, struct db_table *new_base,
    bool *notify_clients)
{
	struct deltas *deltas; /* Deltas in raw form */
	struct delta_group deltas_node; /* Deltas in database node form */
	serial_t min_serial;
	int error;

	error = 0;

	/* No clients listening = no need for deltas */
	if (clients_get_min_serial(&min_serial) == -ENOENT)
		goto purge_deltas;

	if (notify_clients != NULL)
		*notify_clients = true;

	/* First version of the database = No deltas */
	if (old_base == NULL)
		goto purge_deltas;

	/*
	 * Failure on computing deltas = latest database version lacks deltas,
	 * which renders all previous deltas useless. (Because clients always
	 * want the latest.)
	 */
	error = compute_deltas(old_base, new_base, &deltas);
	if (error)
		goto purge_deltas;

	if (deltas_is_empty(deltas)) {
		if (notify_clients != NULL)
			*notify_clients = false;
		deltas_refput(deltas);
		goto success; /* Happy path when the DB doesn't change. */
	}

	deltas_node.serial = state.serial;
	deltas_node.deltas = deltas;
	/* On success, ownership of deltas is transferred to state.deltas. */
	error = deltas_db_add(&state.deltas, &deltas_node);
	if (error) {
		deltas_refput(deltas);
		goto purge_deltas;
	}

	/* Happy path when the DB changes. (Fall through) */

success:
	cleanup_deltas(min_serial);
	return 0;

purge_deltas:
	deltas_db_cleanup(&state.deltas, deltagroup_cleanup);
	return error;
}

static int
__vrps_update(bool *notify_clients)
{
	struct db_table *old_base;
	struct db_table *new_base;
	int error;

	if (notify_clients)
		*notify_clients = false;
	old_base = NULL;
	new_base = NULL;

	error = __perform_standalone_validation(&new_base);
	if (error)
		return error;
	error = slurm_apply(&new_base, &state.slurm);
	if (error) {
		db_table_destroy(new_base);
		return error;
	}

	/*
	 * At this point, new_base is completely valid. Even if we error out
	 * later, report the ROAs.
	 *
	 * This is done after the validation, not during it, to prevent
	 * duplicate ROAs.
	 */
	output_print_data(new_base);

	rwlock_write_lock(&state_lock);

	old_base = state.base; /* Postpone destruction, to release lock ASAP. */
	state.base = new_base;
	state.serial++;

	/*
	 * TODO after refactoring vrps_foreach_filtered_delta(), move this out
	 * of the mutex. You don't really need the mutex to compute the deltas;
	 * vrps_update() is supposed to be the only writer.
	 */
	error = __compute_deltas(old_base, new_base, notify_clients);
	if (error) {
		/*
		 * Deltas are nice-to haves. As long as state.base is correct,
		 * the validator can continue serving the routers.
		 * (Albeit less efficiently.)
		 * So drop a warning and keep going.
		 */
		pr_op_warn("Deltas could not be computed: %s", strerror(error));
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
			pr_op_info("- Valid Prefixes: 0");
			pr_op_info("- Valid Router Keys: 0");
			if (config_get_mode() == SERVER)
				pr_op_info("- No serial number.");
			break;
		}

		pr_op_info("- Valid Prefixes: %u", db_table_roa_count(state.base));
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
			goto unlock;
		error = db_table_foreach_router_key(state.base, cb_rk, arg);
	} else
		error = -EAGAIN;

unlock:
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
		if (VRP_EQ(&delta->vrp, &ptr->delta.vrp) &&
		    delta->flags != ptr->delta.flags) {
			SLIST_REMOVE(filtered_vrps, ptr, vrp_node, next);
			free(ptr);
			return 0;
		}

	ptr = malloc(sizeof(struct vrp_node));
	if (ptr == NULL)
		return pr_enomem();

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

	ptr = malloc(sizeof(struct rk_node));
	if (ptr == NULL)
		return pr_enomem();

	ptr->delta = *delta;
	SLIST_INSERT_HEAD(filtered_keys, ptr, next);
	return 0;
}

/*
 * Remove all operations on @deltas that override each other, and do @cb (with
 * @arg) on each element of the resultant delta.
 */
int
vrps_foreach_filtered_delta(struct deltas_db *deltas,
    delta_vrp_foreach_cb cb_prefix, delta_router_key_foreach_cb cb_rk,
    void *arg)
{
	struct sorted_lists filtered_lists;
	struct delta_group *group;
	struct vrp_node *vnode;
	struct rk_node *rnode;
	array_index i;
	int error = 0;

	/*
	 * Filter: Remove entries that cancel each other.
	 * (We'll have to build a separate list because the database nodes
	 * are immutable.)
	 */
	SLIST_INIT(&filtered_lists.prefixes);
	SLIST_INIT(&filtered_lists.router_keys);
	ARRAYLIST_FOREACH(deltas, group, i) {
		error = deltas_foreach(group->serial, group->deltas,
		    vrp_ovrd_remove, router_key_ovrd_remove, &filtered_lists);
		if (error)
			goto release_list;
	}

	/* Now do the corresponding callback on the filtered deltas */
	SLIST_FOREACH(vnode, &filtered_lists.prefixes, next) {
		error = cb_prefix(&vnode->delta, arg);
		if (error)
			break;
	}
	SLIST_FOREACH(rnode, &filtered_lists.router_keys, next) {
		error = cb_rk(&rnode->delta, arg);
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

	return error;
}

/**
 * Adds to @result the deltas whose serial > @from.
 *
 * Please keep in mind that there is at least one errcode-aware caller. The most
 * important ones are
 * 1. 0: No errors.
 * 2. -EAGAIN: No data available; database still under construction.
 * 3. -ESRCH: @from was not found.
 *
 * As usual, only 0 guarantees valid out parameters. (@to and @result.)
 * (But note that @result is supposed to be already initialized, so caller will
 * have to clean it up regardless of error.)
 */
int
vrps_get_deltas_from(serial_t from, serial_t *to, struct deltas_db *result)
{
	struct delta_group *group;
	serial_t first_serial;
	serial_t last_serial;
	array_index i;
	int error;

	error = rwlock_read_lock(&state_lock);
	if (error)
		return error;

	if (state.base == NULL)
		goto try_again; /* Database still under construction. */
	if (from == state.serial) {
		/* Client already has the latest serial. */
		rwlock_unlock(&state_lock);
		*to = from;
		return 0;
	}
	if (state.deltas.len == 0)
		goto reset_database; /* No deltas available. */

	first_serial = state.deltas.array[0].serial - 1;
	last_serial = state.deltas.array[state.deltas.len - 1].serial;

	if (from < first_serial)
		goto reset_database; /* Delta was already deleted. */
	if (from > last_serial)
		goto reset_database; /* Serial is invalid. */

	for (i = from - first_serial; i < state.deltas.len; i++) {
		group = &state.deltas.array[i];

		error = deltas_db_add(result, group);
		if (error) {
			rwlock_unlock(&state_lock);
			return error;
		}

		deltas_refget(group->deltas);
	}

	rwlock_unlock(&state_lock);
	*to = last_serial;
	return 0;

try_again:
	rwlock_unlock(&state_lock);
	return -EAGAIN;

reset_database:
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
	/* Semaphore isn't needed since this value is set at initialization */
	if (rtr_version == 1)
		return state.v1_session_id;
	return state.v0_session_id;
}
