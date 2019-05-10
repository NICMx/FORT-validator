#include "vrps.h"

#include <pthread.h>
#include <stdbool.h>
#include <string.h>
#include "clients.h"
#include "common.h"
#include "validation_handler.h"
#include "data_structure/array_list.h"
#include "object/tal.h"
#include "rtr/db/roa_table.h"
#include "slurm/slurm_loader.h"

/*
 * Storage of VRPs (term taken from RFC 6811 "Validated ROA Payload") and
 * Serials that contain such VRPs
 */

#define START_SERIAL		0

struct delta {
	uint32_t serial;
	struct deltas *deltas;
};

ARRAY_LIST(deltas_db, struct delta)

struct state {
	/**
	 * All the current valid ROAs.
	 *
	 * Can be NULL, so handle gracefully.
	 * (We use this to know we're supposed to generate a @deltas entry
	 * during the current iteration.)
	 */
	struct roa_table *base;
	/** ROA changes to @base over time. */
	struct deltas_db deltas;

	uint32_t current_serial;
	uint16_t v0_session_id;
	uint16_t v1_session_id;
	time_t last_modified_date;
} state;

/** Read/write lock, which protects @state and its inhabitants. */
static pthread_rwlock_t lock;

static void
delta_destroy(struct delta *delta)
{
	deltas_destroy(delta->deltas);
}

int
vrps_init(void)
{
	int error;

	state.base = NULL;

	deltas_db_init(&state.deltas);

	/*
	 * Use the same start serial, the session ID will avoid
	 * "desynchronization" (more at RFC 6810 'Glossary' and
	 * 'Fields of a PDU')
	 */
	state.current_serial = START_SERIAL;

	/* Get the bits that'll fit in session_id */
	state.v0_session_id = time(NULL) & 0xFFFF;
	/* Minus 1 to prevent same ID */
	state.v1_session_id = (state.v0_session_id != 0)
	    ? (state.v0_session_id - 1)
	    : (0xFFFFu);

	error = pthread_rwlock_init(&lock, NULL);
	if (error) {
		deltas_db_cleanup(&state.deltas, delta_destroy);
		return pr_errno(error, "pthread_rwlock_init() errored");
	}

	return 0;
}

void
vrps_destroy(void)
{
	if (state.base != NULL)
		roa_table_destroy(state.base);
	deltas_db_cleanup(&state.deltas, delta_destroy);
	pthread_rwlock_destroy(&lock); /* Nothing to do with error code */
}

static int
__merge(void *dst, void *src)
{
	return rtrhandler_merge(dst, src);
}

static int
__reset(void *arg)
{
	return rtrhandler_reset(arg);
}

int
__handle_roa_v4(uint32_t as, struct ipv4_prefix const *prefix,
    uint8_t max_length, void *arg)
{
	return rtrhandler_handle_roa_v4(arg, as, prefix, max_length);
}

int
__handle_roa_v6(uint32_t as, struct ipv6_prefix const * prefix,
    uint8_t max_length, void *arg)
{
	return rtrhandler_handle_roa_v6(arg, as, prefix, max_length);
}

static int
__perform_standalone_validation(struct roa_table **result)
{
	struct roa_table *roas, *global_roas;
	struct validation_handler validation_handler;
	int error;

	roas = roa_table_create();
	if (roas == NULL)
		return pr_enomem();

	global_roas = roa_table_create();
	if (global_roas == NULL) {
		roa_table_destroy(roas);
		return pr_enomem();
	}

	validation_handler.merge = __merge;
	validation_handler.merge_arg = global_roas;
	validation_handler.reset = __reset;
	validation_handler.traverse_down = NULL;
	validation_handler.traverse_up = NULL;
	validation_handler.handle_roa_v4 = __handle_roa_v4;
	validation_handler.handle_roa_v6 = __handle_roa_v6;
	validation_handler.arg = roas;

	error = perform_standalone_validation(&validation_handler);
	roa_table_destroy(roas);
	if (error) {
		roa_table_destroy(global_roas);
		return error;
	}

	*result = global_roas;
	return 0;
}



/**
 * Reallocate the array of @db starting at @start, the length and capacity are
 * calculated according to the new start.
 */
static void
resize_deltas_db(struct deltas_db *db, struct delta *start)
{
	struct delta *tmp, *ptr;

	db->len -= (start - db->array);
	while (db->len < db->capacity / 2)
		db->capacity /= 2;
	tmp = malloc(sizeof(struct delta) * db->capacity);
	if (tmp == NULL) {
		pr_enomem();
		return;
	}
	memcpy(tmp, start, db->len * sizeof(struct delta));
	/* Release memory allocated */
	for (ptr = db->array; ptr < start; ptr++)
		deltas_destroy(ptr->deltas);
	free(db->array);
	db->array = tmp;
}

static void
vrps_purge(void)
{
	struct delta *d;
	uint32_t min_serial;

	min_serial = clients_get_min_serial();

	/** Assume is ordered by serial, so get the new initial pointer */
	ARRAYLIST_FOREACH(&state.deltas, d)
		if (d->serial >= min_serial)
			break;

	/** Is the first element or reached end, nothing to purge */
	if (d == state.deltas.array ||
	    (d - state.deltas.array) == state.deltas.len)
		return;

	resize_deltas_db(&state.deltas, d);
}

int
vrps_update(bool *changed)
{
	struct roa_table *old_base;
	struct roa_table *new_base;
	struct deltas *deltas; /* Deltas in raw form */
	struct delta deltas_node; /* Deltas in database node form */
	int error;

	*changed = false;
	old_base = NULL;
	new_base = NULL;

	error = __perform_standalone_validation(&new_base);
	if (error)
		return error;

	rwlock_write_lock(&lock);

	error = slurm_apply(new_base);
	if (error) {
		rwlock_unlock(&lock);
		goto revert_base;
	}

	if (state.base != NULL) {
		error = compute_deltas(state.base, new_base, &deltas);
		if (error) {
			rwlock_unlock(&lock);
			goto revert_base;
		}

		if (deltas_is_empty(deltas)) {
			rwlock_unlock(&lock);
			goto revert_deltas; /* error == 0 is good */
		}

		deltas_node.serial = state.current_serial;
		deltas_node.deltas = deltas;
		error = deltas_db_add(&state.deltas, &deltas_node);
		if (error) {
			rwlock_unlock(&lock);
			goto revert_deltas;
		}

		/*
		 * Postpone destruction of the old database,
		 * to release the lock ASAP.
		 */
		old_base = state.base;

		/** Remove unnecessary deltas */
		vrps_purge();
	}

	*changed = true;
	state.base = new_base;
	state.current_serial++;

	rwlock_unlock(&lock);

	if (old_base != NULL)
		roa_table_destroy(old_base);
	return 0;

revert_deltas:
	deltas_destroy(deltas);
revert_base:
	roa_table_destroy(new_base);
	return error;
}

/*
 * Get a status to know the difference between the delta with serial SERIAL and
 * the last delta at DB.
 *
 * If SERIAL is received as NULL, and there's data at DB then the status will
 * be DIFF_AVAILABLE.
 *
 * This function can only fail due to critical r/w lock bugs.
 */
int
deltas_db_status(uint32_t *serial, enum delta_status *result)
{
	struct delta *delta;
	int error;

	error = rwlock_read_lock(&lock);
	if (error)
		return error;

	if (state.base == NULL) {
		*result = DS_NO_DATA_AVAILABLE;
		goto rlock_succeed;
	}

	/* No serial to match, and there's data at DB */
	if (serial == NULL) {
		*result = DS_DIFF_AVAILABLE;
		goto rlock_succeed;
	}

	/* Is the last version? */
	if (*serial == (state.current_serial - 1)) {
		*result = DS_NO_DIFF;
		goto rlock_succeed;
	}

	/* The first serial isn't at deltas */
	if (*serial == START_SERIAL) {
		*result = DS_DIFF_AVAILABLE;
		goto rlock_succeed;
	}

	/* Get the delta corresponding to the serial */
	ARRAYLIST_FOREACH(&state.deltas, delta)
		if (delta->serial == *serial) {
			*result = DS_DIFF_AVAILABLE;
			goto rlock_succeed;
		}

	/* No match yet, release lock */
	rwlock_unlock(&lock);

	/* Reached end, diff can't be determined */
	*result = DS_DIFF_UNDETERMINED;
	return 0;

rlock_succeed:
	rwlock_unlock(&lock);
	return 0;
}

int
vrps_foreach_base_roa(vrp_foreach_cb cb, void *arg)
{
	int error;

	error = rwlock_read_lock(&lock);
	if (error)
		return error;

	if (state.base != NULL)
		error = roa_table_foreach_roa(state.base, cb, arg);

	rwlock_unlock(&lock);

	return error;
}

int
vrps_foreach_delta_roa(uint32_t from, uint32_t to, vrp_foreach_cb cb, void *arg)
{
	struct delta *d;
	bool from_found;
	int error;

	from_found = false;

	error = rwlock_read_lock(&lock);
	if (error)
		return error;

	ARRAYLIST_FOREACH(&state.deltas, d) {
		if (!from_found) {
			if (d->serial > from)
				from_found = true;
			else
				continue;
		}
		if (d->serial > to)
			break;
		error = deltas_foreach(d->deltas, cb, arg);
		if (error)
			break;
	}

	rwlock_unlock(&lock);

	return error;
}

int
get_last_serial_number(uint32_t *result)
{
	int error;

	error = rwlock_read_lock(&lock);
	if (error)
		return error;

	*result = state.current_serial - 1;

	rwlock_unlock(&lock);

	return 0;
}

uint16_t
get_current_session_id(uint8_t rtr_version)
{
	/* Semaphore isn't needed since this value is set at initialization */
	if (rtr_version == 1)
		return state.v1_session_id;
	return state.v0_session_id;
}
