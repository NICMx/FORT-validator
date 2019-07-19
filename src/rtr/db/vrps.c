#include "vrps.h"

#include <pthread.h>
#include <string.h>
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

/*
 * Storage of VRPs (term taken from RFC 6811 "Validated ROA Payload") and
 * Serials that contain such VRPs
 */

#define START_SERIAL		0

DEFINE_ARRAY_LIST_FUNCTIONS(deltas_db, struct delta_group, )

struct vrp_node {
	struct delta_vrp delta;
	SLIST_ENTRY(vrp_node) next;
};

/** Sorted list to filter deltas */
SLIST_HEAD(vrp_slist, vrp_node);

struct state {
	/**
	 * All the current valid ROAs.
	 *
	 * Can be NULL, so handle gracefully.
	 * (We use this to know we're supposed to generate a @deltas entry
	 * during the current iteration.)
	 */
	struct db_table *base;
	/** ROA changes to @base over time. */
	struct deltas_db deltas;

	serial_t next_serial;
	uint16_t v0_session_id;
	uint16_t v1_session_id;
	time_t last_modified_date;
} state;

/** Read/write lock, which protects @state and its inhabitants. */
static pthread_rwlock_t lock;

void
deltagroup_cleanup(struct delta_group *group)
{
	deltas_refput(group->deltas);
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
	state.next_serial = START_SERIAL;

	/* Get the bits that'll fit in session_id */
	state.v0_session_id = time(NULL) & 0xFFFF;
	/* Minus 1 to prevent same ID */
	state.v1_session_id = (state.v0_session_id != 0)
	    ? (state.v0_session_id - 1)
	    : (0xFFFFu);

	error = pthread_rwlock_init(&lock, NULL);
	if (error) {
		deltas_db_cleanup(&state.deltas, deltagroup_cleanup);
		return pr_errno(error, "pthread_rwlock_init() errored");
	}

	return 0;
}

void
vrps_destroy(void)
{
	if (state.base != NULL)
		db_table_destroy(state.base);
	deltas_db_cleanup(&state.deltas, deltagroup_cleanup);
	pthread_rwlock_destroy(&lock); /* Nothing to do with error code */
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

int
__handle_bgpsec(unsigned char const *ski, uint32_t as, unsigned char const *spk,
    size_t spk_len, void *arg)
{
	return rtrhandler_handle_router_key(arg, ski, as, spk, spk_len);
}

static int
__perform_standalone_validation(struct db_table **result)
{
	struct db_table *db;
	struct validation_handler validation_handler;
	int error;

	db = db_table_create();
	if (db == NULL)
		return pr_enomem();

	validation_handler.handle_roa_v4 = __handle_roa_v4;
	validation_handler.handle_roa_v6 = __handle_roa_v6;
	validation_handler.handle_bgpsec = __handle_bgpsec;
	validation_handler.arg = db;

	error = perform_standalone_validation(&validation_handler);
	if (error) {
		db_table_destroy(db);
		return error;
	}

	*result = db;
	return 0;
}

/*
 * Make an empty dummy delta array.
 * It's annoying, but temporary. (Until it expires.) Otherwise, it'd be a pain
 * to have to check NULL delta_group.deltas all the time.
 */
static int
create_empty_delta(struct deltas **deltas)
{
	struct delta_group deltas_node;
	int error;

	error = deltas_create(deltas);
	if (error)
		return error;

	deltas_node.serial = state.next_serial;
	deltas_node.deltas = *deltas;
	error = deltas_db_add(&state.deltas, &deltas_node);
	if (error)
		deltas_refput(*deltas);
	return error;
}

/**
 * Reallocate the array of @db starting at @start, the length and capacity are
 * calculated according to the new start.
 */
static int
resize_deltas_db(struct deltas_db *db, struct delta_group *start)
{
	struct delta_group *tmp, *ptr;

	db->len -= (start - db->array);
	while (db->len < db->capacity / 2)
		db->capacity /= 2;
	tmp = malloc(sizeof(struct delta_group) * db->capacity);
	if (tmp == NULL)
		return pr_enomem();

	memcpy(tmp, start, db->len * sizeof(struct delta_group));
	/* Release memory allocated */
	for (ptr = db->array; ptr < start; ptr++)
		deltas_refput(ptr->deltas);
	free(db->array);
	db->array = tmp;

	return 0;
}

/*
 * Lock must be requested before calling this function
 */
static int
vrps_purge(struct deltas **deltas)
{
	struct delta_group *group;
	array_index i;
	serial_t min_serial;

	if (clients_get_min_serial(&min_serial) != 0) {
		/* Nobody will need deltas, just leave an empty one */
		deltas_refput(*deltas);
		deltas_db_cleanup(&state.deltas, deltagroup_cleanup);
		deltas_db_init(&state.deltas);
		return create_empty_delta(deltas);
	}

	/* Assume its ordered by serial, so get the new initial pointer */
	ARRAYLIST_FOREACH(&state.deltas, group, i)
		if (group->serial >= min_serial)
			break;

	/* Its the first element or reached end, nothing to purge */
	if (group == state.deltas.array ||
	    (group - state.deltas.array) == state.deltas.len)
		return 0;

	return resize_deltas_db(&state.deltas, group);
}

int
vrps_update(bool *changed)
{
	struct db_table *old_base;
	struct db_table *new_base;
	struct deltas *deltas; /* Deltas in raw form */
	struct delta_group deltas_node; /* Deltas in database node form */
	serial_t min_serial;
	int error;

	*changed = false;
	old_base = NULL;
	new_base = NULL;

	error = __perform_standalone_validation(&new_base);
	if (error)
		return error;

	rwlock_write_lock(&lock);

	/*
	 * TODO (next iteration) Remember the last valid SLURM
	 *
	 * Currently SLURM is ignored if it has errors, the error is logged and
	 * the new_base isn't altered. Instead of this, the last valid SLURM
	 * should be remembered, and will be applied when a new SLURM has
	 * errors; a warning should be logged to indicate which version of the
	 * SLURM is being applied.
	 */
	slurm_apply(&new_base);

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

		/* Just store deltas if someone will care about it */
		if (clients_get_min_serial(&min_serial) == 0) {
			deltas_node.serial = state.next_serial;
			deltas_node.deltas = deltas;
			error = deltas_db_add(&state.deltas, &deltas_node);
			if (error) {
				rwlock_unlock(&lock);
				goto revert_deltas;
			}
		}

		/*
		 * Postpone destruction of the old database,
		 * to release the lock ASAP.
		 */
		old_base = state.base;

		/* Remove unnecessary deltas */
		error = vrps_purge(&deltas);
		if (error) {
			rwlock_unlock(&lock);
			goto revert_base;
		}
	} else {
		error = create_empty_delta(&deltas);
		if (error) {
			rwlock_unlock(&lock);
			goto revert_base;
		}
	}

	*changed = true;
	state.base = new_base;
	state.next_serial++;

	rwlock_unlock(&lock);

	if (old_base != NULL)
		db_table_destroy(old_base);

	/* Print after validation to avoid duplicated info */
	output_print_data(new_base);

	return 0;

revert_deltas:
	deltas_refput(deltas);
revert_base:
	/* Print info that was already validated */
	output_print_data(new_base);
	db_table_destroy(new_base);
	return error;
}

/**
 * Please keep in mind that there is at least one errcode-aware caller. The most
 * important ones are
 * 1. 0: No errors.
 * 2. -EAGAIN: No data available; database still under construction.
 */
int
vrps_foreach_base_roa(vrp_foreach_cb cb, void *arg)
{
	int error;

	error = rwlock_read_lock(&lock);
	if (error)
		return error;

	if (state.base != NULL)
		error = db_table_foreach_roa(state.base, cb, arg);
	else
		error = -EAGAIN;

	rwlock_unlock(&lock);

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
	struct vrp_node *ptr;
	struct vrp_slist *filtered_vrps = arg;

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

/*
 * Remove all operations on @deltas that override each other, and do @cb (with
 * @arg) on each element of the resultant delta.
 */
int
vrps_foreach_filtered_delta(struct deltas_db *deltas, delta_vrp_foreach_cb cb,
    void *arg)
{
	struct vrp_slist filtered_vrps;
	struct delta_group *group;
	struct vrp_node *ptr;
	array_index i;
	int error = 0;

	/*
	 * Filter: Remove entries that cancel each other.
	 * (We'll have to build a separate list because the database nodes
	 * are immutable.)
	 */
	SLIST_INIT(&filtered_vrps);
	ARRAYLIST_FOREACH(deltas, group, i) {
		/* FIXME Add cb function for router keys */
		error = deltas_foreach(group->serial, group->deltas,
		    vrp_ovrd_remove, NULL, &filtered_vrps);
		if (error)
			goto release_list;
	}

	/* Now do the callback on the filtered deltas */
	SLIST_FOREACH(ptr, &filtered_vrps, next) {
		error = cb(&ptr->delta, arg);
		if (error)
			break;
	}

release_list:
	while (!SLIST_EMPTY(&filtered_vrps)) {
		ptr = filtered_vrps.slh_first;
		SLIST_REMOVE_HEAD(&filtered_vrps, next);
		free(ptr);
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
	array_index i;
	bool from_found;
	int error;

	from_found = false;

	error = rwlock_read_lock(&lock);
	if (error)
		return error;

	if (state.base == NULL) {
		rwlock_unlock(&lock);
		return -EAGAIN;
	}

	ARRAYLIST_FOREACH(&state.deltas, group, i) {
		if (!from_found) {
			if (group->serial == from) {
				from_found = true;
				*to = group->serial;
			}
			continue;
		}

		error = deltas_db_add(result, group);
		if (error) {
			rwlock_unlock(&lock);
			return error;
		}

		deltas_refget(group->deltas);
		*to = group->serial;
	}

	rwlock_unlock(&lock);
	return from_found ? 0 : -ESRCH;
}

int
get_last_serial_number(serial_t *result)
{
	int error;

	error = rwlock_read_lock(&lock);
	if (error)
		return error;

	if (state.base != NULL)
		*result = state.next_serial - 1;
	else
		error = -EAGAIN;

	rwlock_unlock(&lock);

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
