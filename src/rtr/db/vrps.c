#include "vrps.h"

#include <stdbool.h>
#include <string.h>
#include "common.h"
#include "data_structure/array_list.h"

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
	struct roa_tree *base; /** All the current valid ROAs */
	struct deltas_db deltas; /** ROA changes to @base over time */

	uint32_t current_serial;
	uint16_t v0_session_id;
	uint16_t v1_session_id;
	time_t last_modified_date;
} state;

/* Read and Write locks */
static sem_t rlock, wlock;

/* Readers counter */
static unsigned int rcounter;

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

	error = deltas_db_init(&state.deltas);
	if (error)
		return error;

	/*
	 * Use the same start serial, the session ID will avoid
	 * "desynchronization" (more at RFC 6810 'Glossary' and
	 * 'Fields of a PDU')
	 */
	state.current_serial = START_SERIAL;

	/* Get the bits that'll fit in session_id */
	state.v0_session_id = time(NULL) & 0xFFFF;
	/* Minus 1 to prevent same ID */
	/*
	 * TODO Assigning an int (and potentially negative) to a uint16_t.
	 * Is this legal?
	 */
	state.v1_session_id = state.v0_session_id - 1;

	sem_init(&rlock, 0, 1);
	sem_init(&wlock, 0, 1);
	rcounter = 0;

	return 0;
}

void
vrps_destroy(void)
{
	sem_wait(&wlock);
	roa_tree_put(state.base);
	deltas_db_cleanup(&state.deltas, delta_destroy);
	sem_post(&wlock);

	sem_destroy(&wlock);
	sem_destroy(&rlock);
}

/*
 * @new_deltas can be NULL, @new_tree cannot.
 */
int
vrps_update(struct roa_tree *new_tree, struct deltas *new_deltas)
{
	struct delta new_delta;
	int error;

	sem_wait(&wlock);

	if (new_deltas != NULL) {
		new_delta.serial = state.current_serial + 1;
		new_delta.deltas = new_deltas;
		error = deltas_db_add(&state.deltas, &new_delta);
		if (error) {
			sem_post(&wlock);
			return error;
		}
	}

	if (state.base != NULL)
		roa_tree_put(state.base);
	state.base = new_tree;
	roa_tree_get(new_tree);
	state.current_serial++;

	sem_post(&wlock);
	return 0;
}

/*
 * Get a status to know the difference between the delta with serial SERIAL and
 * the last delta at DB.
 *
 * If SERIAL is received as NULL, and there's data at DB then the status will
 * be DIFF_AVAILABLE.
 */
enum delta_status
deltas_db_status(uint32_t *serial)
{
	struct delta *delta;
	enum delta_status result;

	read_lock(&rlock, &wlock, &rcounter);
	if (state.base == NULL) {
		result = DS_NO_DATA_AVAILABLE;
		goto end;
	}

	/* No serial to match, and there's data at DB */
	if (serial == NULL) {
		result = DS_DIFF_AVAILABLE;
		goto end;
	}

	/* Is the last version? */
	if (*serial == state.current_serial) {
		result = DS_NO_DIFF;
		goto end;
	}

	/* Get the delta corresponding to the serial */
	ARRAYLIST_FOREACH(&state.deltas, delta)
		if (delta->serial == *serial) {
			result = DS_DIFF_AVAILABLE;
			goto end;
		}

	/* No match yet, release lock */
	read_unlock(&rlock, &wlock, &rcounter);

	/* The first serial isn't at deltas */
	if (*serial == START_SERIAL)
		return DS_DIFF_AVAILABLE;

	/* Reached end, diff can't be determined */
	return DS_DIFF_UNDETERMINED;
end:
	read_unlock(&rlock, &wlock, &rcounter);
	return result;
}

int
vrps_foreach_base_roa(vrp_foreach_cb cb, void *arg)
{
	int error;

	read_lock(&rlock, &wlock, &rcounter);
	error = roa_tree_foreach_roa(state.base, cb, arg);
	read_unlock(&rlock, &wlock, &rcounter);

	return error;
}

int
vrps_foreach_delta_roa(uint32_t from, uint32_t to, vrp_foreach_cb cb, void *arg)
{
	struct delta *d;
	bool from_found;
	int error;

	from_found = false;
	error = 0;

	read_lock(&rlock, &wlock, &rcounter);

	ARRAYLIST_FOREACH(&state.deltas, d) {
		if (!from_found) {
			if (d->serial >= from)
				from_found = true;
		} else {
			if (d->serial > to)
				break;
			error = deltas_foreach(d->deltas, cb, arg);
			if (error)
				break;
		}
	}

	read_unlock(&rlock, &wlock, &rcounter);

	return error;
}

uint32_t
get_last_serial_number(void)
{
	uint32_t serial;

	read_lock(&rlock, &wlock, &rcounter);
	serial = state.current_serial - 1;
	read_unlock(&rlock, &wlock, &rcounter);

	return serial;
}

uint16_t
get_current_session_id(uint8_t rtr_version)
{
	/* Semaphore isn't needed since this value is set at initialization */
	if (rtr_version == 1)
		return state.v1_session_id;
	return state.v0_session_id;
}
