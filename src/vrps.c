#include "vrps.h"

#include <stdbool.h>
#include <string.h>
#include "array_list.h"

/*
 * Storage of VRPs (term taken from RFC 6811 "Validated ROA Payload") and
 * Serials that contain such VRPs
 */

#define FLAG_WITHDRAWAL		0
#define FLAG_ANNOUNCEMENT	1
#define START_SERIAL		0

ARRAY_LIST(vrps, struct vrp)

struct delta {
	u_int32_t serial;
	struct vrps vrps;
};

/* TODO (review) why pointers? */
ARRAY_LIST(deltasdb, struct delta *)

/*
 * TODO (review) It seems you only have one instance of this.
 *
 * Best remove those asterisks; you don't need `base_db` and `deltas_db` to live
 * in the heap.
 */
struct state {
	/** The current valid ROAs, freshly loaded from the file */
	struct delta *base_db;
	/** ROA changes over time */
	struct deltasdb *deltas_db;
	u_int32_t current_serial;
	u_int16_t v0_session_id;
	u_int16_t v1_session_id;
	time_t last_modified_date;
} state;

int
deltas_db_init(void)
{
	int error;

	state.base_db = create_delta();
	if (state.base_db == NULL){
		err(-ENOMEM, "Delta base DB couldn't be initialized");
		return -ENOMEM;
	}

	state.deltas_db = malloc(sizeof(struct deltasdb));
	if (state.deltas_db == NULL){
		err(-ENOMEM, "Deltas DB couldn't be allocated");
		return -ENOMEM;
	}

	error = deltasdb_init(state.deltas_db);
	if (error) {
		err(error, "Deltas DB couldn't be initialized");
		return error;
	}

	/*
	 * Use the same start serial, the session ID will avoid
	 * "desynchronization" (more at RFC 6810 'Glossary' and
	 * 'Fields of a PDU')
	 */
	state.current_serial = START_SERIAL;
	/* The downcast takes the LSBs */
	/*
	 * TODO (review) The result of `time()` is unlikely to fit in a 16-bit
	 * integer.
	 *
	 * (Also: Integer overflow yields undefined behavior.)
	 */
	state.v0_session_id = time(NULL);
	/* Minus 1 to prevent same ID */
	state.v1_session_id = state.v0_session_id - 1;

	return 0;
}

struct delta *
create_delta(void)
{
	struct delta *result;

	result = malloc(sizeof(struct delta));
	if (result == NULL)
		goto fail1;

	if (vrps_init(&result->vrps) != 0)
		goto fail2;

	return result;
fail2:
	free(result);
fail1:
	return NULL;
}

static struct vrp *
create_vrp (u_int32_t asn, u_int8_t prefix_length, u_int8_t max_prefix_length)
{
	struct vrp *result;

	result = malloc(sizeof(struct vrp));
	if (result == NULL)
		return NULL;

	result->asn = asn;
	result->prefix_length = prefix_length;
	result->max_prefix_length = max_prefix_length;
	/* Set as ANNOUNCEMENT by default */
	result->flags = FLAG_ANNOUNCEMENT;

	return result;
}

struct vrp *
create_vrp4(u_int32_t asn, struct in_addr ipv4_prefix, u_int8_t prefix_length,
    u_int8_t max_prefix_length)
{
	struct vrp *result;

	result = create_vrp(asn, prefix_length, max_prefix_length);
	if (result == NULL)
		return NULL;

	result->ipv4_prefix = ipv4_prefix;
	result->in_addr_len = INET_ADDRSTRLEN;

	return result;
}

struct vrp *
create_vrp6(u_int32_t asn, struct in6_addr ipv6_prefix, u_int8_t prefix_length,
    u_int8_t max_prefix_length)
{
	struct vrp *result;

	result = create_vrp(asn, prefix_length, max_prefix_length);
	if (result == NULL)
		return NULL;

	result->ipv6_prefix = ipv6_prefix;
	result->in_addr_len = INET6_ADDRSTRLEN;

	return result;
}

static bool
vrp_equal(struct vrp *left, struct vrp *right)
{
	return left->asn == right->asn
	    && left->in_addr_len == right->in_addr_len
	    && left->prefix_length == right->prefix_length
	    && left->max_prefix_length == right->max_prefix_length
	    && ((left->in_addr_len == INET_ADDRSTRLEN
	        && left->ipv4_prefix.s_addr == right->ipv4_prefix.s_addr)
	    || (left->in_addr_len == INET6_ADDRSTRLEN
	    && IN6_ARE_ADDR_EQUAL(left->ipv6_prefix.s6_addr32,
	        right->ipv6_prefix.s6_addr32)));
}

static struct vrp *
vrp_locate(struct vrps *base, struct vrp *vrp)
{
	struct vrp *cursor;

	ARRAYLIST_FOREACH(base, cursor)
		if (vrp_equal(cursor, vrp))
			return cursor;

	return NULL;
}

static bool
vrp_is_new(struct vrps *base, struct vrp *vrp)
{
	return vrp_locate(base, vrp) == NULL;
}

/*
 * TODO (review) I don't understand the name of this function.
 *
 * I think that you meant "summarize." I've never seen "resume" used
 * an spanish "resumen."
 */
static struct delta *
delta_resume(struct delta *delta)
{
	struct delta *resume_delta;
	struct vrps *base, *search_list;
	struct vrp *cursor;

	/*
	 * Note: Don't fix this function yet.
	 * I realize why you implemented it this way, and I'm trying to come up
	 * with a more efficient algorithm.
	 */

	/* TODO (review) check NULL */
	resume_delta = create_delta();
	resume_delta->serial = delta->serial;
	/* First check for announcements */
	base = &delta->vrps;
	search_list = &state.base_db->vrps;
	ARRAYLIST_FOREACH(base, cursor)
		if (vrp_is_new(search_list, cursor)) {
			cursor->flags = FLAG_ANNOUNCEMENT;
			/* TODO (review) check error code */
			delta_add_vrp(resume_delta, cursor);
		}

	/* Now for withdrawals */
	base = &state.base_db->vrps;
	search_list = &delta->vrps;
	ARRAYLIST_FOREACH(base, cursor)
		if (vrp_is_new(search_list, cursor)) {
			cursor->flags = FLAG_WITHDRAWAL;
			/* TODO (review) check error code */
			delta_add_vrp(resume_delta, cursor);
		}

	return resume_delta;
}

int
deltas_db_add_delta(struct delta *delta)
{
	struct delta *resume;
	int result;

	result = 0;
	delta->serial = state.current_serial;
	/* Store only updates */
	if (delta->serial != START_SERIAL) {
		resume = delta_resume(delta);
		result = deltasdb_add(state.deltas_db, &resume);
	}
	/* Don't set the base in case of error */
	if (result != 0)
		return result;

	free(state.base_db);
	state.base_db = delta;
	state.current_serial++;
	return result;
}

int
delta_add_vrp(struct delta *delta, struct vrp *vrp)
{
	return vrps_add(&delta->vrps, vrp);
}

void
vrp_destroy(struct vrp *vrp)
{
	/* Nothing to free yet */
}

void
delta_destroy(struct delta **delta)
{
	/* Nothing else to free yet */
	vrps_cleanup(&(*delta)->vrps, vrp_destroy);
	free(*delta);
}

void
deltas_db_destroy(void)
{
	deltasdb_cleanup(state.deltas_db, delta_destroy);
	free(state.deltas_db);
	free(state.base_db);
}

/*
 * Get a status to know the difference between the delta with serial SERIAL and
 * the last delta at DB.
 *
 * If SERIAL is received as NULL, and there's data at DB then the status will
 * be DIFF_AVAILABLE.
 *
 * The possible return values are:
 *  NO_DATA_AVAILABLE -> There's no data at the DB
 *  DIFF_UNDETERMINED -> The diff can't be determined
 *  NO_DIFF -> There's no difference
 *  DIFF_AVAILABLE -> There are diffs between SERIAL and the last DB serial
 */
int
deltas_db_status(u_int32_t *serial)
{
	struct delta **delta;

	if (state.base_db->vrps.len == 0)
		return NO_DATA_AVAILABLE;

	/* No serial to match, and there's data at DB */
	if (serial == NULL)
		return DIFF_AVAILABLE;

	/* Is the last version? */
	if (*serial == state.base_db->serial)
		return NO_DIFF;

	/* Get the delta corresponding to the serial */
	ARRAYLIST_FOREACH(state.deltas_db, delta) {
		if ((*delta)->serial == *serial)
			return DIFF_AVAILABLE;
	}

	/* The first serial isn't at deltas */
	if (*serial == START_SERIAL)
		return DIFF_AVAILABLE;

	/* Reached end, diff can't be determined */
	return DIFF_UNDETERMINED;
}

static void
add_vrps_filtered(struct vrps *dst, struct vrps *src)
{
	int i;
	for (i = 0; i < src->len; i++)
		if (vrp_is_new(dst, &src->array[i]))
			vrps_add(dst, &src->array[i]);
}

static void
copy_vrps(struct vrp **dst, struct vrp *src, unsigned int len)
{
	struct vrp *tmp;
	tmp = realloc(*dst, len * sizeof(struct vrp));
	if (tmp == NULL) {
		err(-ENOMEM, "Couldn't copy VRPs");
		return;
	}
	*dst = tmp;
	*dst = memcpy(*dst, src, len * sizeof(struct vrp));
}

/*
 * Get the number of updates from serial START_SERIAL to END_SERIAL, set them
 * at RESULT.
 *
 * Return 0 if no updates are available or couldn't be calculated with the
 * received values.
 */
unsigned int
get_vrps_delta(u_int32_t *start_serial, u_int32_t *end_serial,
    struct vrp **result)
{
	struct delta **delta1;
	struct vrps summary;

	/* No data */
	if (state.base_db->vrps.len == 0)
		return 0;

	/* NULL start? Send the last version, there's no need to iterate DB */
	if (start_serial == NULL) {
		copy_vrps(result, state.base_db->vrps.array,
		    state.base_db->vrps.len);
		return state.base_db->vrps.len;
	}

	/* Apparently nothing to return */
	if (*start_serial >= *end_serial)
		return 0;

	/* Get the delta corresponding to the serials */
	vrps_init(&summary);
	ARRAYLIST_FOREACH(state.deltas_db, delta1) {
		if ((*delta1)->serial > *start_serial)
			add_vrps_filtered(&summary, &(*delta1)->vrps);
		if ((*delta1)->serial == *end_serial)
			break;
	}

	copy_vrps(result, summary.array, summary.len);
	vrps_cleanup(&summary, vrp_destroy);
	return summary.len;
}

void
set_vrps_last_modified_date(time_t new_date)
{
	state.last_modified_date = new_date;
}

u_int32_t
get_last_serial_number(void)
{
	return state.current_serial - 1;
}

u_int16_t
get_current_session_id(u_int8_t rtr_version)
{
	if (rtr_version == 1)
		return state.v1_session_id;
	return state.v0_session_id;
}

time_t
get_vrps_last_modified_date(void)
{
	return state.last_modified_date;
}
