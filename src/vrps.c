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

ARRAY_LIST(deltasdb, struct delta)

struct state {
	/** The current valid ROAs, freshly loaded from the file */
	struct delta base_db;
	/** ROA changes over time */
	struct deltasdb deltas_db;
	u_int32_t current_serial;
	u_int16_t v0_session_id;
	u_int16_t v1_session_id;
	time_t last_modified_date;
} state;

static int
delta_init(struct delta *delta)
{
	return vrps_init(&delta->vrps);
}

static void
vrp_destroy(struct vrp *vrp)
{
	/* Didn't allocate something, so do nothing */
}

static void
delta_destroy(struct delta *delta)
{
	vrps_cleanup(&delta->vrps, vrp_destroy);
}

int
deltas_db_init(void)
{
	int error, shift;

	error = delta_init(&state.base_db);
	if (error){
		warnx("Delta base DB couldn't be initialized");
		return error;
	}

	error = deltasdb_init(&state.deltas_db);
	if (error) {
		warnx("Deltas DB couldn't be initialized");
		delta_destroy(&state.base_db);
		return error;
	}

	/*
	 * Use the same start serial, the session ID will avoid
	 * "desynchronization" (more at RFC 6810 'Glossary' and
	 * 'Fields of a PDU')
	 */
	state.current_serial = START_SERIAL;

	/* Get the bits that'll fit in session_id */
	shift = sizeof(time_t) - sizeof(state.v0_session_id);
	state.v0_session_id = (u_int16_t)((time(NULL) << shift) >> shift);
	/* Minus 1 to prevent same ID */
	state.v1_session_id = state.v0_session_id - 1;

	return 0;
}

static void
init_vrp (struct vrp *vrp, u_int32_t asn, u_int8_t prefix_length,
    u_int8_t max_prefix_length)
{
	vrp->asn = asn;
	vrp->prefix_length = prefix_length;
	vrp->max_prefix_length = max_prefix_length;
	/* Set as ANNOUNCEMENT by default */
	vrp->flags = FLAG_ANNOUNCEMENT;
}

struct vrp
create_vrp4(u_int32_t asn, struct in_addr ipv4_prefix, u_int8_t prefix_length,
    u_int8_t max_prefix_length)
{
	struct vrp result;

	init_vrp(&result, asn, prefix_length, max_prefix_length);
	result.ipv4_prefix = ipv4_prefix;
	result.in_addr_len = INET_ADDRSTRLEN;

	return result;
}

struct vrp
create_vrp6(u_int32_t asn, struct in6_addr ipv6_prefix, u_int8_t prefix_length,
    u_int8_t max_prefix_length)
{
	struct vrp result;

	init_vrp(&result, asn, prefix_length, max_prefix_length);
	result.ipv6_prefix = ipv6_prefix;
	result.in_addr_len = INET6_ADDRSTRLEN;

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

static int
delta_add_vrp(struct delta *delta, struct vrp *vrp)
{
	return vrps_add(&delta->vrps, vrp);
}

static int
delta_summary(struct delta *base_delta, struct delta *result)
{
	struct vrps *base, *search_list;
	struct vrp *cursor;
	int error;

	/*
	 * Note: Don't fix this function yet.
	 * I realize why you implemented it this way, and I'm trying to come up
	 * with a more efficient algorithm.
	 */

	error = delta_init(result);
	if (error)
		return error;

	result->serial = base_delta->serial;
	/* First check for announcements */
	base = &base_delta->vrps;
	search_list = &state.base_db.vrps;
	ARRAYLIST_FOREACH(base, cursor)
		if (vrp_is_new(search_list, cursor)) {
			cursor->flags = FLAG_ANNOUNCEMENT;
			error = delta_add_vrp(result, cursor);
			if (error) {
				warnx("Couldn't add announcement to summary");
				return error;
			}
		}

	/* Now for withdrawals */
	base = &state.base_db.vrps;
	search_list = &base_delta->vrps;
	ARRAYLIST_FOREACH(base, cursor)
		if (vrp_is_new(search_list, cursor)) {
			cursor->flags = FLAG_WITHDRAWAL;
			error = delta_add_vrp(result, cursor);
			if (error) {
				warnx("Couldn't add withdrawal to summary");
				return error;
			}
		}

	return 0;
}

static int
deltas_db_add_delta(struct delta delta)
{
	struct delta summary;
	int result;

	result = 0;
	delta.serial = state.current_serial;
	/* Store only updates */
	if (delta.serial != START_SERIAL) {
		result = delta_summary(&delta, &summary);
		if (result != 0) {
			warnx("Error summarizing new delta");
			return result;
		}
		result = deltasdb_add(&state.deltas_db, &summary);
	}
	/* Don't set the base in case of error */
	if (result != 0) {
		warnx("Error persisting new delta");
		return result;
	}

	free(state.base_db.vrps.array);
	state.base_db = delta;
	state.current_serial++;
	return result;
}

static void
copy_vrps(struct vrp **dst, struct vrp *src, unsigned int len)
{
	struct vrp *tmp;
	tmp = realloc(*dst, len * sizeof(struct vrp));
	if (tmp == NULL) {
		warn("Couldn't copy VRPs");
		return;
	}
	*dst = tmp;
	memcpy(*dst, src, len * sizeof(struct vrp));
}

int
deltas_db_create_delta(struct vrp *array, unsigned int len)
{
	struct delta new_delta;
	int error;

	error = delta_init(&new_delta);
	if (error) {
		warnx("New Delta couldn't be initialized");
		return error;
	}

	copy_vrps(&new_delta.vrps.array, array, len);
	new_delta.vrps.len = len;
	new_delta.vrps.capacity = len * sizeof(struct vrp);

	error = deltas_db_add_delta(new_delta);
	if (error)
		return error;

	return 0;
}

void
deltas_db_destroy(void)
{

	delta_destroy(&state.base_db);
	deltasdb_cleanup(&state.deltas_db, delta_destroy);
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
	struct delta *delta;

	if (state.base_db.vrps.len == 0)
		return NO_DATA_AVAILABLE;

	/* No serial to match, and there's data at DB */
	if (serial == NULL)
		return DIFF_AVAILABLE;

	/* Is the last version? */
	if (*serial == state.base_db.serial)
		return NO_DIFF;

	/* Get the delta corresponding to the serial */
	ARRAYLIST_FOREACH(&state.deltas_db, delta) {
		if (delta->serial == *serial)
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
	struct vrp *ptr;
	for (ptr = src->array; (ptr - src->array) < src->len; ptr++)
		if (vrp_is_new(dst, ptr))
			vrps_add(dst, ptr);
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
	struct delta *delta1;
	struct vrps summary;

	/* No data */
	if (state.base_db.vrps.len == 0)
		return 0;

	/* NULL start? Send the last version, there's no need to iterate DB */
	if (start_serial == NULL) {
		copy_vrps(result, state.base_db.vrps.array,
		    state.base_db.vrps.len);
		return state.base_db.vrps.len;
	}

	/* Apparently nothing to return */
	if (*start_serial >= *end_serial)
		return 0;

	/* Get the delta corresponding to the serials */
	vrps_init(&summary);
	ARRAYLIST_FOREACH(&state.deltas_db, delta1) {
		if (delta1->serial > *start_serial)
			add_vrps_filtered(&summary, &delta1->vrps);
		if (delta1->serial == *end_serial)
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
