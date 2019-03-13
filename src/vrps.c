#include "vrps.h"

#include "array_list.h"

#define FLAG_WITHDRAWAL		0
#define FLAG_ANNOUNCEMENT	1

ARRAY_LIST(vrps, struct vrp)

struct delta {
	u_int32_t serial;
	struct vrps vrps;
};

ARRAY_LIST(deltasdb, struct delta)

struct state {
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
	state.current_serial = 0;
	/* The downcast takes the LSBs */
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

int
deltas_db_add_delta(struct delta *delta)
{
	delta->serial = state.current_serial++;
	return deltasdb_add(state.deltas_db, delta);
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
delta_destroy(struct delta *delta)
{
	/* Nothing else to free yet */
	vrps_cleanup(&delta->vrps, vrp_destroy);
}

void
deltas_db_destroy(void)
{
	deltasdb_cleanup(state.deltas_db, delta_destroy);
	free(state.deltas_db);
}

static unsigned int
get_delta_diff(struct delta *start_delta, struct delta *end_delta,
    struct vrp **result)
{
	/* TODO Do some magic to get the diff */
	*result = state.deltas_db->array[state.deltas_db->len - 1].vrps.array;
	return state.deltas_db->array[state.deltas_db->len - 1].vrps.len;
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
 *  DIFF_AVAILABLE -> There are differences between SERIAL and the last DB serial
 */
int
deltas_db_status(u_int32_t *serial)
{
	struct deltasdb *deltas_db;
	struct delta *delta;

	deltas_db = state.deltas_db;
	if (deltas_db->len == 0)
		return NO_DATA_AVAILABLE;

	// No serial to match, and there's data at DB
	if (serial == NULL)
		return DIFF_AVAILABLE;

	/* Is the last version? */
	if (*serial == deltas_db->array[deltas_db->len-1].serial)
		return NO_DIFF;

	/* Get the delta corresponding to the serial */
	ARRAYLIST_FOREACH(deltas_db, delta) {
		if (delta->serial == *serial)
			return DIFF_AVAILABLE;
	}

	/* Reached end, diff can't be determined */
	return DIFF_UNDETERMINED;
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
	struct deltasdb *deltas_db;
	struct delta *delta0, *delta1;

	deltas_db = state.deltas_db;
	/* No data */
	if (deltas_db->len == 0)
		return 0;

	/* NULL start? Send the last version, there's no need to iterate DB */
	if (start_serial == NULL) {
		*result = deltas_db->array[deltas_db->len - 1].vrps.array;
		return deltas_db->array[deltas_db->len - 1].vrps.len;
		/* TODO Send all data as ANNOUNCEMENTS */
	}

	/* Apparently nothing to return */
	if (*start_serial >= *end_serial)
		return 0;

	/* Get the delta corresponding to the serials */
	delta0 = NULL;
	ARRAYLIST_FOREACH(deltas_db, delta1) {
		if (delta1->serial == *start_serial)
			delta0 = delta1;
		if (delta1->serial == *end_serial)
			break;
	}

	/* Reached end or no delta0 found, diff can't be determined, send error */
	if (delta1 == NULL || delta0 == NULL)
		return 0;

	return get_delta_diff(delta0, delta1, result);
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
