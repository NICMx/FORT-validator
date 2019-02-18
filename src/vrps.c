#include "vrps.h"

#include <netinet/in.h>
#include <stdlib.h>
#include "array_list.h"

struct vrp {
	u_int32_t	asn;
	union {
		struct	in_addr ipv4_prefix;
		struct	in6_addr ipv6_prefix;
	};
	u_int8_t	prefix_length;
	u_int8_t	max_prefix_length;
};

ARRAY_LIST(delta, struct vrp)
ARRAY_LIST(deltasdb, struct delta)

struct deltasdb db;

int
deltas_db_init(void)
{
	int error;

	error = deltasdb_init(&db);
	if (error) {
		err(error, "Deltas DB couldn't be allocated");
		return error;
	}

	return 0;
}

struct delta *
create_delta(void)
{
	struct delta *result;

	result = malloc(sizeof(struct delta));
	if (result == NULL)
		goto fail1;

	if (delta_init(result) != 0)
		goto fail2;

	return result;
fail2:
	free(result);
fail1:
	return NULL;
}

static struct vrp *
create_vrp (u_int32_t asn, u_int8_t prefix_length, u_int8_t max_prefix_length) {
	struct vrp *result;

	result = malloc(sizeof(struct vrp));
	if (result == NULL)
		return NULL;

	result->asn = asn;
	result->prefix_length = prefix_length;
	result->max_prefix_length = max_prefix_length;

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

	return result;
}

int
deltas_db_add_delta(struct delta *delta)
{
	return deltasdb_add(&db, delta);
}

int
delta_add_vrp(struct delta *delta, struct vrp *vrp)
{
	return delta_add(delta, vrp);
}

void
vrp_destroy(struct vrp *vrp)
{
	free(vrp);
}

void
delta_destroy(struct delta *delta)
{
	delta_cleanup(delta, vrp_destroy);
	free(delta);
}

void
deltas_db_destroy()
{
	deltasdb_cleanup(&db, delta_destroy);
}
