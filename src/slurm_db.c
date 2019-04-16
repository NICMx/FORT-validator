#include "slurm_db.h"

#include <stdbool.h>
#include <string.h>
#include "array_list.h"

ARRAY_LIST(al_filter_prefix, struct slurm_prefix)
ARRAY_LIST(al_assertion_prefix, struct slurm_prefix)
ARRAY_LIST(al_filter_bgpsec, struct slurm_bgpsec)
ARRAY_LIST(al_assertion_bgpsec, struct slurm_bgpsec)

struct arraylist_db {
	struct al_filter_prefix filter_pfx_al;
	struct al_assertion_prefix assertion_pfx_al;
	struct al_filter_bgpsec filter_bgps_al;
	struct al_assertion_bgpsec assertion_bgps_al;
} array_lists_db;

#define LOCATE_FUNCS(name, type, array_list, equal_cb, filter)		\
	static type *							\
	name##_locate(array_list *base, type *obj)			\
	{								\
		type *cursor;						\
									\
		ARRAYLIST_FOREACH(base, cursor)				\
			if (equal_cb(cursor, obj, filter))		\
				return cursor;				\
									\
		return NULL;						\
	}								\
									\
	static bool							\
	name##_exists(array_list *base, type *obj)			\
	{								\
		return name##_locate(base, obj) != NULL;		\
	}

int
slurm_db_init(void)
{
	al_filter_prefix_init(&array_lists_db.filter_pfx_al);
	al_assertion_prefix_init(&array_lists_db.assertion_pfx_al);
	al_filter_bgpsec_init(&array_lists_db.filter_bgps_al);
	al_assertion_bgpsec_init(&array_lists_db.assertion_bgps_al);

	return 0;
}

static bool
prefix_filtered_by(struct slurm_prefix *prefix, struct slurm_prefix *filter)
{
	/* Both have ASN */
	if ((prefix->data_flag & SLURM_COM_FLAG_ASN) > 0 &&
	    (filter->data_flag & SLURM_COM_FLAG_ASN) > 0)
		return prefix->asn == filter->asn;

	/* Both have a prefix of the same type */
	if ((prefix->data_flag & SLURM_PFX_FLAG_PREFIX) > 0 &&
	    (filter->data_flag & SLURM_PFX_FLAG_PREFIX) > 0 &&
	    prefix->addr_fam == filter->addr_fam &&
	    prefix->prefix_length == filter->prefix_length)
		return ((prefix->addr_fam == AF_INET &&
		    prefix->ipv4_prefix.s_addr == filter->ipv4_prefix.s_addr) ||
		    (prefix->addr_fam == AF_INET6 &&
		    IN6_ARE_ADDR_EQUAL(prefix->ipv6_prefix.s6_addr32,
		    filter->ipv6_prefix.s6_addr32)));

	return false;
}

static bool
prefix_equal(struct slurm_prefix *left, struct slurm_prefix *right,
    bool filter)
{
	bool equal;

	/* Ignore the comments */
	if ((left->data_flag & ~SLURM_COM_FLAG_COMMENT) !=
	    (right->data_flag & ~SLURM_COM_FLAG_COMMENT))
		return filter && prefix_filtered_by(left, right);

	/* It has the same data, compare it */
	equal = true;
	if ((left->data_flag & SLURM_COM_FLAG_ASN) > 0)
		equal = equal && left->asn == right->asn;

	if ((left->data_flag & SLURM_PFX_FLAG_PREFIX) > 0)
		equal = equal && left->prefix_length == right->prefix_length
		    && left->addr_fam == right->addr_fam
		    && ((left->addr_fam == AF_INET
		    && left->ipv4_prefix.s_addr == right->ipv4_prefix.s_addr)
		    || (left->addr_fam == AF_INET6
		    && IN6_ARE_ADDR_EQUAL(left->ipv6_prefix.s6_addr32,
		    right->ipv6_prefix.s6_addr32)));

	if ((left->data_flag & SLURM_PFX_FLAG_MAX_LENGTH) > 0)
		equal = equal &&
		    ((left->data_flag & SLURM_PFX_FLAG_MAX_LENGTH) > 0) &&
		    left->max_prefix_length == right->max_prefix_length;

	return equal;
}

static bool
bgpsec_filtered_by(struct slurm_bgpsec *bgpsec, struct slurm_bgpsec *filter)
{
	/* Both have ASN */
	if ((bgpsec->data_flag & SLURM_COM_FLAG_ASN) > 0 &&
	    (filter->data_flag & SLURM_COM_FLAG_ASN) > 0)
		return bgpsec->asn == filter->asn;

	/* Both have a SKI */
	if ((bgpsec->data_flag & SLURM_BGPS_FLAG_SKI) > 0 &&
	    (filter->data_flag & SLURM_BGPS_FLAG_SKI) > 0 &&
	    bgpsec->ski_len == filter->ski_len)
		return memcmp(bgpsec->ski, filter->ski, bgpsec->ski_len) == 0;

	return false;
}

static bool
bgpsec_equal(struct slurm_bgpsec *left, struct slurm_bgpsec *right,
    bool filter)
{
	bool equal;

	/* Ignore the comments */
	if ((left->data_flag & ~SLURM_COM_FLAG_COMMENT) !=
	    (right->data_flag & ~SLURM_COM_FLAG_COMMENT))
		return filter && bgpsec_filtered_by(left, right);

	/* It has the same data, compare it */
	equal = true;
	if ((left->data_flag & SLURM_COM_FLAG_ASN) > 0)
		equal = equal && left->asn == right->asn;

	if ((left->data_flag & SLURM_BGPS_FLAG_SKI) > 0)
		equal = equal && left->ski_len == right->ski_len &&
		    memcmp(left->ski, right->ski, left->ski_len) == 0;

	if ((left->data_flag & SLURM_BGPS_FLAG_ROUTER_KEY) > 0)
		equal = equal &&
		    left->router_public_key_len ==
		    right->router_public_key_len &&
		    memcmp(left->router_public_key, right->router_public_key,
		    left->router_public_key_len) == 0;

	return equal;
}

LOCATE_FUNCS(prefix_filter, struct slurm_prefix, struct al_filter_prefix,
    prefix_equal, true)
LOCATE_FUNCS(bgpsec_filter, struct slurm_bgpsec, struct al_filter_bgpsec,
    bgpsec_equal, true)
LOCATE_FUNCS(prefix_assertion, struct slurm_prefix, struct al_assertion_prefix,
    prefix_equal, false)
LOCATE_FUNCS(bgpsec_assertion, struct slurm_bgpsec, struct al_assertion_bgpsec,
    bgpsec_equal, false)

/*
 * Try to persist the @prefix filter, if it already exists or is covered
 * by another filter, then the error -EEXIST is returned; otherwise, returns
 * the result of persisting the @prefix.
 */
int
slurm_db_add_prefix_filter(struct slurm_prefix *prefix)
{
	if (prefix_filter_exists(&array_lists_db.filter_pfx_al, prefix))
		return -EEXIST;

	return al_filter_prefix_add(&array_lists_db.filter_pfx_al, prefix);
}

/*
 * Try to persist the @prefix assertion, if it already exists, then the error
 * -EEXIST is returned; otherwise, returns the result of persisting the
 * @prefix.
 */
int
slurm_db_add_prefix_assertion(struct slurm_prefix *prefix)
{
	if (prefix_assertion_exists(&array_lists_db.assertion_pfx_al, prefix))
		return -EEXIST;

	return al_assertion_prefix_add(&array_lists_db.assertion_pfx_al,
	    prefix);
}

/*
 * Try to persist the @bgpsec filter, if it already exists or is covered
 * by another filter, then the error -EEXIST is returned; otherwise, returns
 * the result of persisting the @bgpsec.
 */
int
slurm_db_add_bgpsec_filter(struct slurm_bgpsec *bgpsec)
{
	if (bgpsec_filter_exists(&array_lists_db.filter_bgps_al, bgpsec))
		return -EEXIST;

	return al_filter_bgpsec_add(&array_lists_db.filter_bgps_al, bgpsec);
}

/*
 * Try to persist the @bgpsec assertion, if it already exists, then the error
 * -EEXIST is returned; otherwise, returns the result of persisting the
 * @bgpsec.
 */
int
slurm_db_add_bgpsec_assertion(struct slurm_bgpsec *bgpsec)
{
	if (bgpsec_assertion_exists(&array_lists_db.assertion_bgps_al, bgpsec))
		return -EEXIST;

	return al_assertion_bgpsec_add(&array_lists_db.assertion_bgps_al,
	    bgpsec);
}

static void
clean_slurm_prefix(struct slurm_prefix *prefix)
{
	if ((prefix->data_flag & SLURM_COM_FLAG_COMMENT) > 0)
		free((void *)prefix->comment);
}

static void
clean_slurm_bgpsec(struct slurm_bgpsec *bgpsec)
{
	if ((bgpsec->data_flag & SLURM_BGPS_FLAG_SKI) > 0)
		free(bgpsec->ski);
	if ((bgpsec->data_flag & SLURM_BGPS_FLAG_ROUTER_KEY) > 0)
		free(bgpsec->router_public_key);
	if ((bgpsec->data_flag & SLURM_COM_FLAG_COMMENT) > 0)
		free((void *)bgpsec->comment);
}

void
slurm_db_cleanup(void)
{
	al_filter_prefix_cleanup(&array_lists_db.filter_pfx_al,
	    clean_slurm_prefix);
	al_filter_bgpsec_cleanup(&array_lists_db.filter_bgps_al,
	    clean_slurm_bgpsec);
	al_assertion_prefix_cleanup(&array_lists_db.assertion_pfx_al,
	    clean_slurm_prefix);
	al_assertion_bgpsec_cleanup(&array_lists_db.assertion_bgps_al,
	    clean_slurm_bgpsec);
}
