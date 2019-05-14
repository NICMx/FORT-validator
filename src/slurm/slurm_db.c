#include "slurm_db.h"

#include <string.h>

#include "data_structure/array_list.h"

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

void
slurm_db_init(void)
{
	al_filter_prefix_init(&array_lists_db.filter_pfx_al);
	al_assertion_prefix_init(&array_lists_db.assertion_pfx_al);
	al_filter_bgpsec_init(&array_lists_db.filter_bgps_al);
	al_assertion_bgpsec_init(&array_lists_db.assertion_bgps_al);
}

static bool
prefix_filtered_by(struct slurm_prefix *filter, struct slurm_prefix *prefix)
{
	struct vrp *filter_vrp, *prefix_vrp;

	filter_vrp = &filter->vrp;
	prefix_vrp = &prefix->vrp;

	/* Both have ASN */
	if ((filter->data_flag & SLURM_COM_FLAG_ASN) > 0 &&
	    (prefix->data_flag & SLURM_COM_FLAG_ASN) > 0)
		return filter_vrp->asn == prefix_vrp->asn;

	/* Both have a prefix of the same type */
	if ((filter->data_flag & SLURM_PFX_FLAG_PREFIX) > 0 &&
	    (prefix->data_flag & SLURM_PFX_FLAG_PREFIX) > 0 &&
	    filter_vrp->addr_fam == prefix_vrp->addr_fam &&
	    filter_vrp->prefix_length == prefix_vrp->prefix_length)
		return ((filter_vrp->addr_fam == AF_INET &&
		    filter_vrp->prefix.v4.s_addr == prefix_vrp->prefix.v4.s_addr) ||
		    (filter_vrp->addr_fam == AF_INET6 &&
		    IN6_ARE_ADDR_EQUAL(filter_vrp->prefix.v6.s6_addr32,
		    prefix_vrp->prefix.v6.s6_addr32)));

	return false;
}

static bool
prefix_equal(struct slurm_prefix *left, struct slurm_prefix *right,
    bool filter)
{
	struct vrp *left_vrp, *right_vrp;
	bool equal;

	left_vrp = &left->vrp;
	right_vrp = &right->vrp;

	/* Ignore the comments */
	if ((left->data_flag & ~SLURM_COM_FLAG_COMMENT) !=
	    (right->data_flag & ~SLURM_COM_FLAG_COMMENT))
		return filter && prefix_filtered_by(left, right);

	/* It has the same data, compare it */
	equal = true;
	if ((left->data_flag & SLURM_COM_FLAG_ASN) > 0)
		equal = equal && left_vrp->asn == right_vrp->asn;

	if ((left->data_flag & SLURM_PFX_FLAG_PREFIX) > 0)
		equal = equal
		    && left_vrp->prefix_length == right_vrp->prefix_length
		    && left_vrp->addr_fam == right_vrp->addr_fam
		    && ((left_vrp->addr_fam == AF_INET
		    && left_vrp->prefix.v4.s_addr == right_vrp->prefix.v4.s_addr)
		    || (left_vrp->addr_fam == AF_INET6
		    && IN6_ARE_ADDR_EQUAL(left_vrp->prefix.v6.s6_addr32,
		    right_vrp->prefix.v6.s6_addr32)));

	if ((left->data_flag & SLURM_PFX_FLAG_MAX_LENGTH) > 0)
		equal = equal &&
		    ((left->data_flag & SLURM_PFX_FLAG_MAX_LENGTH) > 0) &&
		    left_vrp->max_prefix_length == right_vrp->max_prefix_length;

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

#define ADD_FUNCS(name, type, list_name, db_list, equal_cb, filter)	\
	static type *							\
	name##_locate(type *obj)					\
	{								\
		type *cursor;						\
									\
		ARRAYLIST_FOREACH(db_list, cursor)			\
			if (equal_cb(cursor, obj, filter))		\
				return cursor;				\
									\
		return NULL;						\
	}								\
									\
	static bool							\
	name##_exists(type *obj)					\
	{								\
		return name##_locate(obj) != NULL;			\
	}								\
									\
	int								\
	slurm_db_add_##name(type *elem) {				\
		if (name##_exists(elem))				\
			return -EEXIST;					\
		return list_name##_add(db_list, elem);			\
	}

ADD_FUNCS(prefix_filter, struct slurm_prefix, al_filter_prefix,
    &array_lists_db.filter_pfx_al, prefix_equal, true)
ADD_FUNCS(bgpsec_filter, struct slurm_bgpsec, al_filter_bgpsec,
    &array_lists_db.filter_bgps_al, bgpsec_equal, true)
ADD_FUNCS(prefix_assertion, struct slurm_prefix, al_assertion_prefix,
    &array_lists_db.assertion_pfx_al, prefix_equal, false)
ADD_FUNCS(bgpsec_assertion, struct slurm_bgpsec, al_assertion_bgpsec,
    &array_lists_db.assertion_bgps_al, bgpsec_equal, false)

bool
slurm_db_vrp_is_filtered(struct vrp const *vrp)
{
	struct slurm_prefix slurm_prefix;

	slurm_prefix.data_flag = SLURM_COM_FLAG_ASN | SLURM_PFX_FLAG_PREFIX
	    | SLURM_PFX_FLAG_MAX_LENGTH;
	slurm_prefix.vrp = *vrp;
	slurm_prefix.comment = NULL;

	return prefix_filter_exists(&slurm_prefix);
}

int
slurm_db_foreach_assertion_prefix(assertion_pfx_foreach_cb cb, void *arg)
{
	struct slurm_prefix *cursor;
	int error;

	ARRAYLIST_FOREACH(&array_lists_db.assertion_pfx_al, cursor) {
		error = cb(cursor, arg);
		if (error)
			return error;
	}

	return 0;
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
