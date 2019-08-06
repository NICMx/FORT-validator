#include "slurm_db.h"

#include <string.h>
#include <sys/types.h> /* AF_INET, AF_INET6 (needed in OpenBSD) */
#include <sys/socket.h> /* AF_INET, AF_INET6 (needed in OpenBSD) */

#include "data_structure/array_list.h"

struct slurm_prefix_ctx {
	struct slurm_prefix element;
	int ctx;
};

struct slurm_bgpsec_ctx {
	struct slurm_bgpsec element;
	int ctx;
};

ARRAY_LIST(al_filter_prefix, struct slurm_prefix_ctx)
ARRAY_LIST(al_assertion_prefix, struct slurm_prefix_ctx)
ARRAY_LIST(al_filter_bgpsec, struct slurm_bgpsec_ctx)
ARRAY_LIST(al_assertion_bgpsec, struct slurm_bgpsec_ctx)

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
		return VRP_ASN_EQ(filter_vrp, prefix_vrp);

	/* Both have a prefix of the same type */
	if ((filter->data_flag & SLURM_PFX_FLAG_PREFIX) > 0 &&
	    (prefix->data_flag & SLURM_PFX_FLAG_PREFIX) > 0)
		return VRP_PREFIX_EQ(filter_vrp, prefix_vrp);

	return false;
}

static bool
prefix_contained(struct slurm_prefix_ctx *left_ctx, struct slurm_prefix *right,
    int ctx)
{
	struct slurm_prefix *left;
	struct vrp *left_vrp, *right_vrp;

	/*
	 * rfc8416#section-4.2:
	 * 1. There may be conflicting changes to ROA Prefix Assertions if an
	 *    IP address X and distinct SLURM files Y and Z exist such that X
	 *    is contained by any prefix in any "prefixAssertions" or
	 *    "prefixFilters" in file Y and X is contained by any prefix in any
	 *    "prefixAssertions" or "prefixFilters" in file Z.
	 *
	 * A negative @ctx or an equal context will avoid this check.
	 */
	if (ctx < 0 || ctx == left_ctx->ctx)
		return false;

	left = &left_ctx->element;
	left_vrp = &left->vrp;
	right_vrp = &right->vrp;

	return (left->data_flag & SLURM_PFX_FLAG_PREFIX) > 0 &&
	    (right->data_flag & SLURM_PFX_FLAG_PREFIX) > 0 &&
	    VRP_PREFIX_EQ(left_vrp, right_vrp);
}

static bool
prefix_equal(struct slurm_prefix_ctx *left_ctx, struct slurm_prefix *right,
    int ctx, bool filter)
{
	struct slurm_prefix *left;
	struct vrp *left_vrp, *right_vrp;
	bool equal;

	left = &left_ctx->element;
	left_vrp = &left->vrp;
	right_vrp = &right->vrp;

	if (prefix_contained(left_ctx, right, ctx))
		return true;

	/* Ignore the comments */
	if ((left->data_flag & ~SLURM_COM_FLAG_COMMENT) !=
	    (right->data_flag & ~SLURM_COM_FLAG_COMMENT))
		return filter && prefix_filtered_by(left, right);

	/* It has the same data, compare it */
	equal = true;
	if ((left->data_flag & SLURM_COM_FLAG_ASN) > 0)
		equal = equal && VRP_ASN_EQ(left_vrp, right_vrp);

	if ((left->data_flag & SLURM_PFX_FLAG_PREFIX) > 0)
		equal = equal && VRP_PREFIX_EQ(left_vrp, right_vrp);

	if ((left->data_flag & SLURM_PFX_FLAG_MAX_LENGTH) > 0)
		equal = equal &&
		    ((left->data_flag & SLURM_PFX_FLAG_MAX_LENGTH) > 0) &&
		    VRP_MAX_PREFIX_LEN_EQ(left_vrp, right_vrp);

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
bgpsec_contained(struct slurm_bgpsec_ctx *left_ctx, struct slurm_bgpsec *right,
    int ctx)
{
	struct slurm_bgpsec *left;

	/*
	 * rfc8416#section-4.2:
	 * 2. There may be conflicting changes to BGPsec Assertions if an ASN X
	 *    and distinct SLURM files Y and Z exist such that X is used in any
	 *    "bgpsecAssertions" or "bgpsecFilters" in file Y and X is used in
	 *    any "bgpsecAssertions" or "bgpsecFilters" in file Z.
	 *
	 * A negative @ctx or an equal context will avoid this check.
	 */
	if (ctx < 0 || ctx == left_ctx->ctx)
		return false;

	left = &left_ctx->element;

	return (left->data_flag & SLURM_COM_FLAG_ASN) > 0 &&
	    (right->data_flag & SLURM_COM_FLAG_ASN) > 0 &&
	    left->asn == right->asn;
}

static bool
bgpsec_equal(struct slurm_bgpsec_ctx *left_ctx, struct slurm_bgpsec *right,
    int ctx, bool filter)
{
	struct slurm_bgpsec *left;
	bool equal;

	left = &left_ctx->element;

	if (bgpsec_contained(left_ctx, right, ctx))
		return true;

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

#define ADD_FUNCS(name, type, list_name, db_list, db_alt_list, equal_cb,\
    cont_cb, filter)							\
	static type *							\
	name##_locate(type *obj, int ctx)				\
	{								\
		type##_ctx *cursor;					\
		array_index i;						\
									\
		ARRAYLIST_FOREACH(db_list, cursor, i)			\
			if (equal_cb(cursor, obj, ctx, filter))		\
				return &cursor->element;		\
									\
		ARRAYLIST_FOREACH(db_alt_list, cursor, i)		\
			if (cont_cb(cursor, obj, ctx))			\
				return &cursor->element;		\
									\
		return NULL;						\
	}								\
									\
	static bool							\
	name##_exists(type *obj, int ctx)				\
	{								\
		return name##_locate(obj, ctx) != NULL;			\
	}								\
									\
	int								\
	slurm_db_add_##name(type *elem, int ctx) {			\
		type##_ctx new_elem;					\
		if (name##_exists(elem, ctx))				\
			return -EEXIST;					\
		new_elem.element = *elem;				\
		new_elem.ctx = ctx;					\
		return list_name##_add(db_list, &new_elem);		\
	}

ADD_FUNCS(prefix_filter, struct slurm_prefix, al_filter_prefix,
    &array_lists_db.filter_pfx_al, &array_lists_db.assertion_pfx_al,
    prefix_equal, prefix_contained, true)
ADD_FUNCS(bgpsec_filter, struct slurm_bgpsec, al_filter_bgpsec,
    &array_lists_db.filter_bgps_al, &array_lists_db.assertion_bgps_al,
    bgpsec_equal, bgpsec_contained, true)
ADD_FUNCS(prefix_assertion, struct slurm_prefix, al_assertion_prefix,
    &array_lists_db.assertion_pfx_al, &array_lists_db.filter_pfx_al,
    prefix_equal, prefix_contained, false)
ADD_FUNCS(bgpsec_assertion, struct slurm_bgpsec, al_assertion_bgpsec,
    &array_lists_db.assertion_bgps_al, &array_lists_db.filter_bgps_al,
    bgpsec_equal, bgpsec_contained, false)

bool
slurm_db_vrp_is_filtered(struct vrp const *vrp)
{
	struct slurm_prefix slurm_prefix;

	slurm_prefix.data_flag = SLURM_COM_FLAG_ASN | SLURM_PFX_FLAG_PREFIX
	    | SLURM_PFX_FLAG_MAX_LENGTH;
	slurm_prefix.vrp = *vrp;
	slurm_prefix.comment = NULL;

	return prefix_filter_exists(&slurm_prefix, -1);
}

int
slurm_db_foreach_assertion_prefix(assertion_pfx_foreach_cb cb, void *arg)
{
	struct slurm_prefix_ctx *cursor;
	array_index i;
	int error;

	ARRAYLIST_FOREACH(&array_lists_db.assertion_pfx_al, cursor, i) {
		error = cb(&cursor->element, arg);
		if (error)
			return error;
	}

	return 0;
}

static void
clean_slurm_prefix(struct slurm_prefix_ctx *prefix)
{
	if ((prefix->element.data_flag & SLURM_COM_FLAG_COMMENT) > 0)
		free(prefix->element.comment);
}

static void
clean_slurm_bgpsec(struct slurm_bgpsec_ctx *bgpsec)
{
	if ((bgpsec->element.data_flag & SLURM_BGPS_FLAG_SKI) > 0)
		free(bgpsec->element.ski);
	if ((bgpsec->element.data_flag & SLURM_BGPS_FLAG_ROUTER_KEY) > 0)
		free(bgpsec->element.router_public_key);
	if ((bgpsec->element.data_flag & SLURM_COM_FLAG_COMMENT) > 0)
		free(bgpsec->element.comment);
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
