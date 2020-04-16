#include "db_slurm.h"

#include <string.h>
#include <time.h>
#include <arpa/inet.h>

#include "crypto/base64.h"
#include "data_structure/array_list.h"
#include "object/router_key.h"
#include "common.h"

struct slurm_prefix_ctx {
	struct slurm_prefix element;
	int ctx;
};

struct slurm_bgpsec_ctx {
	struct slurm_bgpsec element;
	int ctx;
};

STATIC_ARRAY_LIST(al_filter_prefix, struct slurm_prefix_ctx)
STATIC_ARRAY_LIST(al_assertion_prefix, struct slurm_prefix_ctx)
STATIC_ARRAY_LIST(al_filter_bgpsec, struct slurm_bgpsec_ctx)
STATIC_ARRAY_LIST(al_assertion_bgpsec, struct slurm_bgpsec_ctx)

struct db_slurm {
	struct al_filter_prefix filter_pfx_al;
	struct al_assertion_prefix assertion_pfx_al;
	struct al_filter_bgpsec filter_bgps_al;
	struct al_assertion_bgpsec assertion_bgps_al;
	bool loaded_date_set;
	time_t loaded_date;
};

static char addr_buf[INET6_ADDRSTRLEN];

int
db_slurm_create(struct db_slurm **result)
{
	struct db_slurm *db;

	db = malloc(sizeof(struct db_slurm));
	if (db == NULL)
		return pr_enomem();

	/* Not ready yet (nor required yet) for multithreading */
	al_filter_prefix_init(&db->filter_pfx_al);
	al_assertion_prefix_init(&db->assertion_pfx_al);
	al_filter_bgpsec_init(&db->filter_bgps_al);
	al_assertion_bgpsec_init(&db->assertion_bgps_al);
	db->loaded_date_set = false;

	*result = db;
	return 0;
}

static bool
prefix_filtered_by(struct slurm_prefix *filter, struct slurm_prefix *prefix,
    bool exact_match)
{
	struct vrp *filter_vrp, *prefix_vrp;

	filter_vrp = &filter->vrp;
	prefix_vrp = &prefix->vrp;

	/* The filter has ASN and prefix */
	if (exact_match && (filter->data_flag & ~SLURM_COM_FLAG_COMMENT) ==
	    (SLURM_COM_FLAG_ASN | SLURM_PFX_FLAG_PREFIX))
		return VRP_ASN_EQ(filter_vrp, prefix_vrp) &&
		    VRP_PREFIX_COV(filter_vrp, prefix_vrp);

	/* Both have ASN */
	if ((filter->data_flag & SLURM_COM_FLAG_ASN) > 0 &&
	    (prefix->data_flag & SLURM_COM_FLAG_ASN) > 0)
		return VRP_ASN_EQ(filter_vrp, prefix_vrp);

	/* Both have a prefix of the same type */
	if ((filter->data_flag & SLURM_PFX_FLAG_PREFIX) > 0 &&
	    (prefix->data_flag & SLURM_PFX_FLAG_PREFIX) > 0)
		return VRP_PREFIX_COV(filter_vrp, prefix_vrp);

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
	    VRP_PREFIX_COV(left_vrp, right_vrp);
}

/*
 * @left_ctx is the prefix loaded from SLURM, @right is the VRP "masked" as a
 * slurm prefix
 */
static bool
prefix_equal(struct slurm_prefix_ctx *left_ctx, struct slurm_prefix *right,
    int ctx, bool filter, bool exact_match)
{
	struct slurm_prefix *left;
	struct vrp *left_vrp, *right_vrp;
	bool equal;

	left = &left_ctx->element;
	left_vrp = &left->vrp;
	right_vrp = &right->vrp;

	if (prefix_contained(left_ctx, right, ctx))
		return true;

	/*
	 * Ignore the comments, remember: FILTERS don't have the same data (no
	 * max_length is declared), while ASSERTIONS do.
	 */
	if ((left->data_flag & ~SLURM_COM_FLAG_COMMENT) !=
	    (right->data_flag & ~SLURM_COM_FLAG_COMMENT))
		return filter && prefix_filtered_by(left, right, exact_match);

	/* It has the same data, compare it */
	equal = true;
	if (equal && (left->data_flag & SLURM_COM_FLAG_ASN) > 0)
		equal = VRP_ASN_EQ(left_vrp, right_vrp);

	if (equal && (left->data_flag & SLURM_PFX_FLAG_PREFIX) > 0)
		equal = (filter ?
		    VRP_PREFIX_COV(left_vrp, right_vrp) :
		    VRP_PREFIX_EQ(left_vrp, right_vrp));

	if (equal && (left->data_flag & SLURM_PFX_FLAG_MAX_LENGTH) > 0)
		equal = VRP_MAX_PREFIX_LEN_EQ(left_vrp, right_vrp);

	return equal;
}

static bool
bgpsec_filtered_by(struct slurm_bgpsec *bgpsec, struct slurm_bgpsec *filter,
    bool exact_match)
{
	/* The filter has ASN and SKI */
	if (exact_match && (filter->data_flag & ~SLURM_COM_FLAG_COMMENT) ==
	    (SLURM_COM_FLAG_ASN | SLURM_BGPS_FLAG_SKI))
		return bgpsec->asn == filter->asn &&
		    memcmp(bgpsec->ski, filter->ski, RK_SKI_LEN) == 0;

	/* Both have ASN */
	if ((bgpsec->data_flag & SLURM_COM_FLAG_ASN) > 0 &&
	    (filter->data_flag & SLURM_COM_FLAG_ASN) > 0)
		return bgpsec->asn == filter->asn;

	/* Both have a SKI */
	if ((bgpsec->data_flag & SLURM_BGPS_FLAG_SKI) > 0 &&
	    (filter->data_flag & SLURM_BGPS_FLAG_SKI) > 0)
		return memcmp(bgpsec->ski, filter->ski, RK_SPKI_LEN) == 0;

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
    int ctx, bool filter, bool exact_filter)
{
	struct slurm_bgpsec *left;
	bool equal;

	left = &left_ctx->element;

	if (bgpsec_contained(left_ctx, right, ctx))
		return true;

	/* Ignore the comments */
	if ((left->data_flag & ~SLURM_COM_FLAG_COMMENT) !=
	    (right->data_flag & ~SLURM_COM_FLAG_COMMENT))
		return filter && bgpsec_filtered_by(left, right, exact_filter);

	/* It has the same data, compare it */
	equal = true;
	if (equal && (left->data_flag & SLURM_COM_FLAG_ASN) > 0)
		equal = left->asn == right->asn;

	if (equal && (left->data_flag & SLURM_BGPS_FLAG_SKI) > 0)
		equal = memcmp(left->ski, right->ski, RK_SKI_LEN) == 0;

	if (equal && (left->data_flag & SLURM_BGPS_FLAG_ROUTER_KEY) > 0)
		equal = memcmp(left->router_public_key,
		    right->router_public_key, RK_SPKI_LEN) == 0;

	return equal;
}

#define ADD_FUNCS(name, type, list_name, db_list, db_alt_list, equal_cb,\
    cont_cb, filter)							\
	static type *							\
	name##_locate(struct db_slurm *db, type *obj, bool flt, int ctx)\
	{								\
		type##_ctx *cursor;					\
		array_index i;						\
									\
		ARRAYLIST_FOREACH(&db->db_list, cursor, i)		\
			if (equal_cb(cursor, obj, ctx, filter, flt))	\
				return &cursor->element;		\
									\
		if (ctx < 0)						\
			return NULL; /* Avoid the next loop */		\
									\
		ARRAYLIST_FOREACH(&db->db_alt_list, cursor, i)	\
			if (cont_cb(cursor, obj, ctx))			\
				return &cursor->element;		\
									\
		return NULL;						\
	}								\
									\
	static bool							\
	name##_exists(struct db_slurm *db, type *obj, bool flt, int ctx)\
	{								\
		return name##_locate(db, obj, flt, ctx) != NULL;	\
	}								\
									\
	int								\
	db_slurm_add_##name(struct db_slurm *db, type *elem, int ctx)	\
	{								\
		type##_ctx new_elem;					\
		if (name##_exists(db, elem, !filter, ctx))		\
			return -EEXIST;					\
		new_elem.element = *elem;				\
		new_elem.ctx = ctx;					\
		return list_name##_add(&db->db_list, &new_elem);	\
	}

ADD_FUNCS(prefix_filter, struct slurm_prefix, al_filter_prefix, filter_pfx_al,
    assertion_pfx_al, prefix_equal, prefix_contained, true)
ADD_FUNCS(bgpsec_filter, struct slurm_bgpsec, al_filter_bgpsec, filter_bgps_al,
    assertion_bgps_al, bgpsec_equal, bgpsec_contained, true)
ADD_FUNCS(prefix_assertion, struct slurm_prefix, al_assertion_prefix,
    assertion_pfx_al, filter_pfx_al, prefix_equal, prefix_contained, false)
ADD_FUNCS(bgpsec_assertion, struct slurm_bgpsec, al_assertion_bgpsec,
    assertion_bgps_al, filter_bgps_al, bgpsec_equal, bgpsec_contained, false)

bool
db_slurm_vrp_is_filtered(struct db_slurm *db, struct vrp const *vrp)
{
	struct slurm_prefix slurm_prefix;

	slurm_prefix.data_flag = SLURM_COM_FLAG_ASN | SLURM_PFX_FLAG_PREFIX
	    | SLURM_PFX_FLAG_MAX_LENGTH;
	slurm_prefix.vrp = *vrp;

	return prefix_filter_exists(db, &slurm_prefix, true, -1);
}

#define ITERATE_LIST_FUNC(type, object, db_list)			\
	int								\
	db_slurm_foreach_##type##_##object(struct db_slurm *db,		\
	    object##_foreach_cb cb, void *arg)				\
	{								\
		struct slurm_##object##_ctx *cursor;			\
		array_index i;						\
		int error;						\
									\
		ARRAYLIST_FOREACH(&db->db_list, cursor, i) {		\
		error = cb(&cursor->element, arg);			\
		if (error)						\
			return error;					\
		}							\
									\
		return 0;						\
	}

ITERATE_LIST_FUNC(filter, prefix, filter_pfx_al)
ITERATE_LIST_FUNC(filter, bgpsec, filter_bgps_al)
ITERATE_LIST_FUNC(assertion, prefix, assertion_pfx_al)
ITERATE_LIST_FUNC(assertion, bgpsec, assertion_bgps_al)

bool
db_slurm_bgpsec_is_filtered(struct db_slurm *db, struct router_key const *key)
{
	struct slurm_bgpsec slurm_bgpsec;
	unsigned char *tmp;
	bool result;

	tmp = malloc(RK_SKI_LEN);
	if (tmp == NULL) {
		pr_enomem();
		return false;
	}
	slurm_bgpsec.data_flag = SLURM_COM_FLAG_ASN | SLURM_BGPS_FLAG_SKI;
	slurm_bgpsec.asn = key->as;
	memcpy(tmp, key->ski, RK_SKI_LEN);
	slurm_bgpsec.ski = tmp;
	/* Router public key isn't used at filters */
	slurm_bgpsec.router_public_key = NULL;

	result = bgpsec_filter_exists(db, &slurm_bgpsec, true, -1);
	free(tmp);
	return result;
}

static void
clean_slurm_bgpsec(struct slurm_bgpsec_ctx *bgpsec)
{
	if ((bgpsec->element.data_flag & SLURM_BGPS_FLAG_SKI) > 0)
		free(bgpsec->element.ski);
	if ((bgpsec->element.data_flag & SLURM_BGPS_FLAG_ROUTER_KEY) > 0)
		free(bgpsec->element.router_public_key);
}

void
db_slurm_update_time(struct db_slurm *db)
{
	db->loaded_date = time(NULL);
	db->loaded_date_set = true;
}

static int
print_prefix_data(struct slurm_prefix *prefix, void *arg)
{
	char *pad = "     ";

	pr_info("    {");
	if (prefix->data_flag & SLURM_COM_FLAG_ASN)
		pr_info("%s ASN: %u", pad, prefix->vrp.asn);

	if (prefix->data_flag & SLURM_PFX_FLAG_PREFIX) {
		switch (prefix->vrp.addr_fam) {
		case AF_INET:
			pr_info("%s Prefix: %s/%u", pad,
			    addr2str4(&prefix->vrp.prefix.v4, addr_buf),
			    prefix->vrp.prefix_length);
			break;
		case AF_INET6:
			pr_info("%s Prefix: %s/%u", pad,
			    addr2str6(&prefix->vrp.prefix.v6, addr_buf),
			    prefix->vrp.prefix_length);
			break;
		default:
			pr_crit("Unknown addr family type: %u",
			    prefix->vrp.addr_fam);
		}
	}

	if (prefix->data_flag & SLURM_PFX_FLAG_MAX_LENGTH)
		pr_info("%s Max prefix length: %u", pad,
		    prefix->vrp.max_prefix_length);
	pr_info("    }");

	return 0;
}

static int
print_bgpsec_data(struct slurm_bgpsec *bgpsec, void *arg)
{
	char *pad = "     ";
	char *buf;
	int error;

	pr_info("    {");
	if (bgpsec->data_flag & SLURM_COM_FLAG_ASN)
		pr_info("%s ASN: %u", pad, bgpsec->asn);

	if (bgpsec->data_flag & SLURM_BGPS_FLAG_SKI) {
		do {
			error = base64url_encode(bgpsec->ski, RK_SKI_LEN, &buf);
			if (error) {
				pr_info("%s SKI: <error encoding value>", pad);
				break;
			}
			pr_info("%s SKI: %s", pad, buf);
			free(buf);
		} while (0);
	}

	if (bgpsec->data_flag & SLURM_BGPS_FLAG_ROUTER_KEY) {
		do {
			error = base64url_encode(bgpsec->router_public_key,
			    RK_SPKI_LEN, &buf);
			if (error) {
				pr_info("%s Router public key: <error encoding value>",
				    pad);
				break;
			}
			pr_info("%s Router public key: %s", pad, buf);
			free(buf);
		} while (0);
	}
	pr_info("    }");

	return 0;
}

void
db_slurm_log(struct db_slurm *db)
{
	if (db->loaded_date_set)
		pr_info("SLURM loaded at %s",
		    asctime(localtime(&db->loaded_date)));
	pr_info("Validation output filters {");
	pr_info("  Prefix filters {");
	db_slurm_foreach_filter_prefix(db, print_prefix_data, NULL);
	pr_info("  }");
	pr_info("  BGPsec filters {");
	db_slurm_foreach_filter_bgpsec(db, print_bgpsec_data, NULL);
	pr_info("  }");
	pr_info("}");

	pr_info("Locally added assertions {");
	pr_info("  Prefix assertions {");
	db_slurm_foreach_assertion_prefix(db, print_prefix_data, NULL);
	pr_info("  }");
	pr_info("  BGPsec assertions {");
	db_slurm_foreach_assertion_bgpsec(db, print_bgpsec_data, NULL);
	pr_info("  }");
	pr_info("}");
}

void
db_slurm_destroy(struct db_slurm *db)
{
	/* No need to cleanup prefixes (filters or assertions) */
	al_filter_prefix_cleanup(&db->filter_pfx_al, NULL);
	al_filter_bgpsec_cleanup(&db->filter_bgps_al,
	    clean_slurm_bgpsec);
	al_assertion_prefix_cleanup(&db->assertion_pfx_al, NULL);
	al_assertion_bgpsec_cleanup(&db->assertion_bgps_al,
	    clean_slurm_bgpsec);
	free(db);
}
