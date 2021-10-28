#include "slurm/db_slurm.h"

#include <string.h>
#include <time.h>
#include <arpa/inet.h>

#include "common.h"
#include "crypto/base64.h"
#include "data_structure/array_list.h"
#include "types/router_key.h"

struct slurm_prefix_wrap {
	struct slurm_prefix element;
	unsigned int references;
};

struct slurm_bgpsec_wrap {
	struct slurm_bgpsec element;
	unsigned int references;
};

STATIC_ARRAY_LIST(al_filter_prefix, struct slurm_prefix_wrap)
STATIC_ARRAY_LIST(al_assertion_prefix, struct slurm_prefix_wrap)
STATIC_ARRAY_LIST(al_filter_bgpsec, struct slurm_bgpsec_wrap)
STATIC_ARRAY_LIST(al_assertion_bgpsec, struct slurm_bgpsec_wrap)

struct slurm_lists {
	struct al_filter_prefix filter_pfx_al;
	struct al_assertion_prefix assertion_pfx_al;
	struct al_filter_bgpsec filter_bgps_al;
	struct al_assertion_bgpsec assertion_bgps_al;
};

struct db_slurm {
	struct slurm_lists lists;
	struct slurm_lists *cache;
	time_t loaded_date;
	struct slurm_csum_list csum_list;
};

static char addr_buf[INET6_ADDRSTRLEN];

static void
slurm_bgpsec_wrap_refget(struct slurm_bgpsec_wrap *elem)
{
	elem->references++;
}

static void
slurm_bgpsec_wrap_refput(struct slurm_bgpsec_wrap *elem)
{
	elem->references--;
	if (elem->references == 0) {
		if ((elem->element.data_flag & SLURM_BGPS_FLAG_SKI) > 0)
			free(elem->element.ski);
		if ((elem->element.data_flag & SLURM_BGPS_FLAG_ROUTER_KEY) > 0)
			free(elem->element.router_public_key);
	}
}

static int
slurm_lists_create(struct slurm_lists **result)
{
	struct slurm_lists *cache;

	cache = malloc(sizeof(struct slurm_lists));
	if (cache == NULL)
		return pr_enomem();

	al_filter_prefix_init(&cache->filter_pfx_al);
	al_assertion_prefix_init(&cache->assertion_pfx_al);
	al_filter_bgpsec_init(&cache->filter_bgps_al);
	al_assertion_bgpsec_init(&cache->assertion_bgps_al);

	*result = cache;
	return 0;
}

static void
slurm_lists_cleanup(struct slurm_lists *lists)
{
	/* No need to cleanup prefixes (filters or assertions) */
	al_filter_prefix_cleanup(&lists->filter_pfx_al, NULL);
	al_filter_bgpsec_cleanup(&lists->filter_bgps_al,
	    slurm_bgpsec_wrap_refput);
	al_assertion_prefix_cleanup(&lists->assertion_pfx_al, NULL);
	al_assertion_bgpsec_cleanup(&lists->assertion_bgps_al,
	    slurm_bgpsec_wrap_refput);
}

static void
slurm_lists_destroy(struct slurm_lists *lists)
{
	slurm_lists_cleanup(lists);
	free(lists);
}

int
db_slurm_create(struct slurm_csum_list *csums, struct db_slurm **result)
{
	struct db_slurm *db;
	int error;

	db = malloc(sizeof(struct db_slurm));
	if (db == NULL)
		return pr_enomem();

	error = get_current_time(&db->loaded_date);
	if (error) {
		free(db);
		return error;
	}

	/* Not ready yet (nor required yet) for multithreading */
	al_filter_prefix_init(&db->lists.filter_pfx_al);
	al_assertion_prefix_init(&db->lists.assertion_pfx_al);
	al_filter_bgpsec_init(&db->lists.filter_bgps_al);
	al_assertion_bgpsec_init(&db->lists.assertion_bgps_al);
	db->cache = NULL;
	db->csum_list = *csums;

	/*
	 * Slight hack: Clean up csums, so caller can always call
	 * destroy_local_csum_list().
	 */
	csums->slh_first = NULL;
	csums->list_size = 0;

	*result = db;
	return 0;
}

/*
 * @filter_wrap is the prefix loaded from SLURM, @prefix is the VRP "masked" as
 * a slurm_prefix
 */
static bool
prefix_filtered_by(struct slurm_prefix_wrap *filter_wrap,
    struct slurm_prefix *prefix)
{
	struct slurm_prefix *filter;
	struct vrp *filter_vrp, *prefix_vrp;
	bool equal;

	filter = &filter_wrap->element;
	filter_vrp = &filter->vrp;
	prefix_vrp = &prefix->vrp;

	/*
	 * Ignore the comments, remember: FILTERS don't have the same data (no
	 * max_length is declared), while ASSERTIONS do.
	 */
	if ((filter->data_flag & ~SLURM_COM_FLAG_COMMENT) !=
	    (prefix->data_flag & ~SLURM_COM_FLAG_COMMENT)) {
		/* The filter has ASN and prefix */
		if ((filter->data_flag & ~SLURM_COM_FLAG_COMMENT) ==
		    (SLURM_COM_FLAG_ASN | SLURM_PFX_FLAG_PREFIX))
			return (filter_vrp->asn == prefix_vrp->asn) &&
			    vrp_prefix_cov(filter_vrp, prefix_vrp);

		/* Both have ASN */
		if ((filter->data_flag & SLURM_COM_FLAG_ASN) > 0 &&
		    (prefix->data_flag & SLURM_COM_FLAG_ASN) > 0)
			return filter_vrp->asn == prefix_vrp->asn;

		/* Both have a prefix of the same type */
		if ((filter->data_flag & SLURM_PFX_FLAG_PREFIX) > 0 &&
		    (prefix->data_flag & SLURM_PFX_FLAG_PREFIX) > 0)
			return vrp_prefix_cov(filter_vrp, prefix_vrp);

		return false;
	}

	/* It has the same data, compare it */
	equal = true;
	if (equal && (filter->data_flag & SLURM_COM_FLAG_ASN) > 0)
		equal = filter_vrp->asn == prefix_vrp->asn;

	if (equal && (filter->data_flag & SLURM_PFX_FLAG_PREFIX) > 0)
		equal = vrp_prefix_cov(filter_vrp, prefix_vrp);

	return equal;
}

static bool
prefix_filtered(struct db_slurm *db, struct slurm_prefix *prefix)
{
	struct slurm_prefix_wrap *cursor;
	array_index i;

	ARRAYLIST_FOREACH(&db->lists.filter_pfx_al, cursor, i)
		if (prefix_filtered_by(cursor, prefix))
			return true;

	return false;
}

static bool
bgpsec_filtered_by(struct slurm_bgpsec_wrap *filter_wrap,
    struct slurm_bgpsec *bgpsec)
{
	struct slurm_bgpsec *filter;
	bool equal;

	filter = &filter_wrap->element;

	/* Ignore the comments */
	if ((filter->data_flag & ~SLURM_COM_FLAG_COMMENT) !=
	    (bgpsec->data_flag & ~SLURM_COM_FLAG_COMMENT)) {
		/* The filter has ASN and SKI */
		if ((filter->data_flag & ~SLURM_COM_FLAG_COMMENT) ==
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
			return memcmp(bgpsec->ski, filter->ski, RK_SKI_LEN)
			    == 0;

		return false;
	}

	/* It has the same data, compare it */
	equal = true;
	if (equal && (filter->data_flag & SLURM_COM_FLAG_ASN) > 0)
		equal = filter->asn == bgpsec->asn;

	if (equal && (filter->data_flag & SLURM_BGPS_FLAG_SKI) > 0)
		equal = memcmp(filter->ski, bgpsec->ski, RK_SKI_LEN) == 0;

	return equal;
}

static bool
bgpsec_filtered(struct db_slurm *db, struct slurm_bgpsec *bgpsec)
{
	struct slurm_bgpsec_wrap *cursor;
	array_index i;

	ARRAYLIST_FOREACH(&db->lists.filter_bgps_al, cursor, i)
		if (bgpsec_filtered_by(cursor, bgpsec))
			return true;

	return false;
}

static bool
prefix_contained(struct slurm_prefix *left, struct slurm_prefix *right)
{
	struct vrp *left_vrp, *right_vrp;

	left_vrp = &left->vrp;
	right_vrp = &right->vrp;

	return (left->data_flag & SLURM_PFX_FLAG_PREFIX) > 0 &&
	    (right->data_flag & SLURM_PFX_FLAG_PREFIX) > 0 &&
	    vrp_prefix_cov(left_vrp, right_vrp);
}

/*
 * rfc8416#section-4.2:
 * 1. There may be conflicting changes to ROA Prefix Assertions if an
 *    IP address X and distinct SLURM files Y and Z exist such that X
 *    is contained by any prefix in any "prefixAssertions" or
 *    "prefixFilters" in file Y and X is contained by any prefix in any
 *    "prefixAssertions" or "prefixFilters" in file Z.
 */
static bool
prefix_exists(struct db_slurm *db, struct slurm_prefix *elem)
{
	struct slurm_prefix_wrap *cursor;
	array_index i;

	ARRAYLIST_FOREACH(&db->lists.filter_pfx_al, cursor, i)
		if (prefix_contained(&cursor->element, elem) ||
		    prefix_contained(elem, &cursor->element))
			return true;

	ARRAYLIST_FOREACH(&db->lists.assertion_pfx_al, cursor, i)
		if (prefix_contained(&cursor->element, elem) ||
		    prefix_contained(elem, &cursor->element))
			return true;

	return false;
}

int
db_slurm_add_prefix_filter(struct db_slurm *db, struct slurm_prefix *elem)
{
	struct slurm_prefix_wrap new;

	if (prefix_exists(db, elem))
		return -EEXIST;

	new.element = *elem;
	new.references = 1;

	return al_filter_prefix_add(&db->cache->filter_pfx_al, &new);
}

int
db_slurm_add_prefix_assertion(struct db_slurm *db, struct slurm_prefix *elem)
{
	struct slurm_prefix_wrap new;

	if (prefix_exists(db, elem))
		return -EEXIST;

	new.element = *elem;
	new.references = 1;

	return al_assertion_prefix_add(&db->cache->assertion_pfx_al, &new);
}

static bool
bgpsec_contained(struct slurm_bgpsec *left, struct slurm_bgpsec *right)
{
	return (left->data_flag & SLURM_COM_FLAG_ASN) > 0 &&
	    (right->data_flag & SLURM_COM_FLAG_ASN) > 0 &&
	    left->asn == right->asn;
}

/*
 * rfc8416#section-4.2:
 * 2. There may be conflicting changes to BGPsec Assertions if an ASN X
 *    and distinct SLURM files Y and Z exist such that X is used in any
 *    "bgpsecAssertions" or "bgpsecFilters" in file Y and X is used in
 *    any "bgpsecAssertions" or "bgpsecFilters" in file Z.
 */
static bool
bgpsec_exists(struct db_slurm *db, struct slurm_bgpsec *elem)
{
	struct slurm_bgpsec_wrap *cursor;
	array_index i;

	ARRAYLIST_FOREACH(&db->lists.filter_bgps_al, cursor, i)
		if (bgpsec_contained(&cursor->element, elem) ||
		    bgpsec_contained(elem, &cursor->element))
			return true;

	ARRAYLIST_FOREACH(&db->lists.assertion_bgps_al, cursor, i)
		if (bgpsec_contained(&cursor->element, elem) ||
		    bgpsec_contained(elem, &cursor->element))
			return true;

	return false;
}

int
db_slurm_add_bgpsec_filter(struct db_slurm *db, struct slurm_bgpsec *elem)
{
	struct slurm_bgpsec_wrap new;

	if (bgpsec_exists(db, elem))
		return -EEXIST;

	new.element = *elem;
	new.references = 1;

	return al_filter_bgpsec_add(&db->cache->filter_bgps_al, &new);
}

int
db_slurm_add_bgpsec_assertion(struct db_slurm *db, struct slurm_bgpsec *elem)
{
	struct slurm_bgpsec_wrap new;

	if (bgpsec_exists(db, elem))
		return -EEXIST;

	new.element = *elem;
	new.references = 1;

	return al_assertion_bgpsec_add(&db->cache->assertion_bgps_al, &new);
}

bool
db_slurm_vrp_is_filtered(struct db_slurm *db, struct vrp const *vrp)
{
	struct slurm_prefix slurm_prefix;

	slurm_prefix.data_flag = SLURM_COM_FLAG_ASN | SLURM_PFX_FLAG_PREFIX
	    | SLURM_PFX_FLAG_MAX_LENGTH;
	slurm_prefix.vrp = *vrp;

	return prefix_filtered(db, &slurm_prefix);
}

bool
db_slurm_bgpsec_is_filtered(struct db_slurm *db, struct router_key const *key)
{
	unsigned char ski[RK_SKI_LEN];
	struct slurm_bgpsec slurm_bgpsec;

	slurm_bgpsec.data_flag = SLURM_COM_FLAG_ASN | SLURM_BGPS_FLAG_SKI;
	slurm_bgpsec.asn = key->as;
	memcpy(ski, key->ski, RK_SKI_LEN);
	slurm_bgpsec.ski = ski;
	/* Router public key isn't used at filters */
	slurm_bgpsec.router_public_key = NULL;

	return bgpsec_filtered(db, &slurm_bgpsec);
}

#define ITERATE_LIST_FUNC(type, object, db_list)			\
	static int							\
	foreach_##type##_##object(struct slurm_lists *lists,		\
	    object##_foreach_cb cb, void *arg)				\
	{								\
		struct slurm_##object##_wrap *cursor;			\
		array_index i;						\
		int error;						\
									\
		ARRAYLIST_FOREACH(&lists->db_list, cursor, i) {		\
			error = cb(&cursor->element, arg);		\
			if (error)					\
				return error;				\
		}							\
									\
		return 0;						\
	}

ITERATE_LIST_FUNC(filter, prefix, filter_pfx_al)
ITERATE_LIST_FUNC(filter, bgpsec, filter_bgps_al)
ITERATE_LIST_FUNC(assertion, prefix, assertion_pfx_al)
ITERATE_LIST_FUNC(assertion, bgpsec, assertion_bgps_al)

int
db_slurm_foreach_assertion_prefix(struct db_slurm *db, prefix_foreach_cb cb,
    void *arg)
{
	return foreach_assertion_prefix(&db->lists, cb, arg);
}

int
db_slurm_foreach_assertion_bgpsec(struct db_slurm *db, bgpsec_foreach_cb cb,
    void *arg)
{
	return foreach_assertion_bgpsec(&db->lists, cb, arg);
}

static int
print_prefix_data(struct slurm_prefix *prefix, void *arg)
{
	char *pad = "     ";

	pr_op_info("    {");
	if (prefix->data_flag & SLURM_COM_FLAG_ASN)
		pr_op_info("%s ASN: %u", pad, prefix->vrp.asn);

	if (prefix->data_flag & SLURM_PFX_FLAG_PREFIX) {
		pr_op_info("%s Prefix: %s/%u", pad,
		    inet_ntop(prefix->vrp.addr_fam, &prefix->vrp.prefix,
		    addr_buf, INET6_ADDRSTRLEN), prefix->vrp.prefix_length);
	}

	if (prefix->data_flag & SLURM_PFX_FLAG_MAX_LENGTH)
		pr_op_info("%s Max prefix length: %u", pad,
		    prefix->vrp.max_prefix_length);
	pr_op_info("    }");

	return 0;
}

static int
print_bgpsec_data(struct slurm_bgpsec *bgpsec, void *arg)
{
	char *pad = "     ";
	char *buf;
	int error;

	pr_op_info("    {");
	if (bgpsec->data_flag & SLURM_COM_FLAG_ASN)
		pr_op_info("%s ASN: %u", pad, bgpsec->asn);

	if (bgpsec->data_flag & SLURM_BGPS_FLAG_SKI) {
		do {
			error = base64url_encode(bgpsec->ski, RK_SKI_LEN, &buf);
			if (error) {
				pr_op_info("%s SKI: <error encoding value>",
				    pad);
				break;
			}
			pr_op_info("%s SKI: %s", pad, buf);
			free(buf);
		} while (0);
	}

	if (bgpsec->data_flag & SLURM_BGPS_FLAG_ROUTER_KEY) {
		do {
			error = base64url_encode(bgpsec->router_public_key,
			    RK_SPKI_LEN, &buf);
			if (error) {
				pr_op_info("%s Router public key: <error encoding value>",
				    pad);
				break;
			}
			pr_op_info("%s Router public key: %s", pad, buf);
			free(buf);
		} while (0);
	}
	pr_op_info("    }");

	return 0;
}

void
db_slurm_log(struct db_slurm *db)
{
	pr_op_info("SLURM loaded at %s", asctime(localtime(&db->loaded_date)));
	pr_op_info("Validation output filters {");
	pr_op_info("  Prefix filters {");
	foreach_filter_prefix(&db->lists, print_prefix_data, NULL);
	pr_op_info("  }");
	pr_op_info("  BGPsec filters {");
	foreach_filter_bgpsec(&db->lists, print_bgpsec_data, NULL);
	pr_op_info("  }");
	pr_op_info("}");

	pr_op_info("Locally added assertions {");
	pr_op_info("  Prefix assertions {");
	foreach_assertion_prefix(&db->lists, print_prefix_data, NULL);
	pr_op_info("  }");
	pr_op_info("  BGPsec assertions {");
	foreach_assertion_bgpsec(&db->lists, print_bgpsec_data, NULL);
	pr_op_info("  }");
	pr_op_info("}");
}

int
db_slurm_start_cache(struct db_slurm *db)
{
	struct slurm_lists *cache;
	int error;

	cache = NULL;
	error = slurm_lists_create(&cache);
	if (error)
		return error;

	db->cache = cache;

	return 0;
}

static int
persist_filter_prefix(struct db_slurm *db)
{
	struct slurm_prefix_wrap *cursor;
	array_index i;
	int error;

	ARRAYLIST_FOREACH(&db->cache->filter_pfx_al, cursor, i) {
		error = al_filter_prefix_add(&db->lists.filter_pfx_al, cursor);
		if (error)
			return error;
	}

	return 0;
}

static int
persist_filter_bgpsec(struct db_slurm *db)
{
	struct slurm_bgpsec_wrap *cursor;
	array_index i;
	int error;

	ARRAYLIST_FOREACH(&db->cache->filter_bgps_al, cursor, i) {
		error = al_filter_bgpsec_add(&db->lists.filter_bgps_al, cursor);
		if (error)
			return error;
		slurm_bgpsec_wrap_refget(cursor);
	}

	return 0;
}

static int
persist_assertion_prefix(struct db_slurm *db)
{
	struct slurm_prefix_wrap *cursor;
	array_index i;
	int error;

	ARRAYLIST_FOREACH(&db->cache->assertion_pfx_al, cursor, i) {
		error = al_assertion_prefix_add(&db->lists.assertion_pfx_al,
		    cursor);
		if (error)
			return error;
	}

	return 0;
}

static int
persist_assertion_bgpsec(struct db_slurm *db)
{
	struct slurm_bgpsec_wrap *cursor;
	array_index i;
	int error;

	ARRAYLIST_FOREACH(&db->cache->assertion_bgps_al, cursor, i) {
		error = al_assertion_bgpsec_add(&db->lists.assertion_bgps_al,
		    cursor);
		if (error)
			return error;
		slurm_bgpsec_wrap_refget(cursor);
	}

	return 0;
}

int
db_slurm_flush_cache(struct db_slurm *db)
{
	/* Copy all data in cache to the main lists */
	int error;

	error = persist_filter_prefix(db);
	if (error)
		return error;

	error = persist_filter_bgpsec(db);
	if (error)
		return error;

	error = persist_assertion_prefix(db);
	if (error)
		return error;

	error = persist_assertion_bgpsec(db);
	if (error)
		return error;

	slurm_lists_destroy(db->cache);
	db->cache = NULL;

	return 0;
}

bool
db_slurm_has_data(struct db_slurm *db)
{
	return db->lists.filter_pfx_al.len > 0
	    || db->lists.filter_bgps_al.len > 0
	    || db->lists.assertion_pfx_al.len > 0
	    || db->lists.assertion_bgps_al.len > 0;
}

void
db_slurm_destroy(struct db_slurm *db)
{
	struct slurm_file_csum *tmp;

	slurm_lists_cleanup(&db->lists);
	if (db->cache)
		slurm_lists_destroy(db->cache);

	while (!SLIST_EMPTY(&db->csum_list)) {
		tmp = SLIST_FIRST(&db->csum_list);
		SLIST_REMOVE_HEAD(&db->csum_list, next);
		free(tmp);
	}

	free(db);
}

void
db_slurm_get_csum_list(struct db_slurm *db, struct slurm_csum_list *result)
{
	result->list_size = db->csum_list.list_size;
	result->slh_first = db->csum_list.slh_first;
}

