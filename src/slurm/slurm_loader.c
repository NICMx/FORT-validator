#include "slurm/slurm_loader.h"

#include <errno.h>
#include <openssl/sha.h>

#include "alloc.h"
#include "common.h"
#include "config.h"
#include "hash.h"
#include "log.h"
#include "slurm/slurm_parser.h"

#define SLURM_FILE_EXTENSION	".slurm"

struct slurm_parser_params {
	struct db_table *db_table;
	struct db_slurm *db_slurm;
};

/*
 * Load the SLURM file(s) from the configured path.
 *
 * If this returns zero but @result is NULL, it's fine. There are no SLURM
 * rules.
 */
static int
load_slurm_files(struct slurm_csum_list *csums, struct db_slurm **result)
{
	struct db_slurm *db;
	int error;

	error = db_slurm_create(csums, &db);
	if (error)
		return error;

	error = foreach_file(config_get_slurm(), SLURM_FILE_EXTENSION,
	    false, slurm_parse, db);
	if (error)
		goto cancel;

	/* Empty SLURM dir, or empty SLURM file(s) */
	if (!db_slurm_has_data(db)) {
		*result = NULL;
		goto cancel; /* Success. */
	}

	*result = db;
	return 0;

cancel:
	db_slurm_destroy(db);
	return error;
}

static int
slurm_pfx_filters_apply(struct vrp const *vrp, void *arg)
{
	struct slurm_parser_params *params = arg;

	if (db_slurm_vrp_is_filtered(params->db_slurm, vrp))
		db_table_remove_roa(params->db_table, vrp);

	return 0;
}

static int
slurm_pfx_assertions_add(struct slurm_prefix *prefix, void *arg)
{
	struct db_table *table = arg;
	struct ipv4_prefix prefix4;
	struct ipv6_prefix prefix6;
	struct vrp vrp;

	vrp = prefix->vrp;
	if ((prefix->data_flag & SLURM_PFX_FLAG_MAX_LENGTH) == 0)
		vrp.max_prefix_length = vrp.prefix_length;

	if (vrp.addr_fam == AF_INET) {
		prefix4.addr = vrp.prefix.v4;
		prefix4.len = vrp.prefix_length;
		return rtrhandler_handle_roa_v4(table, vrp.asn, &prefix4,
		    vrp.max_prefix_length);
	}
	if (vrp.addr_fam == AF_INET6) {
		prefix6.addr = vrp.prefix.v6;
		prefix6.len = vrp.prefix_length;
		return rtrhandler_handle_roa_v6(table, vrp.asn, &prefix6,
		    vrp.max_prefix_length);
	}

	pr_crit("Unknown addr family type: %u", vrp.addr_fam);
	return EINVAL; /* Warning shutupper */
}

static int
slurm_pfx_assertions_apply(struct slurm_parser_params *params)
{
	return db_slurm_foreach_assertion_prefix(params->db_slurm,
	    slurm_pfx_assertions_add, params->db_table);
}

static int
slurm_bgpsec_filters_apply(struct router_key const *key, void *arg)
{
	struct slurm_parser_params *params = arg;

	if (db_slurm_bgpsec_is_filtered(params->db_slurm, key))
		db_table_remove_router_key(params->db_table, key);

	return 0;
}

static int
slurm_bgpsec_assertions_add(struct slurm_bgpsec *bgpsec, void *arg)
{
	struct db_table *table = arg;

	return rtrhandler_handle_router_key(table, bgpsec->ski, bgpsec->asn,
	    bgpsec->router_public_key);
}

static int
slurm_bgpsec_assertions_apply(struct slurm_parser_params *params)
{
	return db_slurm_foreach_assertion_bgpsec(params->db_slurm,
	    slurm_bgpsec_assertions_add, params->db_table);
}

static int
__slurm_load_checksums(char const *location, void *arg)
{
	struct slurm_csum_list *list;
	struct slurm_file_csum *csum;

	csum = pmalloc(sizeof(struct slurm_file_csum));

	if (hash_file(hash_get_sha256(), location, csum->csum, &csum->csum_len) != 0) {
		free(csum);
		return pr_op_err("Calculating slurm hash");
	}

	list = arg;
	SLIST_INSERT_HEAD(list, csum, next);
	list->list_size++;

	return 0;
}

static void
destroy_local_csum_list(struct slurm_csum_list *list)
{
	struct slurm_file_csum *tmp;

	while (!SLIST_EMPTY(list)) {
		tmp = SLIST_FIRST(list);
		SLIST_REMOVE_HEAD(list, next);
		free(tmp);
	}
}

static int
slurm_load_checksums(struct slurm_csum_list *csums)
{
	int error;

	SLIST_INIT(csums);
	csums->list_size = 0;

	error = foreach_file(config_get_slurm(), SLURM_FILE_EXTENSION,
	    false, __slurm_load_checksums, csums);
	if (error)
		destroy_local_csum_list(csums);

	return error;
}

static bool
are_csum_lists_equals(struct slurm_csum_list *new_list,
    struct slurm_csum_list *old_list)
{
	struct slurm_file_csum *newcsum, *old;
	bool found = false;

	if (new_list->list_size != old_list->list_size) {
		return false;
	}

	SLIST_FOREACH(newcsum, new_list, next) {
		SLIST_FOREACH(old, old_list, next) {
			if (memcmp(newcsum->csum, old->csum, SHA256_DIGEST_LENGTH) == 0) {
				found = true;
				break;
			}
		}

		if (!found)
			return false;

		found = false;
	}

	return true;
}

/* Load SLURM file(s) that have updates */
static int
update_slurm(struct db_slurm **slurm)
{
	struct slurm_csum_list new_csums;
	struct slurm_csum_list old_csums;
	struct db_slurm *new_slurm = NULL;
	int error;

	pr_op_info("Checking if there are new or modified SLURM files");

	error = slurm_load_checksums(&new_csums);
	if (error)
		return error;

	/* Empty DIR or FILE SLURM not found */
	if (new_csums.list_size == 0)
		goto success;

	if (*slurm != NULL) {
		db_slurm_get_csum_list(*slurm, &old_csums);
		if (are_csum_lists_equals(&new_csums, &old_csums)) {
			pr_op_info("Applying same old SLURM, no changes found.");
			destroy_local_csum_list(&new_csums);
			return 0;
		}
	}

	pr_op_info("Applying configured SLURM");

	error = load_slurm_files(&new_csums, &new_slurm);

	/*
	 * Checksums were transferred to new_slurm on success, but they're
	 * still here on failure.
	 * Either way, new_csums is ready for cleanup.
	 */
	destroy_local_csum_list(&new_csums);

	if (error) {
		/* Fall back to previous iteration's SLURM */
		pr_op_info("Error '%s' loading SLURM. The validation will continue regardless.",
		    strerror(error));
		if (*slurm != NULL) {
			pr_op_info("A previous valid version of the SLURM exists and will be applied.");
			db_slurm_log(*slurm);
		}

		return 0;
	}

success:
	/* Use new SLURM as last valid slurm */
	if (*slurm != NULL)
		db_slurm_destroy(*slurm);

	*slurm = new_slurm;
	return 0;
}

int
slurm_apply(struct db_table *base, struct db_slurm **slurm)
{
	struct slurm_parser_params params;
	int error;

	if (config_get_slurm() == NULL)
		return 0;

	error = update_slurm(slurm);
	if (error)
		return error;

	if (*slurm == NULL)
		return 0;

	/* Ok, apply SLURM */

	params.db_table = base;
	params.db_slurm = *slurm;

	/* TODO invert this. SLURM rules are few, and base is massive. */
	error = db_table_foreach_roa(base, slurm_pfx_filters_apply, &params);
	if (error)
		return error;

	error = db_table_foreach_router_key(base, slurm_bgpsec_filters_apply,
	    &params);
	if (error)
		return error;

	error = slurm_pfx_assertions_apply(&params);
	if (error)
		return error;

	return slurm_bgpsec_assertions_apply(&params);
}
