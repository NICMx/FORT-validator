#include "slurm_loader.h"

#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h> /* AF_INET, AF_INET6 (needed in OpenBSD) */
#include <sys/socket.h> /* AF_INET, AF_INET6 (needed in OpenBSD) */

#include "log.h"
#include "config.h"
#include "common.h"
#include "crypto/hash.h"
#include "slurm/slurm_parser.h"

#define SLURM_FILE_EXTENSION	".slurm"

/*
 * Load the SLURM file(s) from the configured path, if the path is valid but no
 * data is loaded (specific error for a SLURM folder) no error is returned and
 * slurm db from @params is set as NULL.
 */
static int
load_slurm_files(struct slurm_parser_params *params)
{
	struct db_slurm *db;
	int error;

	error = db_slurm_create(&db);
	if (error)
		return error;

	params->db_slurm = db;

	error = process_file_or_dir(config_get_slurm(), SLURM_FILE_EXTENSION,
	    slurm_parse, params);
	if (error) {
		db_slurm_destroy(db);
		params->db_slurm = NULL;
		return error;
	}

	/* Empty SLURM dir, or empty SLURM file(s) */
	if (!db_slurm_has_data(db)) {
		db_slurm_destroy(db);
		params->db_slurm = NULL;
	}

	return 0;
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
	struct slurm_parser_params *params = arg;
	struct ipv4_prefix prefix4;
	struct ipv6_prefix prefix6;
	struct vrp vrp;

	vrp = prefix->vrp;
	if ((prefix->data_flag & SLURM_PFX_FLAG_MAX_LENGTH) == 0)
		vrp.max_prefix_length = vrp.prefix_length;

	if (vrp.addr_fam == AF_INET) {
		prefix4.addr = vrp.prefix.v4;
		prefix4.len = vrp.prefix_length;
		return rtrhandler_handle_roa_v4(params->db_table, vrp.asn,
		    &prefix4, vrp.max_prefix_length);
	}
	if (vrp.addr_fam == AF_INET6) {
		prefix6.addr = vrp.prefix.v6;
		prefix6.len = vrp.prefix_length;
		return rtrhandler_handle_roa_v6(params->db_table, vrp.asn,
		    &prefix6, vrp.max_prefix_length);
	}

	pr_crit("Unknown addr family type: %u", vrp.addr_fam);
}

static int
slurm_pfx_assertions_apply(struct slurm_parser_params *params)
{
	return db_slurm_foreach_assertion_prefix(params->db_slurm,
	    slurm_pfx_assertions_add, params);
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
	struct slurm_parser_params *params = arg;

	return rtrhandler_handle_router_key(params->db_table, bgpsec->ski,
	    bgpsec->asn, bgpsec->router_public_key);
}

static int
slurm_bgpsec_assertions_apply(struct slurm_parser_params *params)
{
	return db_slurm_foreach_assertion_bgpsec(params->db_slurm,
	    slurm_bgpsec_assertions_add, params);
}

static int
slurm_create_parser_params(struct slurm_parser_params **result)
{
	struct slurm_parser_params *params;

	params = malloc(sizeof(struct slurm_parser_params));
	if (params == NULL)
		return pr_enomem();

	params->db_table = NULL;
	params->db_slurm = NULL;

	*result = params;
	return 0;
}

static int
__slurm_load_checksums(char const *location, void *arg)
{
	struct slurm_csum_list *list;
	struct slurm_file_csum *csum;
	int error;

	list = arg;
	csum = malloc(sizeof(struct slurm_file_csum));
	if (csum == NULL)
		return pr_enomem();


	error = hash_local_file("sha256", location, csum->csum,
	    &csum->csum_len);
	if (error) {
		free(csum);
		return pr_err("Calculating slurm hash");
	}

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
slurm_load_checksums(struct slurm_csum_list *csum_list)
{
	struct slurm_csum_list result;
	int error;

	SLIST_INIT(&result);
	result.list_size = 0;

	error = process_file_or_dir(config_get_slurm(), SLURM_FILE_EXTENSION,
	    __slurm_load_checksums, &result);
	if (error) {
		destroy_local_csum_list(&result);
		return error;
	}

	csum_list->list_size = result.list_size;
	csum_list->slh_first = result.slh_first;

	return 0;
}

/* Returns whether a new slurm was allocated */
static void
__load_slurm_files(struct db_slurm **last_slurm,
    struct slurm_parser_params *params, struct slurm_csum_list *csum_list)
{
	int error;

	error = load_slurm_files(params);
	if (error) {
		/* Any error: use last valid SLURM */
		pr_warn("Error loading SLURM, the validation will still continue.");
		if (*last_slurm != NULL) {
			pr_warn("A previous valid version of the SLURM exists and will be applied.");
			params->db_slurm = *last_slurm;
			/* Log applied SLURM as info */
			db_slurm_log(params->db_slurm);
		}
		destroy_local_csum_list(csum_list);
		return;
	}

	/* Use new SLURM as last valid slurm */
	if (*last_slurm != NULL)
		db_slurm_destroy(*last_slurm);

	*last_slurm = params->db_slurm;
	if (*last_slurm != NULL) {
		db_slurm_update_time(*last_slurm);
		db_slurm_set_csum_list(*last_slurm, csum_list);
	}
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

			if (newcsum->csum_len != old->csum_len)
				continue;

			if (memcmp(newcsum->csum, old->csum,
			    newcsum->csum_len) == 0) {
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
load_updated_slurm(struct db_slurm **last_slurm,
    struct slurm_parser_params *params)
{
	struct slurm_csum_list csum_list, old_csum_list;
	int error;
	bool list_equals;

	list_equals = false;

	pr_info("Checking if there are new or modified SLURM files");
	error = slurm_load_checksums(&csum_list);
	if (error)
		return error;

	if (*last_slurm != NULL) {
		db_slurm_get_csum_list(*last_slurm, &old_csum_list);
		list_equals = are_csum_lists_equals(&csum_list, &old_csum_list);
	}

	if (list_equals) {
		if (*last_slurm != NULL) {
			pr_info("Applying same old SLURM, no changes found.");
			params->db_slurm = *last_slurm;
		}
		destroy_local_csum_list(&csum_list);
		return 0;
	}

	/* Empty DIR or FILE SLURM not found */
	if (csum_list.list_size == 0) {
		if (*last_slurm != NULL)
			db_slurm_destroy(*last_slurm);
		*last_slurm = NULL;
		params->db_slurm = NULL;
		return 0;
	}

	pr_info("Applying configured SLURM");
	__load_slurm_files(last_slurm, params, &csum_list);

	return 0;
}

int
slurm_apply(struct db_table **base, struct db_slurm **last_slurm)
{
	struct slurm_parser_params *params;
	int error;

	if (config_get_slurm() == NULL)
		return 0;

	params = NULL;
	error = slurm_create_parser_params(&params);
	if (error)
		return error;

	error = load_updated_slurm(last_slurm, params);
	if (error)
		goto release_params;

	/* If there's no new SLURM loaded, stop */
	if (params->db_slurm == NULL)
		goto success;

	/* Deep copy of the base so that updates can be reverted */
	error = db_table_clone(&params->db_table, *base);
	if (error)
		goto release_params;

	error = db_table_foreach_roa(params->db_table, slurm_pfx_filters_apply,
	    params);
	if (error)
		goto release_table;

	error = db_table_foreach_router_key(params->db_table,
	    slurm_bgpsec_filters_apply, params);
	if (error)
		goto release_table;

	error = slurm_pfx_assertions_apply(params);
	if (error)
		goto release_table;

	error = slurm_bgpsec_assertions_apply(params);
	if (error) {
		goto release_table;
	}

	db_table_destroy(*base);
	*base = params->db_table;
success:
	free(params);
	return 0;
release_table:
	db_table_destroy(params->db_table);
release_params:
	free(params);
	return error;
}
