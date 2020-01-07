#include "slurm_loader.h"

#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h> /* AF_INET, AF_INET6 (needed in OpenBSD) */
#include <sys/socket.h> /* AF_INET, AF_INET6 (needed in OpenBSD) */

#include "log.h"
#include "config.h"
#include "common.h"
#include "slurm/slurm_parser.h"

#define SLURM_FILE_EXTENSION	".slurm"

/*
 * Load the SLURM file(s) from the configured path, if the path is valid but no
 * data is loaded (specific error for a SLURM folder) return -ENOENT error.
 *
 * Expect an EEXIST error from slurm_parse() if there's a syntax error.
 */
static int
slurm_load(struct slurm_parser_params *params)
{
	struct db_slurm *db;
	int error;

	error = db_slurm_create(&db);
	if (error)
		return error;

	params->db_slurm = db;

	error = process_file_or_dir(config_get_slurm(), SLURM_FILE_EXTENSION,
	    slurm_parse, params);
	if (error)
		goto err;

	/* A unmodified context means that no SLURM was loaded */
	if(params->cur_ctx == 0) {
		error = -ENOENT;
		goto err;
	}

	return 0;
err:
	db_slurm_destroy(db);
	params->db_slurm = NULL;
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
	params->cur_ctx = 0;

	*result = params;
	return 0;
}

int
slurm_apply(struct db_table **base, struct db_slurm **last_slurm)
{
	struct slurm_parser_params *params = NULL;
	int error;

	if (config_get_slurm() == NULL)
		return 0;

	error = slurm_create_parser_params(&params);
	if (error)
		return error;

	error = slurm_load(params);
	switch (error) {
	case 0:
		/* Use as last valid slurm */
		if (*last_slurm != NULL)
			db_slurm_destroy(*last_slurm);
		*last_slurm = params->db_slurm;
		db_slurm_update_time(*last_slurm);
		break;
	case -EEXIST:
		/* Syntax error, use last valid slurm, log as info */
		if (*last_slurm != NULL) {
			pr_warn("A previous valid version of the SLURM exists and will be applied");
			params->db_slurm = *last_slurm;
			db_slurm_log(params->db_slurm);
		}
		break;
	default:
		/* Some other error, discard SLURM */
		if (*last_slurm != NULL) {
			pr_info("Discarding previous valid SLURM");
			db_slurm_destroy(*last_slurm);
			*last_slurm = NULL;
		}
		goto success;
	}

	/* If there's no SLURM, stop */
	if (params->db_slurm == NULL)
		goto success;

	/* Deep copy of the base so that updates can be reverted */
	error = db_table_clone(&params->db_table, *base);
	if (error)
		goto release_slurm;

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
release_slurm:
	db_slurm_destroy(params->db_slurm);
	free(params);
	return error;
}
