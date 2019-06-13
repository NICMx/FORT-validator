#include "slurm_loader.h"

#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h> /* AF_INET, AF_INET6 (needed in OpenBSD) */
#include <sys/socket.h> /* AF_INET, AF_INET6 (needed in OpenBSD) */

#include "log.h"
#include "config.h"
#include "common.h"
#include "slurm/slurm_db.h"
#include "slurm/slurm_parser.h"

#define SLURM_FILE_EXTENSION	".slurm"

static int
slurm_load(bool *loaded)
{
	/* Optional configuration */
	*loaded = false;
	if (config_get_slurm() == NULL)
		return 0;

	*loaded = true;
	slurm_db_init();

	return process_file_or_dir(config_get_slurm(),
	    SLURM_FILE_EXTENSION, slurm_parse, NULL);
}

static void
slurm_cleanup(void)
{
	/* Only if the SLURM was configured */
	if (config_get_slurm() != NULL)
		slurm_db_cleanup();
}

static int
slurm_pfx_filters_apply(struct vrp const *vrp, void *arg)
{
	struct roa_table *table = arg;

	if (slurm_db_vrp_is_filtered(vrp))
		roa_table_remove_roa(table, vrp);

	return 0;
}

static int
slurm_pfx_assertions_add(struct slurm_prefix *prefix, void *arg)
{
	struct roa_table *table = arg;
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
}

static int
slurm_pfx_assertions_apply(struct roa_table *base)
{
	return slurm_db_foreach_assertion_prefix(slurm_pfx_assertions_add,
	    base);
}

/*
 * Load the SLURM file/dir and try to apply it on @base.
 *
 * On any error the SLURM won't be applied to @base.
 */
int
slurm_apply(struct roa_table **base)
{
	struct roa_table *new_base;
	bool loaded;
	int error;

	loaded = false;
	error = slurm_load(&loaded);
	if (error)
		goto cleanup;

	if (!loaded)
		return 0;

	/* Deep copy of the base so that updates can be reverted */
	error = roa_table_clone(&new_base, *base);
	if (error)
		goto cleanup;

	error = roa_table_foreach_roa(new_base, slurm_pfx_filters_apply,
	    new_base);
	if (error)
		goto release_new;

	error = slurm_pfx_assertions_apply(new_base);
	if (!error) {
		roa_table_destroy(*base);
		*base = new_base;
		goto cleanup;
	}

	/** TODO (next iteration) Apply BGPsec filters and assertions */
release_new:
	roa_table_destroy(new_base);
cleanup:
	slurm_cleanup();
	return error;
}
