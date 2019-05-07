#include "slurm_loader.h"

#include <errno.h>
#include <dirent.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "log.h"
#include "config.h"
#include "slurm/slurm_db.h"
#include "slurm/slurm_parser.h"

#define SLURM_FILE_EXTENSION	".slurm"

static int
single_slurm_load(const char *dir_name, const char *file_name)
{
	char *ext, *fullpath, *tmp;
	int error;

	ext = strrchr(file_name, '.');
	/* Ignore file if extension isn't the expected */
	if (ext == NULL || strcmp(ext, SLURM_FILE_EXTENSION) != 0)
		return 0;

	/* Get the full file path */
	tmp = strdup(dir_name);
	if (tmp == NULL)
		return -pr_errno(errno,
		    "Couldn't create temporal char for SLURM");

	tmp = realloc(tmp, strlen(tmp) + 1 + strlen(file_name) + 1);
	if (tmp == NULL)
		return -pr_errno(errno,
		    "Couldn't reallocate temporal char for SLURM");

	strcat(tmp, "/");
	strcat(tmp, file_name);
	fullpath = realpath(tmp, NULL);
	if (fullpath == NULL) {
		free(tmp);
		return -pr_errno(errno,
		    "Error getting real path for file '%s' at dir '%s'",
		    dir_name, file_name);
	}

	error = slurm_parse(fullpath);
	free(tmp);
	free(fullpath);
	return error;
}

static int
slurm_load(bool *loaded)
{
	DIR *dir_loc;
	struct dirent *dir_ent;
	char const *slurm_dir;
	int error;

	/* Optional configuration */
	*loaded = false;
	slurm_dir = config_get_slurm_location();
	if (slurm_dir == NULL)
		return 0;

	*loaded = true;
	slurm_db_init();

	dir_loc = opendir(slurm_dir);
	if (dir_loc == NULL) {
		error = -pr_errno(errno, "Couldn't open dir %s", slurm_dir);
		goto end;
	}

	errno = 0;
	while ((dir_ent = readdir(dir_loc)) != NULL) {
		error = single_slurm_load(slurm_dir, dir_ent->d_name);
		if (error) {
			pr_err("The error was at SLURM file %s",
			    dir_ent->d_name);
			goto close_dir;
		}
		errno = 0;
	}
	if (errno) {
		pr_err("Error reading dir %s", slurm_dir);
		error = -errno;
	}
close_dir:
	closedir(dir_loc);
end:
	return error;
}

static void
slurm_cleanup(void)
{
	/* Only if the SLURM was configured */
	if (config_get_slurm_location() != NULL)
		slurm_db_cleanup();
}

static int
slurm_pfx_filters_apply(struct vrp *vrp, void *arg)
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
	return -pr_crit("Unkown addr family type");
}

static int
slurm_pfx_assertions_apply(struct roa_table *base)
{
	return slurm_db_foreach_assertion_prefix(slurm_pfx_assertions_add,
	    base);
}

int
slurm_apply(struct roa_table *base)
{
	bool loaded;
	int error;

	loaded = false;
	error = slurm_load(&loaded);
	if (error)
		goto cleanup;

	if (!loaded)
		return 0;

	error = roa_table_foreach_roa(base, slurm_pfx_filters_apply, base);
	if (error)
		goto cleanup;

	error = slurm_pfx_assertions_apply(base);

	/** TODO Apply BGPsec filters and assertions */

cleanup:
	slurm_cleanup();
	return error;
}
