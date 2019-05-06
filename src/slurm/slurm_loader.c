#include "slurm_loader.h"

#include <errno.h>
#include <dirent.h>
#include <stdlib.h>
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

int
slurm_load(void)
{
	DIR *dir_loc;
	struct dirent *dir_ent;
	char const *slurm_dir;
	int error;

	/* Optional configuration */
	slurm_dir = config_get_slurm_location();
	if (slurm_dir == NULL)
		return 0;

	error = slurm_db_init();
	if (error)
		return error;

	dir_loc = opendir(slurm_dir);
	if (dir_loc == NULL)
		return -pr_errno(errno, "Couldn't open dir %s", slurm_dir);

	errno = 0;
	while ((dir_ent = readdir(dir_loc)) != NULL) {
		error = single_slurm_load(slurm_dir, dir_ent->d_name);
		if (error) {
			pr_err("The error was at SLURM file %s",
			    dir_ent->d_name);
			goto end;
		}
		errno = 0;
	}
	if (errno) {
		pr_err("Error reading dir %s", slurm_dir);
		error = -errno;
	}
end:
	closedir(dir_loc);
	return error;
}

void
slurm_cleanup(void)
{
	/* Only if the SLURM was configured */
	if (config_get_slurm_location() != NULL)
		slurm_db_cleanup();
}
