#include "slurm_loader.h"

#include <err.h>
#include <errno.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>

#include "configuration.h"
#include "slurm_parser.h"

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
	if (tmp == NULL) {
		warn("Couldn't create temporal char for SLURM");
		return -errno;
	}
	tmp = realloc(tmp, strlen(tmp) + 1 + strlen(file_name) + 1);
	if (tmp == NULL) {
		warn("Couldn't reallocate temporal char for SLURM");
		return -errno;
	}

	strcat(tmp, "/");
	strcat(tmp, file_name);
	fullpath = realpath(tmp, NULL);
	if (fullpath == NULL) {
		warn("Error getting real path for file '%s' at dir '%s'",
		    dir_name, file_name);
		free(tmp);
		return -errno;
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

	dir_loc = opendir(slurm_dir);
	if (dir_loc == NULL) {
		warn("Couldn't open dir %s", slurm_dir);
		return -errno;
	}

	error = 0;
	errno = 0;
	while ((dir_ent = readdir(dir_loc)) != NULL) {
		error = single_slurm_load(slurm_dir, dir_ent->d_name);
		if (error)
			goto end;
		errno = 0;
	}
	if (errno) {
		warn("Error reading dir %s", slurm_dir);
		error = -errno;
	}
end:
	closedir(dir_loc);
	return error;
}

void
slurm_cleanup(void)
{
	/* TODO Nothing for now */
}
