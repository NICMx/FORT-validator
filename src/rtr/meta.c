#include "rtr/meta.h"

#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "alloc.h"
#include "common.h"
#include "config.h"
#include "log.h"
#include "file.h"

/* TODO delete in Fort2 */
char *
rtr_filename(char const *a, char const *b)
{
	char const *root;
	char *result;
	size_t len;
	int ret, error;

	root = config_get_local_repository();

	len = strlen(root) + strlen("/rtr") + 1;
	if (a) {
		len += 1 + strlen(a);
		if (b)
			len += 1 + strlen(b);
	}

	result = pmalloc(len);

	if (b)
		ret = snprintf(result, len, "%s/rtr/%s/%s", root, a, b);
	else if (a)
		ret = snprintf(result, len, "%s/rtr/%s", root, a);
	else
		ret = snprintf(result, len, "%s/rtr", root);

	if (ret < 0 || len <= ret) {
		error = errno;
		if (!error)
			error = EINVAL;
		pr_crit("snprintf(): %s", strerror(error));
	}

	return result;
}

/* TODO delete in Fort2 */
char *
rtr_filename2(serial_t serial, char const *b)
{
	char const *root;
	char *result;
	size_t len;
	int ret, error;

	root = config_get_local_repository();

	len = strlen(root) + strlen("/rtr/") + 10 + 1;
	if (b)
		len += 1 + strlen(b);
	result = pmalloc(len);

	ret = b
	    ? snprintf(result, len, "%s/rtr/%u/%s", root, serial, b)
	    : snprintf(result, len, "%s/rtr/%u", root, serial);
	if (ret < 0 || len <= ret) {
		error = errno;
		if (!error)
			error = EINVAL;
		pr_crit("snprintf(): %s", strerror(error));
	}

	return result;
}

void
rtr_new_metadata(struct rtr_metadata *rtr)
{
	time_t now = 0x1234u;
	get_current_time(&now);
	rtr->session = now & 0xFFFFu;
	rtr->serial = 0;
}

int
rtr_save_metadata(struct rtr_metadata *rtr)
{
	char *filepath;
	FILE *file;
	int error = 0;

	filepath = rtr_filename("metadata", NULL);

	file = fopen(filepath, "w");
	if (!file) {
		error = errno;
		pr_op_err("Cannot open '%s' for writing: %s",
		    filepath, strerror(error));
		free(filepath);
		return error;
	}

	free(filepath);

	if (fprintf(file, "session:%u serial:%u", rtr->session, rtr->serial) < 0)
		error = pr_op_err("fprintf(serial) failed.");

	fclose(file);
	return error;
}

int
rtr_load_metadata(struct rtr_metadata *rtr)
{
	char *filepath;
	FILE *file;
	unsigned int session;
	unsigned int serial;
	int error = 0;

	filepath = rtr_filename("metadata", NULL);

	file = fopen(filepath, "r");
	if (!file) {
		free(filepath);
		return errno;
	}

	free(filepath);

	if (fscanf(file, "session:%u serial:%u", &session, &serial) >= 2) {
		rtr->session = session;
		rtr->serial = serial;
	} else {
		error = EINVAL;
	}

	fclose(file);
	return error;
}

int
rtr_serial_stat(serial_t serial)
{
	char *path;
	int ret;

	path = rtr_filename2(serial, NULL);
	ret = file_exists(path);
	free(path);

	return ret;
}

int
rtr_open_file(serial_t serial, char const *basename, char const *mode,
    FILE **result)
{
	char *path;
	FILE *file;
	int ret;

	path = rtr_filename2(serial, basename);

	file = fopen(path, mode);
	if (!file) {
		ret = errno;
		pr_op_err("Cannot open '%s' in '%s' mode: %s",
		    path, mode, strerror(ret));
		free(path);
		return ret;
	}

	free(path);

	*result = file;
	return 0;
}
