#include "rtr/meta.h"

#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "alloc.h"
#include "common.h"
#include "config.h"
#include "data_structure/common.h"
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
rtridx_init(struct rtr_index *idx)
{
	time_t now;

	now = time(NULL);
	if (now == (time_t)-1)
		pr_crit("time(NULL) returned (time_t) -1.");

	idx->session = now & 0xFFFF;
	idx->serials = NULL;
}

int
rtridx_save(struct rtr_index *idx)
{
	char *path;
	FILE *file;
	struct rtr_serial *srl;
	int error;

	path = rtr_filename("index", NULL);

	file = fopen(path, "w");
	if (!file) {
		error = errno;
		pr_op_err("Cannot open '%s' for writing: %s",
		    path, strerror(error));
		free(path);
		return error;
	}

	free(path);

	if (fprintf(file, "session:%u\n", idx->session) < 0) {
		error = pr_op_err("fprintf(session) failed.");
		goto end;
	}

	for (srl = idx->serials; srl; srl = srl->next) {
		if (fprintf(file, "serial:%u date:%04d-%02d-%02dT%02d:%02d:%02dZ\n",
		    srl->serial, srl->date.tm_year + 1900, srl->date.tm_mon + 1,
		    srl->date.tm_mday, srl->date.tm_hour, srl->date.tm_min,
		    srl->date.tm_sec) < 0) {
			error = pr_op_err("fprintf(serial) failed.");
			goto end;
		}
	}

	error = 0;

end:	fclose(file);
	return error;
}

/*
 * If @all is true, loads all the serials from the index.
 * Otherwise loads only the most recent one.
 */
int
rtridx_load(struct rtr_index *idx, bool all)
{
	char *filepath;
	FILE *file;
	char buf[64];
	unsigned int se;
	struct rtr_serial *srl, *prev;
	int error;

	idx->serials = NULL;

	filepath = rtr_filename("index", NULL); /* cache/rtr/index */

	file = fopen(filepath, "r");
	if (!file) {
		error = errno;
		if (error != ENOENT)
			pr_op_warn("Cannot open RTR index: %s", strerror(error));
		free(filepath);
		return error;
	}

	free(filepath);

	if (!fgets(buf, sizeof(buf), file)) {
		pr_op_debug("RTR index seems empty.");
		goto fail;
	}
	if (sscanf(buf, "session:%u", &se) < 1 || se > UINT16_MAX) {
		pr_op_debug("First line of RTR index is not a session.");
		goto fail;
	}

	idx->session = se;
	prev = NULL;

	while (fgets(buf, sizeof(buf), file) != NULL) {
		srl = pzalloc(sizeof(struct rtr_serial));

		if (sscanf(buf, "serial:%u date:%d-%d-%dT%d:%d:%dZ",
		    &se, &srl->date.tm_year, &srl->date.tm_mon,
		    &srl->date.tm_mday, &srl->date.tm_hour, &srl->date.tm_min,
		    &srl->date.tm_sec) < 1 || se > UINT32_MAX) {
			pr_op_debug("Malformed serial in RTR index.");
			goto fail;
		}
		srl->serial = se;

		if (idx->serials) {
			if (serial_le(idx->serials->serial, srl->serial)) {
				pr_op_debug("RTR index serials are not sorted.");
				goto fail;
			}
		}

		srl->date.tm_year -= 1900;
		srl->date.tm_mon -= 1;
		if (prev)
			prev->next = srl;
		else
			idx->serials = srl;
		prev = srl;

		if (!all)
			break;
	}

	fclose(file);
	return 0;

fail:	fclose(file);
	rtridx_cleanup(idx);
	return ENOENT;
}

serial_t
rtridx_add_serial(struct rtr_index *idx)
{
	struct rtr_serial *srl;
	time_t now;

	srl = pmalloc(sizeof(struct rtr_serial));

	srl->serial = idx->serials ? (idx->serials->serial + 1) : 1;

	now = time(NULL);
	if (now == (time_t)-1)
		pr_crit("time(NULL) returned (time_t) -1.");
	if (gmtime_r(&now, &srl->date) == NULL)
		pr_crit("gmtime_r(now) failed: %s", strerror(errno));

	srl->next = idx->serials;
	idx->serials = srl;

	return srl->serial;
}

void
rtridx_cleanup(struct rtr_index *idx)
{
	struct rtr_serial *srl;

	while (idx->serials) {
		srl = idx->serials;
		idx->serials = srl->next;
		free(srl);
	}
}

void
rtridx_print(struct rtr_index *idx)
{
	struct rtr_serial *srl;

	printf("==== RTR index ====\n");

	if (!idx) {
		printf("<Empty>\n");
		return;
	}

	printf("session:%u\n", idx->session);
	printf("serials:\n");

	for (srl = idx->serials; srl; srl = srl->next)
		printf("  serial:%u date:%04d-%02d-%02dT%02d:%02d:%02dZ\n",
		    srl->serial,
		    srl->date.tm_year + 1900, srl->date.tm_mon + 1, srl->date.tm_mday,
		    srl->date.tm_hour, srl->date.tm_min + 1, srl->date.tm_sec);
}

static bool
is_number(char const *str)
{
	if (*str == 0)
		return false;

	for (; *str != 0; str++)
		if (*str < '0' || '9' < *str)
			return false;

	return true;
}

static void
rm_rf(char *path)
{
	int error;

	error = file_rm_rf(path);
	if (error < 0)
		pr_op_warn("Cannot delete %s: nftw returned %d", path, error);
	else if (error)
		pr_op_warn("Cannot delete %s: %s", path, strerror(error));

	free(path);
}

static void
delete_unindexed_serials(serial_t min, serial_t max)
{
	char *path;
	DIR *dir;
	struct dirent *file;
	serial_t serial;

	path = rtr_filename(NULL, NULL);
	dir = opendir(path);
	free(path);
	if (!dir) {
		if (errno != ENOENT)
			pr_op_warn("Cannot clean rtr directory: %s",
			    strerror(errno));
		return;
	}

	FOREACH_DIR_FILE(dir, file) {
		if (S_ISDOTS(file) || strcmp(file->d_name, "index") == 0)
			continue;
		if (!is_number(file->d_name))
			goto rm;

		errno = 0;
		serial = strtoul(file->d_name, NULL, 10);
		if (errno || serial > UINT32_MAX)
			goto rm;

		if (serial_le(min, serial) && serial_le(serial, max))
			continue;

rm:		pr_op_warn("Deleting stray filesystem entry rtr/%s", file->d_name);
		rm_rf(rtr_filename(file->d_name, NULL));
	}
	if (errno)
		pr_op_warn("Cleanup rtr directory traversal interrupted: %s",
		    strerror(errno));

	closedir(dir);
}

/*
 * Cleans cache/rtr.
 * This means dropping serials that exceed the threshold
 * (config_get_deltas_lifetime()) and unknown files or directories
 * directly in cache/rtr.
 */
void
rtridx_clean(struct rtr_index *idx)
{
	struct rtr_serial *srl, **prev;
	serial_t min, max;

	max = idx->serials[0].serial;
	min = max - config_get_deltas_lifetime();

	for (srl = idx->serials, prev = &idx->serials; srl; srl = *prev) {
		if (serial_lt(srl->serial, min) || serial_lt(max, srl->serial)) {
			pr_op_debug("Dropping serial by FIFO: %u", srl->serial);
			rm_rf(rtr_filename2(srl->serial, NULL));
			*prev = srl->next;
			free(srl);
		} else {
			prev = &srl->next;
		}
	}

	if (!idx->serials) {
		/* The session died; we'll create a new one later. */
		pr_op_debug("All serials expired; clearing RTR cache.");
		rm_rf(rtr_filename(NULL, NULL));
		return;
	}

	rtridx_save(idx);

	/* Clean up unindexed serials for paranoia */
	delete_unindexed_serials(min, max);
}

static bool
too_old(struct rtr_serial *srl, time_t now)
{
	time_t serial_date;
	double diff;
	unsigned int lifetime;

	serial_date = timegm(&srl->date);
	if (serial_date == (time_t)-1)
		return true; /* Dunno; delete it */

	diff = difftime(serial_date, now);
	if (diff > 0)
		return true; /* Dunno; delete it */

	/*
	 * This is an estimate. In reality, I'd like deltas_lifetime to be the
	 * timestamp, but I can't because of historical reasons, and also
	 * because it's a lot easier to test as a cycle count.
	 */
	lifetime = config_get_deltas_lifetime() * config_get_validation_interval();

	return (-diff) > lifetime;
}

/* Deletes serials that are too old, based on time. */
void
rtridx_expire(void)
{
	time_t now;
	struct rtr_index idx;
	struct rtr_serial *srl, **prev;
	int error;

	now = time(NULL);
	if (now == (time_t)-1) {
		pr_op_warn("Can't ditch old RTR: time() returned -1.");
		return;
	}

	error = rtridx_load(&idx, true);
	if (error == ENOENT)
		return;
	if (error) {
		pr_op_warn("Can't ditch old RTR: %s", strerror(error));
		return;
	}

	for (srl = idx.serials, prev = &idx.serials; srl; srl = *prev) {
		if (too_old(srl, now)) {
			pr_op_debug("Dropping expired serial: %u", srl->serial);
			rm_rf(rtr_filename2(srl->serial, NULL));
			*prev = srl->next;
			free(srl);
		} else {
			prev = &srl->next;
		}
	}

	if (!idx.serials) {
		/* The session died; we'll create a new one later. */
		pr_op_debug("All serials expired; clearing RTR cache.");
		rm_rf(rtr_filename(NULL, NULL));
		goto end;
	}

	rtridx_save(&idx);
end:	rtridx_cleanup(&idx);
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
