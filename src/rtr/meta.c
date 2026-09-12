#define _DEFAULT_SOURCE 1

#include "rtr/meta.h"

#include "alloc.h"
#include "config.h"
#include "file.h"
#include "log.h"

/* TODO (fine) overkill? */
static char *
rtr_filename(char const *a)
{
	char *result;
	size_t len;
	int ret, error;

	len = strlen("rtr/") + strlen(a) + 1;
	result = pmalloc(len);

	ret = snprintf(result, len, "rtr/%s", a);
	if (ret < 0 || len <= ret) {
		error = errno;
		if (!error)
			error = EINVAL;
		pr_crit("snprintf(): %s", strerror(error));
	}

	return result;
}

/* TODO (fine) overkill? */
char *
rtr_filename2(serial_t serial, char const *b)
{
	char *result;
	size_t len;
	int ret, error;

	len = SERIAL_DIR_MAXSIZE;
	if (b)
		len += 1 + strlen(b);
	result = pmalloc(len);

	ret = b
	    ? snprintf(result, len, "rtr/%u/%s", serial, b)
	    : snprintf(result, len, "rtr/%u", serial);
	if (ret < 0 || len <= ret) {
		error = errno;
		if (!error)
			error = EINVAL;
		pr_crit("snprintf(): %s", strerror(error));
	}

	return result;
}

char const *
rtr_filename3(char *buf, serial_t serial)
{
	int ret, error;

	ret = snprintf(buf, SERIAL_DIR_MAXSIZE, "rtr/%u", serial);
	if (ret < 0 || SERIAL_DIR_MAXSIZE <= ret) {
		error = errno;
		if (!error)
			error = EINVAL;
		pr_crit("snprintf(): %s", strerror(error));
	}

	return buf;
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
	FILE *file;
	struct rtr_serial *srl;
	int error;

	file = fopen("rtr/index", "w");
	if (!file) {
		error = errno;
		pr_err("Cannot open 'rtr/index' for writing: %s",
		    strerror(error));
		return error;
	}

	if (fprintf(file, "session:%u\n", idx->session) < 0) {
		error = pr_err("fprintf(session) failed.");
		goto end;
	}

	for (srl = idx->serials; srl; srl = srl->next) {
		if (fprintf(file, "serial:%u date:%04d-%02d-%02dT%02d:%02d:%02dZ\n",
		    srl->serial, srl->date.tm_year + 1900, srl->date.tm_mon + 1,
		    srl->date.tm_mday, srl->date.tm_hour, srl->date.tm_min,
		    srl->date.tm_sec) < 0) {
			error = pr_err("fprintf(serial) failed.");
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
	FILE *file;
	char buf[64];
	unsigned int se;
	struct rtr_serial *srl, *prev;
	int error;

	idx->serials = NULL;

	file = fopen("rtr/index", "r");
	if (!file) {
		error = errno;
		if (error != ENOENT)
			pr_wrn("Cannot open RTR index: %s", strerror(error));
		return error;
	}

	if (!fgets(buf, sizeof(buf), file)) {
		pr_trc("RTR index seems empty.");
		goto fail;
	}
	if (sscanf(buf, "session:%u", &se) < 1 || se > UINT16_MAX) {
		pr_trc("First line of RTR index is not a session.");
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
			pr_trc("Malformed serial in RTR index.");
			goto fail;
		}
		srl->serial = se;

		if (idx->serials) {
			if (serial_le(idx->serials->serial, srl->serial)) {
				pr_trc("RTR index serials are not sorted.");
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
__rm_rf(char const *path)
{
	int error;

	error = file_rm_rf(path);
	if (error < 0)
		pr_wrn("Cannot delete %s: nftw returned %d", path, error);
	else if (error)
		pr_wrn("Cannot delete %s: %s", path, strerror(error));
}

static void
rm_rf(char *path)
{
	__rm_rf(path);
	free(path);
}

static void
delete_unindexed_serials(serial_t min, serial_t max)
{
	DIR *dir;
	struct dirent *file;
	serial_t serial;

	dir = opendir("rtr");
	if (!dir) {
		if (errno != ENOENT)
			pr_wrn("Cannot clean rtr directory: %s",
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

rm:		pr_wrn("Deleting stray filesystem entry rtr/%s", file->d_name);
		rm_rf(rtr_filename(file->d_name));
	}
	if (errno)
		pr_wrn("Cleanup rtr directory traversal interrupted: %s",
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
	char path[SERIAL_DIR_MAXSIZE];
	struct rtr_serial *srl, **prev;
	serial_t min, max;

	max = idx->serials[0].serial;
	min = max - config_get_deltas_lifetime();

	for (srl = idx->serials, prev = &idx->serials; srl; srl = *prev) {
		if (serial_lt(srl->serial, min) || serial_lt(max, srl->serial)) {
			pr_trc("Dropping serial by FIFO: %u", srl->serial);
			__rm_rf(rtr_filename3(path, srl->serial));
			*prev = srl->next;
			free(srl);
		} else {
			prev = &srl->next;
		}
	}

	if (!idx->serials) {
		/* The session died; we'll create a new one later. */
		pr_trc("All serials expired; clearing RTR cache.");
		__rm_rf("rtr");
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
	char path[SERIAL_DIR_MAXSIZE];
	int error;

	now = time(NULL);
	if (now == (time_t)-1) {
		pr_wrn("Can't ditch old RTR: time() returned -1.");
		return;
	}

	error = rtridx_load(&idx, true);
	if (error == ENOENT)
		return;
	if (error) {
		pr_wrn("Can't ditch old RTR: %s", strerror(error));
		return;
	}

	for (srl = idx.serials, prev = &idx.serials; srl; srl = *prev) {
		if (too_old(srl, now)) {
			pr_trc("Dropping expired serial: %u", srl->serial);
			__rm_rf(rtr_filename3(path, srl->serial));
			*prev = srl->next;
			free(srl);
		} else {
			prev = &srl->next;
		}
	}

	if (!idx.serials) {
		/* The session died; we'll create a new one later. */
		pr_trc("All serials expired; clearing RTR cache.");
		__rm_rf("rtr");
		goto end;
	}

	rtridx_save(&idx);
end:	rtridx_cleanup(&idx);
}

int
rtr_serial_stat(serial_t serial)
{
	char path[SERIAL_DIR_MAXSIZE];
	return file_stat_errno(rtr_filename3(path, serial));
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
		pr_err("Cannot open '%s' in '%s' mode: %s",
		    path, mode, strerror(ret));
		free(path);
		return ret;
	}

	free(path);

	*result = file;
	return 0;
}
