#include "stats.h"

#include <pthread.h>

#include "alloc.h"
#include "common.h"
#include "log.h"
#include "data_structure/uthash.h"

struct stats_gauge {
	char *name;
	unsigned int value;
	time_t timestamp;

	UT_hash_handle hh;
};

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static struct stats_gauge *gauges;

struct stats_gauge *stat_rtr_connections;

/* Steals ownership of @name */
static struct stats_gauge *
add_gauge(char *name, size_t namelen, unsigned int value)
{
	struct stats_gauge *old;
	struct stats_gauge *new;
	struct stats_gauge *delete;
	struct stats_gauge *result;

	new = pzalloc(sizeof(struct stats_gauge));
	new->name = name;
	new->value = value;
	new->timestamp = time(NULL);

	if (namelen == 0)
		namelen = strlen(name);

	mutex_lock(&lock);
	HASH_FIND(hh, gauges, name, namelen, old);
	if (old != NULL) {
		old->value = value;
		old->timestamp = new->timestamp;
		delete = new;
		result = old;
	} else {
		HASH_ADD_KEYPTR(hh, gauges, name, namelen, new);
		delete = NULL;
		result = new;
	}
	mutex_unlock(&lock);

	if (delete) {
		free(delete->name);
		free(delete);
	}

	return result;
}

#define ADD_GAUGE(name) add_gauge(pstrdup(name), 0, 0)

int
stats_setup(void)
{
	stat_rtr_connections = ADD_GAUGE("fort_rtr_current_connections");
	return 0;
}

void
stats_teardown(void)
{
	struct stats_gauge *gauge, *tmp;

	HASH_ITER(hh, gauges, gauge, tmp) {
		HASH_DEL(gauges, gauge);
		free(gauge->name);
		free(gauge);
	}
}

void
stats_gauge_set(struct stats_gauge *gauge, unsigned int value)
{
	time_t now = time(NULL);

	mutex_lock(&lock);
	gauge->value = value;
	gauge->timestamp = now;
	mutex_unlock(&lock);
}

void
stats_set_tal_vrps(char const *tal_path, char const *proto, unsigned int value)
{
	char const *ta, *dot;
	size_t talen;

	size_t baselen;
	size_t keylen;
	char *key;
	int chars;

	ta = strrchr(tal_path, '/');
	ta = (ta == NULL) ? tal_path : (ta + 1);
	dot = strrchr(ta, '.');
	talen = dot ? (dot - ta) : strlen(ta);

	baselen = strlen("fort_valid_vrps_total{ta=\"\",proto=\"\"}");
	keylen = baselen + talen + strlen(proto) + 1;

	key = pmalloc(keylen);
	chars = snprintf(key, keylen,
	    "fort_valid_vrps_total{ta=\"%.*s\",proto=\"%s\"}",
	    (int)talen, ta, proto);
	if (chars < 0 || keylen <= chars) {
		free(key);
		pr_op_warn("Cannot create valid_vrps_total stat: %d", chars);
		return;
	}

	add_gauge(key, keylen - 1, value);
}

struct stats_buffer {
	char *str;
	char *cursor;
	size_t capacity;
};

static bool
printf_buf(struct stats_buffer *buf, char const *fmt, ...)
{
	size_t available;
	int written;
	va_list ap;

	available = buf->capacity - (buf->cursor - buf->str);

	va_start(ap, fmt);
	written = vsnprintf(buf->cursor, available, fmt, ap);
	va_end(ap);

	if (written < 0 || available <= written)
		return false;

	buf->cursor += written;
	return true;
}

char *
stats_export(void)
{
	struct stats_buffer buf;
	struct stats_gauge *gauge, *tmp;

	buf.capacity = 1024;
	buf.str = buf.cursor = pmalloc(buf.capacity);

	HASH_ITER(hh, gauges, gauge, tmp) {
		if (!printf_buf(&buf, "%s %u", gauge->name, gauge->value))
			goto cancel;
		if (gauge->timestamp != ((time_t)-1))
			if (!printf_buf(&buf, " %jd", (intmax_t)gauge->timestamp))
				goto cancel;
		if (!printf_buf(&buf, "\n"))
			goto cancel;
	}

	if (!printf_buf(&buf, "# EOF\n"))
		goto cancel;

	if (buf.cursor >= buf.str + buf.capacity)
		goto cancel;
	*buf.cursor = '\0';

	return buf.str;

cancel:
	free(buf.str);
	pr_op_err("Cannot create Prometheus response: Too many stats");
	return NULL;
}
