#include "report.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "common.h"
#include "config.h"
#include "log.h"

static FILE *stream;	/* Constant during multithreaded */
static bool enabled;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

int
report_enable(void)
{
	char const *path;
	int error;

	path = config_get_report();
	if (!path)
		/* Will not write report, but pr_wrn & pr_err still need to
		 * be sent to TRC */
		goto done;

	stream = fopen(path, "wb");
	if (!stream) {
		error = errno;
		if (error != EEXIST)
			return pr_err("fopen(%s): %s", path, strerror(error));
	}

done:	enabled = true;
	return 0;
}

bool
report_enabled(void)
{
	return enabled;
}

void
report(char const *tag, char const *fmt, va_list vl)
{
	if (!stream)
		return;

	mutex_lock(&lock);
	fprintf(stream, "Severity: %s\n", tag);
	fprintf(stream, "File: %s\n", ""); // XXX
	vfprintf(stream, fmt, vl);
	fprintf(stream, "\n\n");
	mutex_unlock(&lock);
}

void
report_disable(void)
{
	if (stream) {
		fclose(stream);
		stream = NULL;
	}
	enabled = false;
}
