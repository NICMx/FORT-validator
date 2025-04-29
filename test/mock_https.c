#include "http.h"

#include <check.h>
#include "file.h"

static int dl_error;
static char const *dls[8];
static unsigned int https_counter; /* Times http_download() was called */

int
http_download(struct uri const *url, char const *path,
    curl_off_t ims, bool *changed)
{
	char const *content;

	if (dl_error) {
		printf("Simulating failed HTTP download.\n");
		https_counter++;
		if (changed)
			*changed = false;
		return dl_error;
	}

	printf("Simulating HTTP download: %s -> %s\n", uri_str(url), path);

	content = dls[https_counter++];
	if (!content)
		ck_abort_msg("Test was not expecting an HTTP download.");

	ck_assert_int_eq(0, file_write_txt(path, content));

	if (changed)
		*changed = true;
	return 0;
}
