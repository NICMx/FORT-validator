#include "http.h"

#include <check.h>
#include "file.h"

static int dl_error;
static char const *dls[8];
static unsigned int https_counter; /* Times http_download() was called */

int
http_download(char const *url, char const *path, curl_off_t ims, bool *changed)
{
	char const *content;

	if (dl_error) {
		printf("Simulating failed HTTP download.\n");
		https_counter++;
		if (changed)
			*changed = false;
		return dl_error;
	}

	printf("Simulating HTTP download: %s -> %s\n", url, path);

	content = dls[https_counter++];
	if (!content)
		ck_abort_msg("Test was not expecting an HTTP download.");

	ck_assert_int_eq(0, file_write_full(path,
	    (unsigned char const *)content, strlen(content)));

	if (changed)
		*changed = true;
	return 0;
}
