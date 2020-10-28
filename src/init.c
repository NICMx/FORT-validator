#include "init.h"

#include <errno.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>

#include "log.h"
#include "http/http.h"

/*
 * Quite simple: expect 'yes' from stdin (ignore case)
 */
static int
read_stdin(char const *file)
{
	char c;

	c = getchar();
	if (c != 'y' && c != 'Y')
		goto err;

	c = getchar();
	if (c != 'e' && c != 'E')
		goto err;

	c = getchar();
	if (c != 's' && c != 'S')
		goto err;

	if (feof(stdin) || (c = getchar()) == '\n')
		return 0;
err:
	fprintf(stdout,
	    "\nWarning: The conditions weren't accepted, the TAL '%s' won't be downloaded.\n",
	    file);
	return EINVAL;
}

static int
fetch_url(char const *url, char const *accept_message, void *arg)
{
	char const *prefix = "https://";
	char const *dest_dir = arg;
	char *dest_file;
	char *dest;
	size_t prefix_len;
	size_t url_len;
	size_t dest_dir_len;
	size_t extra_slash;
	size_t offset;
	int error;

	prefix_len = strlen(prefix);
	url_len = strlen(url);
	dest_dir_len = strlen(dest_dir);

	if (url_len <= prefix_len ||
	    strncasecmp(url, prefix, prefix_len) != 0)
		return pr_op_err("Invalid HTTPS URL: '%s'", url);

	dest_file = strrchr(url, '/') + 1;
	if (*dest_file == '\0')
		return pr_op_err("HTTPS URL '%s' must be a file location", url);

	/* Each location must be an HTTPS URI */
	do {
		if (accept_message == NULL)
			break;

		fprintf(stdout, "%s\n", accept_message);
		error = read_stdin(dest_file);
		/* On error, let the other TALs to be downloaded */
		if (error)
			return 0;
	} while (0);

	extra_slash = (dest_dir[dest_dir_len - 1] == '/') ? 0 : 1;

	dest = malloc(dest_dir_len + extra_slash + strlen(dest_file) + 1);
	if (dest == NULL)
		return pr_enomem();

	offset = 0;
	strcpy(dest + offset, dest_dir);
	offset += dest_dir_len;
	if (extra_slash) {
		strcpy(dest + offset, "/");
		offset += extra_slash;
	}
	strcpy(dest + offset, dest_file);
	offset += strlen(dest_file);
	dest[offset] = '\0';

	error = http_direct_download(url, dest);
	if (error) {
		fprintf(stderr, "Couldn't fetch '%s'.\n", dest);
		free(dest);
		return error;
	}

	fprintf(stdout, "Successfully fetched '%s'!\n", dest);
	free(dest);
	return 0;
}

int
init_tals_exec(struct init_locations *source, char const *dest)
{
	return init_locations_foreach(source, fetch_url, (void *)dest);
}
