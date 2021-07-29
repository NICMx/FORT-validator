#include "init.h"

#include <errno.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>

#include "log.h"
#include "http/http.h"

static bool
download_arin_tal(void)
{
	char c;

	printf("Attention: ARIN requires you to agree to their Relying Party Agreement (RPA) before you can download and use their TAL.\n"
	    "Please download and read https://www.arin.net/resources/manage/rpki/rpa.pdf\n"
	    "If you agree to the terms, type 'yes' and hit Enter: ");

	c = getchar();
	if (c != 'y' && c != 'Y')
		goto cancel;

	c = getchar();
	if (c != 'e' && c != 'E')
		goto cancel;

	c = getchar();
	if (c != 's' && c != 'S')
		goto cancel;

	if (feof(stdin) || (c = getchar()) == '\n')
		return true;

	/* Fall through */
cancel:
	printf("Skipping ARIN's TAL.\n\n");
	return false;
}

static int
fetch_url(char const *url)
{
	char const *prefix = "https://";
	char const *dest_dir;
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
	dest_dir = config_get_tal();
	dest_dir_len = strlen(dest_dir);

	if (url_len <= prefix_len ||
	    strncasecmp(url, prefix, prefix_len) != 0)
		return pr_op_err("Invalid HTTPS URL: '%s'", url);

	dest_file = strrchr(url, '/') + 1;
	if (*dest_file == '\0')
		return pr_op_err("HTTPS URL '%s' must be a file location", url);

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

	fprintf(stdout, "Successfully fetched '%s'!\n\n", dest);
	free(dest);
	return 0;
}

int
download_tals(void)
{
	int error;

	/*
	 * https://afrinic.net/resource-certification/tal
	 * https://www.apnic.net/community/security/resource-certification/tal-archive/
	 * https://www.arin.net/resources/manage/rpki/tal/
	 * https://www.lacnic.net/4984/2/lacnic/rpki-rpki-trust-anchor
	 * https://www.ripe.net/manage-ips-and-asns/resource-management/rpki/ripe-ncc-rpki-trust-anchor-structure
	 */

	error = fetch_url("https://rpki.afrinic.net/tal/afrinic.tal");
	if (error)
		return error;
	error = fetch_url("https://tal.apnic.net/apnic.tal");
	if (error)
		return error;
	if (download_arin_tal())
		error = fetch_url("https://www.arin.net/resources/manage/rpki/arin.tal");
	error = fetch_url("https://www.lacnic.net/innovaportal/file/4983/1/lacnic.tal");
	if (error)
		return error;
	error = fetch_url("https://tal.rpki.ripe.net/ripe-ncc.tal");
	if (error)
		return error;

	return error;
}

int
download_tal0s(void)
{
	int error;

	error = fetch_url("https://tal.apnic.net/apnic-as0.tal");
	if (error)
		return error;

	return fetch_url("https://www.lacnic.net/innovaportal/file/4983/1/lacnic-as0.tal");
}
