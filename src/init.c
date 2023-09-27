#include "init.h"

#include "alloc.h"
#include "config.h"
#include "log.h"
#include "http/http.h"

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

	dest = pmalloc(dest_dir_len + extra_slash + strlen(dest_file) + 1);

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
	/*
	 * APNIC is a bit weird. Some thoughts:
	 *
	 * 1. The 6490 and ripe-validator TALs are obsolete, and Fort has never
	 *    been compatible with them.
	 * 2. apnic.tal is identical to apnic-rfc7730.tal, and neither of them
	 *    contain HTTP URLs.
	 * 3. apnic-rfc7730-https.tal is not actually compliant with RFC 7730;
	 *    it's an RFC 8630 TAL. However, I'm wondering if there's a reason
	 *    why they haven't upgraded it to their default TAL.
	 *
	 * I'll stick to the rsync-only one until I've tested it more.
	 */
	error = fetch_url("https://tal.apnic.net/apnic.tal");
	if (error)
		return error;
	error = fetch_url("https://www.arin.net/resources/manage/rpki/arin.tal");
	if (error)
		return error;
	error = fetch_url("https://www.lacnic.net/innovaportal/file/4983/1/lacnic.tal");
	if (error)
		return error;
	/* I wish they stated why they don't recommend the 8630 TAL. */
	return fetch_url("https://tal.rpki.ripe.net/ripe-ncc.tal");
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
