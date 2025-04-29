#include "init.h"

#include "config.h"
#include "http.h"
#include "types/path.h"

static int
fetch_url(char const *url, char const *filename)
{
	struct uri uri;
	char *path;
	int error;

	error = uri_init(&uri, url);
	if (error)
		return error;

	path = path_join(config_get_tal(), filename);

	error = http_download(&uri, path, 0, NULL);
	if (error) {
		fprintf(stderr, "Couldn't fetch '%s': %s\n",
		    path, strerror(abs(error)));
		goto end;
	}

	fprintf(stdout, "Successfully fetched '%s'!\n\n", path);
end:	free(path);
	uri_cleanup(&uri);
	return error;
}

int
download_tals(void)
{
	int error;

	/* https://afrinic.net/resource-certification/tal */
	error = fetch_url("https://rpki.afrinic.net/tal/afrinic.tal", "afrinic.tal");
	if (error)
		return error;

	/*
	 * https://www.apnic.net/community/security/resource-certification/tal-archive/
	 *
	 * APNIC is weird:
	 *
	 * 1. The 6490 and ripe-validator TALs are obsolete, and Fort has never
	 *    been compatible with them.
	 * 2. apnic.tal is identical to apnic-rfc7730.tal, and neither of them
	 *    contain HTTP URLs.
	 * 3. apnic-rfc7730-https.tal is not actually compliant with RFC 7730;
	 *    it's an RFC 8630 TAL. Despite seemingly not being the recommended
	 *    one, both Routinator and rpki-client are using it.
	 */
	error = fetch_url("https://tal.apnic.net/tal-archive/apnic-rfc7730-https.tal", "apnic.tal");
	if (error)
		return error;

	/* https://www.arin.net/resources/manage/rpki/tal/ */
	error = fetch_url("https://www.arin.net/resources/manage/rpki/arin.tal", "arin.tal");
	if (error)
		return error;

	/* https://www.lacnic.net/4984/2/lacnic/rpki-rpki-trust-anchor */
	error = fetch_url("https://www.lacnic.net/innovaportal/file/4983/1/lacnic.tal", "lacnic.tal");
	if (error)
		return error;

	/*
	 * https://www.ripe.net/manage-ips-and-asns/resource-management/rpki/ripe-ncc-rpki-trust-anchor-structure
	 * I wish they stated why they don't recommend the 8630 TAL.
	 */
	return fetch_url("https://tal.rpki.ripe.net/ripe-ncc.tal", "ripe-ncc.tal");
}

int
download_tal0s(void)
{
	int error;

	error = fetch_url("https://tal.apnic.net/tal-archive/apnic-as0-rfc7730-https.tal", "apnic-as0.tal");
	if (error)
		return error;
	return fetch_url("https://www.lacnic.net/innovaportal/file/4983/1/lacnic-as0.tal", "lacnic-as0.tal");
}
