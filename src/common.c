#include "common.h"

#include <errno.h>
#include <string.h>
#include "log.h"

char const *repository;
size_t repository_len;
int NID_rpkiManifest;
int NID_signedObject;

/* @extension must include the period. */
bool
file_has_extension(char const *filename, size_t filename_len, char const *ext)
{
	size_t ext_len;

	ext_len = strlen(ext);
	if (filename_len < ext_len)
		return false;

	return strncmp(filename + filename_len - ext_len, ext, ext_len) == 0;
}

/**
 * Converts the global URI @guri to its local (rsync clone) equivalent.
 * For example, given repository "/tmp/rpki" and global uri
 * "rsync://rpki.ripe.net/repo/manifest.mft", returns
 * "/tmp/rpki/rpki.ripe.net/repo/manifest.mft".
 *
 * You need to free the result once you're done.
 * This function does not assume that @guri is null-terminated.
 *
 * By contract, if @guri is not RSYNC, this will return ENOTRSYNC.
 * This often should not be treated as an error; please handle gracefully.
 * TODO open call hirarchy.
 */
int
uri_g2l(char const *guri, size_t guri_len, char **result)
{
	static char const *const PREFIX = "rsync://";
	char *luri;
	size_t prefix_len;
	size_t extra_slash;
	size_t offset;

	prefix_len = strlen(PREFIX);

	if (guri_len < prefix_len || strncmp(PREFIX, guri, prefix_len) != 0) {
		pr_err("Global URI does not begin with '%s'.", PREFIX);
		return ENOTRSYNC; /* Not really an error, so not negative */
	}

	guri += prefix_len;
	guri_len -= prefix_len;
	extra_slash = (repository[repository_len - 1] == '/') ? 0 : 1;

	luri = malloc(repository_len + extra_slash + guri_len + 1);
	if (!luri)
		return -ENOMEM;

	offset = 0;
	strcpy(luri + offset, repository);
	offset += repository_len;
	strncpy(luri + offset, "/", extra_slash);
	offset += extra_slash;
	strncpy(luri + offset, guri, guri_len);
	offset += guri_len;
	luri[offset] = '\0';

	*result = luri;
	return 0;
}
