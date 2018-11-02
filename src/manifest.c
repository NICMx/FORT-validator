#include "manifest.h"

#include <dirent.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "certificate.h"
#include "common.h"
#include "asn1/content_info.h"
#include "asn1/signed_data.h"
#include "asn1/manifest.h"

bool
is_manifest(char const *file_name)
{
	return file_has_extension(file_name, "mft");
}

/**
 * Given manifest path @mft and its referenced file @file, returns a path
 * @file can be accessed with.
 *
 * ie. if @mft is "a/b/c.mft" and @file is "d/e/f.cer", returns "a/b/d/e/f.cer".
 *
 * The result needs to be freed in the end.
 */
static int
get_relative_file(char const *mft, char const *file, char **result)
{
	char *joined;
	char *slash_pos;
	int dir_len;

	slash_pos = strrchr(mft, '/');
	if (slash_pos == NULL) {
		joined = malloc(strlen(file) + 1);
		if (!joined)
			return -ENOMEM;
		strcpy(joined, file);
		goto succeed;
	}

	dir_len = (slash_pos + 1) - mft;
	joined = malloc(dir_len + strlen(file) + 1);
	if (!joined)
		return -ENOMEM;

	strncpy(joined, mft, dir_len);
	strcpy(joined + dir_len, file);

succeed:
	*result = joined;
	return 0;
}

static int
handle_file(char const *mft, IA5String_t *string)
{
	char *luri;
	int error;

	/* TODO This is probably not correct. */
	pr_debug_add("File %s {", string->buf);

	error = get_relative_file(mft, (char const *) string->buf, &luri);
	if (error)
		goto end;

	if (is_certificate(luri))
		error = handle_certificate(luri);
	else
		pr_debug0("Unhandled file type.");

	free(luri);
end:
	pr_debug0_rm("}");
	return error;
}

static int
__handle_manifest(char const *mft, struct Manifest *manifest)
{
	int i;
	int error;

	for (i = 0; i < manifest->fileList.list.count; i++) {
		error = handle_file(mft,
		    &manifest->fileList.list.array[i]->file);
		if (error)
			return error;
	}

	return 0;
}

int
handle_manifest(char const *file_path)
{
	struct ContentInfo *cinfo;
	struct SignedData *sdata;
	struct Manifest *manifest;
	int error;

	pr_debug_add("Manifest %s {", file_path);

	error = content_info_load(file_path, &cinfo);
	if (error)
		goto end1;

	error = signed_data_decode(&cinfo->content, &sdata);
	if (error)
		goto end2;

	error = manifest_decode(sdata, &manifest);
	if (error)
		goto end3;

	error = __handle_manifest(file_path, manifest);

	manifest_free(manifest);
end3:	signed_data_free(sdata);
end2:	content_info_free(cinfo);
end1:	pr_debug0_rm("}");
	return error;
}
