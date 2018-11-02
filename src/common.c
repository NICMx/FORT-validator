#include "common.h"

#include <err.h>
#include <errno.h>

#define INDENT_MAX 10
static unsigned int indent;

char const *repository;
int NID_rpkiManifest;
int NID_rpkiNotify;

void
pr_indent(void)
{
	unsigned int __indent = indent;
	unsigned int i;

//	if (__indent > INDENT_MAX)
//		__indent = INDENT_MAX;

	for (i = 0; i < __indent; i++)
		printf("  ");
}

void
pr_add_indent(void)
{
	indent++;
}

void
pr_rm_indent(void)
{
	if (indent > 0)
		indent--;
	else
		warnx("Programming error: Too many pr_sub_indent()s.");
}

bool
file_has_extension(char const *file_name, char const *extension)
{
	char *dot;
	dot = strrchr(file_name, '.');
	return dot ? (!strcmp(dot + 1, extension)) : false;
}

/**
 * Converts the global URI @guri to its local (rsync clone) equivalent.
 * For example, given repository "/tmp/rpki" and global uri
 * "rsync://rpki.ripe.net/repo/manifest.mft", returns
 * "/tmp/rpki/rpki.ripe.net/repo/manifest.mft".
 *
 * You need to free the result once you're done.
 */
int
uri_g2l(char const *guri, char **result)
{
	char const *const PREFIX = "rsync://";
	char *luri;
	size_t repository_len;
	size_t prefix_len;
	unsigned int offset;

	prefix_len = strlen(PREFIX);

	if (strncmp(PREFIX, guri, prefix_len) != 0) {
		warnx("Global URI %s does not begin with '%s'.", guri, PREFIX);
		return -EINVAL;
	}

	repository_len = strlen(repository);

	luri = malloc(repository_len
	    + 1 /* slash */
	    + strlen(guri) - prefix_len
	    + 1); /* null chara */
	if (!luri)
		return -ENOMEM;

	offset = 0;
	strcpy(luri + offset, repository);
	offset += repository_len;
	strcpy(luri + offset, "/");
	offset += 1;
	strcpy(luri + offset, &guri[prefix_len]);

	*result = luri;
	return 0;
}

int
gn2uri(GENERAL_NAME *gn, char const **uri)
{
	ASN1_STRING *asn_string;
	int type;

	asn_string = GENERAL_NAME_get0_value(gn, &type);
	if (type != GEN_URI) {
		pr_debug("Unknown GENERAL_NAME type: %d", type);
		return -ENOTSUPPORTED;
	}

	/* TODO is this cast safe? */
	*uri = (char const *) ASN1_STRING_get0_data(asn_string);
	return 0;
}
