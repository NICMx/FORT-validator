#include "content_info.h"

#include <err.h>
#include <errno.h>
#include <libcmscodec/ContentType.h>
#include "common.h"
#include "file.h"

static void
content_type_print(FILE *stream, asn_oid_arc_t *arcs, unsigned int arc_count)
{
	unsigned int i;

	for (i = 0; i < arc_count; i++) {
		fprintf(stream, "%u", arcs[i]);
		if (i != arc_count - 1)
			fprintf(stream, ".");
	}
}

int
content_type_validate(ContentType_t *ctype)
{
	asn_oid_arc_t expected[] = { 1, 2, 840, 113549, 1, 7, 2 };
	asn_oid_arc_t actual[ARRAY_SIZE(expected)];
	const unsigned int SLOTS = ARRAY_SIZE(expected);
	ssize_t result;
	unsigned int i;

	result = OBJECT_IDENTIFIER_get_arcs(ctype, actual, SLOTS);
	if (result != SLOTS)
		goto failure;

	for (i = 0; i < SLOTS; i++) {
		if (expected[i] != actual[i])
			goto failure;
	}

	return 0;

failure:
	fprintf(stderr, "Incorrect content-type; expected ");
	content_type_print(stderr, expected, SLOTS);
	fprintf(stderr, ", got ");
	content_type_print(stderr, actual, (result < SLOTS) ? result : SLOTS);
	fprintf(stderr, ".\n");
	return -EINVAL;
}

static int
validate(struct ContentInfo *info)
{
	char error_msg[256];
	size_t error_msg_size;
	int error;

	error_msg_size = sizeof(error_msg);
	error = asn_check_constraints(&asn_DEF_ContentInfo, info, error_msg,
	    &error_msg_size);
	if (error == -1) {
		warnx("Error validating content info object: %s", error_msg);
		return -EINVAL;
	}

	return content_type_validate(&info->contentType);
}

static int
decode(struct file_contents *fc, struct ContentInfo **result)
{
	struct ContentInfo *info = NULL;
	asn_dec_rval_t rval;
	int error;

	rval = ber_decode(0, &asn_DEF_ContentInfo, (void **) &info, fc->buffer,
	    fc->buffer_size);
	if (rval.code != RC_OK) {
		warnx("Error decoding content info object: %d", rval.code);
		/* Must free partial content info according to API contracts. */
		content_info_free(info);
		return -EINVAL;
	}

	error = validate(info);
	if (error) {
		content_info_free(info);
		return error;
	}

	*result = info;
	return 0;
}

int
content_info_load(const char *file_name, struct ContentInfo **result)
{
	struct file_contents fc;
	int error;

	error = file_load(file_name, &fc);
	if (error)
		return error;

	error = decode(&fc, result);

	file_free(&fc);
	return error;
}

void
content_info_free(struct ContentInfo *info)
{
	asn_DEF_ContentInfo.op->free_struct(&asn_DEF_ContentInfo, info,
	    ASFM_FREE_EVERYTHING);
}
