#include "print_file.h"

#include <errno.h>
#include "common.h"
#include "config.h"
#include "file.h"
#include "log.h"
#include "asn1/content_info.h"
#include "asn1/asn1c/Certificate.h"
#include "asn1/asn1c/CRL.h"

static json_t *
libcrypto2json(char const *filename, json_t *(*encoder)(ANY_t *))
{
	struct file_contents fc;
	ANY_t any;
	json_t *json;
	int error;

	error = file_load(filename, &fc);
	if (error)
		return NULL;

	memset(&any, 0, sizeof(any));
	any.buf = fc.buffer;
	any.size = fc.buffer_size;

	json = encoder(&any);

	file_free(&fc);
	return json;
}

int
print_file(void)
{
	char const *filename;
	struct ContentInfo *ci;
	json_t *json;
	int error;

	filename = config_get_payload();
	if (str_ends_with(filename, ".cer")) {
		json = libcrypto2json(filename, Certificate_encode_json);
	} else if (str_ends_with(filename, ".crl")) {
		json = libcrypto2json(filename, CRL_encode_json);

	} else {
		error = content_info_load(filename, &ci);
		if (error)
			return error;

		json = json_encode(&asn_DEF_ContentInfo, ci);

		ASN_STRUCT_FREE(asn_DEF_ContentInfo, ci);
	}

	if (json == NULL) {
		pr_op_err("Error parsing object.");
		return error;
	}

	errno = 0;
	if (json_dumpf(json, stdout, JSON_INDENT(4)) < 0) {
		error = errno;
		if (error)
			pr_op_err("Error writing JSON to file: %s", strerror(error));
		else
			pr_op_err("Unknown error writing JSON to file.");
	}

	json_decref(json);
	printf("\n");
	return error;
}
