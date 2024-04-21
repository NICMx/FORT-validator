#include "print_file.h"

#include <errno.h>
#include "config.h"
#include "log.h"
#include "asn1/content_info.h"

int
print_file(void)
{
	char const *filename;
	struct ContentInfo *ci;
	json_t *json;
	int error;

	filename = config_get_payload();
//	if (str_starts_with(filename, "rsync://")) {
//
//	} else {
		error = content_info_load(filename, &ci);
		if (error)
			return error;
//	}

	json = json_encode(&asn_DEF_ContentInfo, ci);
	if (json == NULL) {
		pr_op_err("Error parsing object.");
		goto end;
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
end:	ASN_STRUCT_FREE(asn_DEF_ContentInfo, ci);
	return error;
}
