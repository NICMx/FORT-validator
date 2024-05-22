#include "config/file_type.h"

#include <getopt.h>

#include "config/str.h"
#include "log.h"

#define VALUE_ROA	"roa"
#define VALUE_MFT	"mft"
#define VALUE_GBR	"gbr"
#define VALUE_CER	"cer"
#define VALUE_CRL	"crl"

#define DEREFERENCE(void_value) (*((enum file_type *) void_value))

static void
print_file_type(struct option_field const *field, void *value)
{
	char const *str = NULL;

	switch (DEREFERENCE(value)) {
	case FT_UNK:
		break;
	case FT_ROA:
		str = VALUE_ROA;
		break;
	case FT_MFT:
		str = VALUE_MFT;
		break;
	case FT_GBR:
		str = VALUE_GBR;
		break;
	case FT_CER:
		str = VALUE_CER;
		break;
	case FT_CRL:
		str = VALUE_CRL;
		break;
	}

	pr_op_info("%s: %s", field->name, str);
}

static int
parse_argv_mode(struct option_field const *field, char const *str,
    void *result)
{
	if (strcmp(str, VALUE_ROA) == 0)
		DEREFERENCE(result) = FT_ROA;
	else if (strcmp(str, VALUE_MFT) == 0)
		DEREFERENCE(result) = FT_MFT;
	else if (strcmp(str, VALUE_GBR) == 0)
		DEREFERENCE(result) = FT_GBR;
	else if (strcmp(str, VALUE_CER) == 0)
		DEREFERENCE(result) = FT_CER;
	else if (strcmp(str, VALUE_CRL) == 0)
		DEREFERENCE(result) = FT_CRL;
	else
		return pr_op_err("Unknown file type: '%s'", str);

	return 0;
}

static int
parse_json_mode(struct option_field const *opt, struct json_t *json,
    void *result)
{
	char const *string;
	int error;

	error = parse_json_string(json, opt->name, &string);
	return error ? error : parse_argv_mode(opt, string, result);
}

const struct global_type gt_file_type = {
	.has_arg = required_argument,
	.size = sizeof(enum file_type),
	.print = print_file_type,
	.parse.argv = parse_argv_mode,
	.parse.json = parse_json_mode,
	.arg_doc = VALUE_ROA "|" VALUE_MFT "|" VALUE_GBR "|" VALUE_CER "|" VALUE_CRL,
};
