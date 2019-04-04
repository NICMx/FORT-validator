#include "slurm_parser.h"

#include <err.h>
#include <errno.h>
#include <jansson.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "../address.h"
#include "../configuration.h"

/* JSON members */
#define SLURM_VERSION			"slurmVersion"
#define VALIDATION_OUTPUT_FILTERS	"validationOutputFilters"
#define PREFIX_FILTERS			"prefixFilters"
#define BGPSEC_FILTERS			"bgpsecFilters"
#define LOCALLY_ADDED_ASSERTIONS	"locallyAddedAssertions"
#define PREFIX_ASSERTIONS		"prefixAssertions"
#define BGPSEC_ASSERTIONS		"bgpsecAssertions"

/* Prefix and BGPsec properties */
#define PREFIX				"prefix"
#define ASN				"asn"
#define MAX_PREFIX_LENGTH		"maxPrefixLength"
#define SKI				"SKI"
#define ROUTER_PUBLIC_KEY		"routerPublicKey"
#define COMMENT				"comment"

#define CHECK_REQUIRED(element, name)				\
	if (element == NULL) {					\
		warnx("SLURM member '%s' is required", name);	\
		return -EINVAL;					\
	}

struct slurm_prefix {
	u_int8_t data_flag;
	u_int32_t asn;
	union {
		struct	in_addr ipv4_prefix;
		struct	in6_addr ipv6_prefix;
	};
	u_int8_t	prefix_length;
	u_int8_t	max_prefix_length;
	u_int8_t	addr_fam;
	char const	*comment;
};

struct slurm_bgpsec {
	u_int8_t data_flag;
	u_int32_t asn;
	/* TODO Add SKI (Base64) and routerPublicKey */
	char const	*comment;
};

static int handle_json(json_t *);
static int json_get_string(json_t *, char const *, char const **);
static int json_get_int(json_t *, char const *, json_int_t *);
static json_t *json_get_array(json_t *, char const *);
static json_t *json_get_object(json_t *, char const *);

int
slurm_load(void)
{
	json_t *json_root;
	json_error_t json_error;
	int error;

	/* Optional configuration */
	if (config_get_slurm_location() == NULL)
		return 0;

	json_root = json_load_file(config_get_slurm_location(),
	    JSON_REJECT_DUPLICATES, &json_error);
	if (json_root == NULL) {
		warnx("SLURM JSON error on line %d, column %d: %s",
		    json_error.line, json_error.column, json_error.text);
		return -ENOENT;
	}

	error = handle_json(json_root);

	json_decref(json_root);
	return error;
}

void
slurm_cleanup(void)
{
	/* TODO Nothing for now */
}

/*
 * TODO Maybe some of the parsing functions can be on a common place, since
 * csv.c also does a similar parsing
 */

static int
parse_prefix4(char *text, struct ipv4_prefix *prefixv4)
{
	if (text == NULL)
		return -EINVAL;
	return prefix4_decode(text, prefixv4);
}

static int
parse_prefix6(char *text, struct ipv6_prefix *prefixv6)
{
	if (text == NULL)
		return -EINVAL;
	return prefix6_decode(text, prefixv6);
}

static int
parse_prefix_length(char *text, unsigned int *value, int max_value)
{
	if (text == NULL)
		return -EINVAL;
	return prefix_length_decode(text, value, max_value);
}

static int
set_asn(json_t *object, bool is_assertion, u_int32_t *result,
    u_int8_t *flag)
{
	json_int_t int_tmp;
	int error;

	error = json_get_int(object, ASN, &int_tmp);
	if (error)
		return error;

	if (int_tmp == 0) {
		/* Optional for filters */
		if(is_assertion) {
			warnx("ASN is required");
			return -EINVAL;
		} else
			return 0;
	}

	/* An underflow or overflow will be considered here */
	if (int_tmp <= 0 || UINT32_MAX < int_tmp) {
		warnx("ASN (%lld) is out of range [1 - %u].", int_tmp,
		    UINT32_MAX);
		return -EINVAL;
	}
	*flag = *flag | SLURM_COM_FLAG_ASN;
	*result = (u_int32_t) int_tmp;
	return 0;
}

static int
set_prefix(json_t *object, bool is_assertion, struct slurm_prefix *result)
{
	struct ipv4_prefix prefixv4;
	struct ipv6_prefix prefixv6;
	char const *str_prefix;
	char *clone, *token;
	bool isv4;
	int error;

	/* First part: Prefix in string format */
	error = json_get_string(object, PREFIX, &str_prefix);
	if (error)
		return error;

	if (str_prefix == NULL) {
		/* Optional for filters */
		if(is_assertion) {
			warnx("SLURM assertion prefix is required");
			return -EINVAL;
		} else
			return 0;
	}

	clone = strdup(str_prefix);
	if (clone == NULL) {
		warn("Couldn't allocate string to parse prefix");
		return -errno;
	}

	token = strtok(clone, "/");
	isv4 = strchr(token, ':') == NULL;
	if (isv4)
		error = parse_prefix4(token, &prefixv4);
	else
		error = parse_prefix6(token, &prefixv6);

	if (error) {
		free(clone);
		return error;
	}

	/* Second part: Prefix length in numeric format */
	token = strtok(NULL, "/");
	error = parse_prefix_length(token,
	    isv4 ? &prefixv4.len : &prefixv6.len,
	    isv4 ? 32 : 128);
	free(clone);
	if (error)
		return error;

	if (isv4) {
		error = prefix4_validate(&prefixv4);
		if (error)
			return error;
		result->addr_fam = AF_INET;
		result->ipv4_prefix = prefixv4.addr;
		result->prefix_length = prefixv4.len;
	} else {
		error = prefix6_validate(&prefixv6);
		if (error)
			return error;
		result->addr_fam = AF_INET6;
		result->ipv6_prefix = prefixv6.addr;
		result->prefix_length = prefixv6.len;
	}
	result->data_flag |= SLURM_PFX_FLAG_PREFIX;
	return 0;
}

static int
set_comment(json_t *object, char const **comment, u_int8_t *flag)
{
	int error;

	error = json_get_string(object, COMMENT, comment);
	if (error)
		return error;

	if (*comment != NULL)
		*flag = *flag | SLURM_COM_FLAG_COMMENT;

	return 0;
}

static int
set_max_prefix_length(json_t *object, bool is_assertion, u_int8_t addr_fam,
    u_int8_t *result, u_int8_t *flag)
{
	json_int_t int_tmp;
	int error;

	/* Ignore for filters */
	if (!is_assertion)
		return 0;

	error = json_get_int(object, MAX_PREFIX_LENGTH, &int_tmp);
	if (error)
		return error;

	/* Optional for assertions */
	if (int_tmp == 0)
		return 0;

	/* An underflow or overflow will be considered here */
	if (int_tmp <= 0 || (addr_fam == AF_INET ? 32 : 128) < int_tmp) {
		warnx("Max prefix length (%lld) is out of range [1 - %d].",
		    int_tmp, (addr_fam == AF_INET ? 32 : 128));
		return -EINVAL;
	}
	*flag = *flag | SLURM_PFX_FLAG_MAX_LENGTH;
	*result = (u_int8_t) int_tmp;
	return 0;

}

static int
load_single_prefix(json_t *object, bool is_assertion)
{
	struct slurm_prefix result;
	int error;

	if (!json_is_object(object)) {
		warnx("Not a valid JSON object");
		return -EINVAL;
	}

	result.data_flag = SLURM_COM_FLAG_NONE;

	error = set_asn(object, is_assertion, &result.asn, &result.data_flag);
	if (error)
		return error;

	error = set_prefix(object, is_assertion, &result);
	if (error)
		return error;

	error = set_comment(object, &result.comment, &result.data_flag);
	if (error)
		return error;

	error = set_max_prefix_length(object, is_assertion, result.addr_fam,
	    &result.max_prefix_length, &result.data_flag);
	if (error)
		return error;

	if (is_assertion && (result.data_flag & SLURM_PFX_FLAG_MAX_LENGTH))
		if (result.prefix_length > result.max_prefix_length) {
			warnx(
			    "Prefix length is greater than max prefix length");
			return -EINVAL;
		}

	/* TODO Loaded! Now persist it... */
	return 0;
}

static int
load_prefix_array(json_t *array, bool is_assertion)
{
	json_t *element;
	int index, error;

	json_array_foreach(array, index, element) {
		error = load_single_prefix(element, is_assertion);
		if (error) {
			warnx(
			    "Error at prefix %s, element %d, ignoring content",
			    (is_assertion ? "assertions" : "filters"),
			    index + 1);
		}
	}

	return 0;
}

static int
load_bgpsec_array(json_t *array, bool is_assertion)
{
	/* TODO Complete me */
	return 0;
}

static int
load_version(json_t *root)
{
	json_int_t version;
	int error;

	version = -1;
	error = json_get_int(root, SLURM_VERSION, &version);
	if (error)
		return error;

	/* Validate data */
	if (version != 1) {
		warnx("'%s' must be 1", SLURM_VERSION);
		return -EINVAL;
	}

	return 0;
}

static int
load_filters(json_t *root)
{
	json_t *filters, *prefix, *bgpsec;
	int error;

	filters = json_get_object(root, VALIDATION_OUTPUT_FILTERS);
	CHECK_REQUIRED(filters, VALIDATION_OUTPUT_FILTERS)

	prefix = json_get_array(filters, PREFIX_FILTERS);
	CHECK_REQUIRED(prefix, PREFIX_FILTERS)

	bgpsec = json_get_array(filters, BGPSEC_FILTERS);
	CHECK_REQUIRED(bgpsec, BGPSEC_FILTERS)

	/* Arrays loaded, now iterate */
	error = load_prefix_array(prefix, false);
	if (error)
		return error;

	error = load_bgpsec_array(bgpsec, false);
	if (error)
		return error;

	return 0;
}

static int
load_assertions(json_t *root)
{
	json_t *assertions, *prefix, *bgpsec;
	int error;

	assertions = json_get_object(root, LOCALLY_ADDED_ASSERTIONS);
	CHECK_REQUIRED(assertions, LOCALLY_ADDED_ASSERTIONS)

	prefix = json_get_array(assertions, PREFIX_ASSERTIONS);
	CHECK_REQUIRED(prefix, PREFIX_ASSERTIONS)

	bgpsec = json_get_array(assertions, BGPSEC_ASSERTIONS);
	CHECK_REQUIRED(bgpsec, BGPSEC_ASSERTIONS)

	error = load_prefix_array(prefix, true);
	if (error)
		return error;

	error = load_bgpsec_array(bgpsec, true);
	if (error)
		return error;

	return 0;
}

static int
handle_json(json_t *root)
{
	int error;

	if (!json_is_object(root)) {
		warnx("The root of the SLURM is not a JSON object.");
		return -EINVAL;
	}

	error = load_version(root);
	if (error)
		return error;

	error = load_filters(root);
	if (error)
		return error;

	error = load_assertions(root);
	if (error)
		return error;

	return 0;
}

static int
json_get_string(json_t *parent, char const *name, char const **result)
{
	json_t *child;

	child = json_object_get(parent, name);
	if (child == NULL) {
		*result = NULL;
		return 0;
	}

	if (!json_is_string(child)) {
		warnx("The '%s' element is not a JSON string.", name);
		return -EINVAL;
	}

	*result = json_string_value(child);
	return 0;
}

static int
json_get_int(json_t *parent, char const *name, json_int_t *result)
{
	json_t *child;

	child = json_object_get(parent, name);
	if (child == NULL) {
		*result = 0;
		return 0;
	}

	if (!json_is_integer(child)) {
		warnx("The '%s' element is not a JSON integer.", name);
		return -EINVAL;
	}

	*result = json_integer_value(child);
	return 0;
}

static json_t *
json_get_array(json_t *parent, char const *name)
{
	json_t *child;

	child = json_object_get(parent, name);
	if (child == NULL) {
		return NULL;
	}

	if (!json_is_array(child)) {
		warnx("The '%s' element is not a JSON array.", name);
		return NULL;
	}

	return child;
}

static json_t *
json_get_object(json_t *parent, char const *name)
{
	json_t *child;

	child = json_object_get(parent, name);
	if (child == NULL)
		return NULL;

	if (!json_is_object(child)) {
		warnx("The '%s' element is not a JSON object.", name);
		return NULL;
	}

	return child;
}
