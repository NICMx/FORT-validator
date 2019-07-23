#include "slurm_parser.h"

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <sys/types.h> /* AF_INET, AF_INET6 (needed in OpenBSD) */
#include <sys/socket.h> /* AF_INET, AF_INET6 (needed in OpenBSD) */

#include "crypto/base64.h"
#include "algorithm.h"
#include "log.h"
#include "address.h"
#include "json_parser.h"
#include "object/router_key.h"
#include "slurm/slurm_db.h"

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

#define CHECK_REQUIRED(element, name)					\
	if (element == NULL)						\
		return pr_err("SLURM member '%s' is required", name);

static int handle_json(json_t *);

int
slurm_parse(char const *location, void *arg)
{
	json_t *json_root;
	json_error_t json_error;
	int error;

	json_root = json_load_file(location, JSON_REJECT_DUPLICATES,
	    &json_error);
	if (json_root == NULL) {
		pr_err("SLURM JSON error on line %d, column %d: %s",
		    json_error.line, json_error.column, json_error.text);
		return -ENOENT;
	}

	error = handle_json(json_root);

	json_decref(json_root);
	return error;
}

static int
set_asn(json_t *object, bool is_assertion, uint32_t *result, uint8_t *flag,
    size_t *members_loaded)
{
	json_int_t int_tmp;
	int error;

	error = json_get_int(object, ASN, &int_tmp);
	if (error == -ENOENT) {
		if (is_assertion)
			return pr_err("ASN is required");
		else
			return 0; /* Optional for filters */
	} else if (error)
		return error;

	/* An underflow or overflow will be considered here */
	if (int_tmp < 0 || UINT32_MAX < int_tmp)
		return pr_err("ASN (%lld) is out of range [0 - %u].", int_tmp,
		    UINT32_MAX);
	*flag = *flag | SLURM_COM_FLAG_ASN;
	*result = (uint32_t) int_tmp;
	(*members_loaded)++;
	return 0;
}

static int
set_comment(json_t *object, char **comment, uint8_t *flag,
    size_t *members_loaded)
{
	char const *tmp;
	int error;

	error = json_get_string(object, COMMENT, &tmp);
	if (error && error == -ENOENT)
		return 0; /* Optional member */
	else if (error)
		return error;

	*comment = strdup(tmp);
	*flag = *flag | SLURM_COM_FLAG_COMMENT;
	(*members_loaded)++;

	return 0;
}

static int
set_prefix(json_t *object, bool is_assertion, struct slurm_prefix *result,
    size_t *members_loaded)
{
	struct ipv4_prefix prefixv4;
	struct ipv6_prefix prefixv6;
	char const *str_prefix;
	char *clone, *token;
	bool isv4;
	int error;

	/* First part: Prefix in string format */
	error = json_get_string(object, PREFIX, &str_prefix);
	if (error && error == -ENOENT) {
		if (is_assertion)
			return pr_err("SLURM assertion prefix is required");
		else
			return 0; /* Optional for filters */
	} else if (error)
		return error;

	clone = strdup(str_prefix);
	if (clone == NULL)
		return -pr_errno(errno, "Couldn't allocate string to parse prefix");

	token = strtok(clone, "/");
	isv4 = strchr(token, ':') == NULL;
	if (isv4)
		error = prefix4_parse(token, &prefixv4);
	else
		error = prefix6_parse(token, &prefixv6);

	if (error) {
		free(clone);
		return error;
	}

	/* Second part: Prefix length in numeric format */
	token = strtok(NULL, "/");
	error = prefix_length_parse(token,
	    (isv4 ? &prefixv4.len : &prefixv6.len),
	    (isv4 ? 32 : 128));
	free(clone);
	if (error)
		return error;

	if (isv4) {
		error = ipv4_prefix_validate(&prefixv4);
		if (error)
			return error;
		result->vrp.addr_fam = AF_INET;
		result->vrp.prefix.v4 = prefixv4.addr;
		result->vrp.prefix_length = prefixv4.len;
	} else {
		error = ipv6_prefix_validate(&prefixv6);
		if (error)
			return error;
		result->vrp.addr_fam = AF_INET6;
		result->vrp.prefix.v6 = prefixv6.addr;
		result->vrp.prefix_length = prefixv6.len;
	}
	result->data_flag |= SLURM_PFX_FLAG_PREFIX;
	(*members_loaded)++;
	return 0;
}

static int
set_max_prefix_length(json_t *object, bool is_assertion, uint8_t addr_fam,
    uint8_t *result, uint8_t *flag, size_t *members_loaded)
{
	json_int_t int_tmp;
	int error;

	error = json_get_int(object, MAX_PREFIX_LENGTH, &int_tmp);
	if (error == -ENOENT)
		return 0; /* Optional for assertions, unsupported by filters */

	if (error && is_assertion)
		return error;

	/* Unsupported by filters */
	if (!is_assertion)
		return pr_err("Prefix filter can't have a max prefix length");

	/* An underflow or overflow will be considered here */
	if (int_tmp <= 0 || (addr_fam == AF_INET ? 32 : 128) < int_tmp)
		return pr_err("Max prefix length (%lld) is out of range [1 - %d].",
		    int_tmp, (addr_fam == AF_INET ? 32 : 128));

	*flag = *flag | SLURM_PFX_FLAG_MAX_LENGTH;
	*result = (uint8_t) int_tmp;
	(*members_loaded)++;
	return 0;

}

int
validate_base64url_encoded(const char *encoded)
{
	/*
	 * RFC 8416, sections 3.3.2 (SKI member), and 3.4.2 (SKI and
	 * routerPublicKey members): "{..} whose value is the Base64 encoding
	 * without trailing '=' (Section 5 of [RFC4648])"
	 */
	if (strrchr(encoded, '=') != NULL)
		return pr_err("The base64 encoded value has trailing '='");

	/*
	 * IMHO there's an error at RFC 8416 regarding the use of base64
	 * encoding. The RFC cites "RFC 4648 section 5" to justify the
	 * removal of trailing pad char '=', a section that refers to base64url
	 * encoding. So, at the same RFC 4648 section, there's this paragraph:
	 * "This encoding may be referred to as "base64url".  This encoding
	 * should not be regarded as the same as the "base64" encoding and
	 * should not be referred to as only "base64".  Unless clarified
	 * otherwise, "base64" refers to the base 64 in the previous section."
	 *
	 * Well, I believe that the RFC 8416 must say something like:
	 * "{..} whose value is the Base64url encoding without trailing '='
	 * (Section 5 of [RFC4648])"
	 */
	return 0;
}

static int
set_ski(json_t *object, bool is_assertion, struct slurm_bgpsec *result,
    size_t *members_loaded)
{
	char const *str_encoded;
	size_t ski_len;
	int error;

	error = json_get_string(object, SKI, &str_encoded);
	if (error && error == -ENOENT) {
		if (is_assertion)
			return pr_err("SLURM assertion %s is required", SKI);
		else
			return 0; /* Optional for filters */
	} else if (error)
		return error;

	error = validate_base64url_encoded(str_encoded);
	if (error)
		return error;

	error = base64url_decode(str_encoded, &result->ski, &ski_len);
	if (error)
		return error;

	/* Validate that's at least 20 octects long */
	if (ski_len != RK_SKI_LEN) {
		free(result->ski);
		return pr_err("The decoded SKI must be 20 octets long");
	}

	result->data_flag = result->data_flag | SLURM_BGPS_FLAG_SKI;
	(*members_loaded)++;
	return 0;
}

/*
 * Use the provided X509_PUBKEY struct, and validate expected algorithms for a
 * BGPsec certificate.
 */
static int
validate_router_spki(unsigned char *data, size_t len)
{
	unsigned char const *tmp;
	X509_PUBKEY *spki;
	X509_ALGOR *pa;
	ASN1_OBJECT *alg;
	int ok;
	int error;

	tmp = data;
	spki = d2i_X509_PUBKEY(NULL, &tmp, len);
	if (spki == NULL)
		return crypto_err("Not a valid router public key");

	ok = X509_PUBKEY_get0_param(&alg, NULL, NULL, &pa, spki);
	if (!ok) {
		X509_PUBKEY_free(spki);
		return crypto_err("X509_PUBKEY_get0_param() returned %d", ok);
	}

	error = validate_certificate_public_key_algorithm(pa, true);
	X509_PUBKEY_free(spki);
	return error; /* Error 0 is ok */
}

static int
set_router_pub_key(json_t *object, bool is_assertion,
    struct slurm_bgpsec *result, size_t *members_loaded)
{
	char const *str_encoded;
	size_t spk_len;
	int error;

	error = json_get_string(object, ROUTER_PUBLIC_KEY, &str_encoded);
	if (error == -ENOENT && !is_assertion)
		return 0; /* OK for filters */

	/* Required by assertions */
	if (error && is_assertion) {
		if (error == -ENOENT)
			return pr_err("SLURM assertion %s is required", ROUTER_PUBLIC_KEY);
		return error;
	}

	/* Unsupported by filters */
	if (!is_assertion)
		return pr_err("BGPsec filter can't have a router public key");

	error = validate_base64url_encoded(str_encoded);
	if (error)
		return error;

	error = base64url_decode(str_encoded, &result->router_public_key,
	    &spk_len);
	if (error)
		return pr_err("'%s' couldn't be decoded", str_encoded);

	/*
	 * Validate that "is the full ASN.1 DER encoding of the
	 * subjectPublicKeyInfo, including the ASN.1 tag and length values
	 * of the subjectPublicKeyInfo SEQUENCE." (RFC 8416 section 3.4.2)
	 */
	error = validate_router_spki(result->router_public_key, spk_len);
	if (error) {
		free(result->router_public_key);
		return error;
	}

	result->data_flag = result->data_flag | SLURM_BGPS_FLAG_ROUTER_KEY;
	(*members_loaded)++;
	return 0;
}

static void
init_slurm_prefix(struct slurm_prefix *slurm_prefix)
{
	slurm_prefix->data_flag = SLURM_COM_FLAG_NONE;
	slurm_prefix->vrp.asn = 0;
	slurm_prefix->vrp.prefix.v6 = in6addr_any;
	slurm_prefix->vrp.prefix_length = 0;
	slurm_prefix->vrp.max_prefix_length = 0;
	slurm_prefix->vrp.addr_fam = 0;
	slurm_prefix->comment = NULL;
}

static int
load_single_prefix(json_t *object, bool is_assertion)
{
	struct slurm_prefix result;
	size_t member_count;
	int error;

	if (!json_is_object(object))
		return pr_err("Not a valid JSON object");

	init_slurm_prefix(&result);
	member_count = 0;

	error = set_asn(object, is_assertion, &result.vrp.asn,
	    &result.data_flag, &member_count);
	if (error)
		return error;

	error = set_prefix(object, is_assertion, &result, &member_count);
	if (error)
		return error;

	error = set_max_prefix_length(object, is_assertion,
	    result.vrp.addr_fam, &result.vrp.max_prefix_length,
	    &result.data_flag, &member_count);
	if (error)
		return error;

	error = set_comment(object, &result.comment, &result.data_flag,
	    &member_count);
	if (error)
		return error;

	/* A single comment isn't valid */
	if (result.data_flag == SLURM_COM_FLAG_COMMENT) {
		pr_err("Single comments aren't valid");
		error = -EINVAL;
		goto release_comment;
	}

	/* A filter must have ASN and/or prefix */
	if (!is_assertion) {
		if ((result.data_flag &
		    (SLURM_COM_FLAG_ASN | SLURM_PFX_FLAG_PREFIX)) == 0) {
			pr_err("Prefix filter must have an asn and/or prefix");
			error = -EINVAL;
			goto release_comment;
		}

		/* Validate expected members */
		if (!json_valid_members_count(object, member_count)) {
			pr_err("Prefix filter has unknown members (see RFC 8416 section 3.3.1)");
			error = -EINVAL;
			goto release_comment;
		}

		error = slurm_db_add_prefix_filter(&result);
		if (error)
			goto release_comment;

		return 0;
	}

	/*
	 * An assertion must have ASN and prefix, the validation is done at
	 * set_asn and set_prefix
	 */

	if ((result.data_flag & SLURM_PFX_FLAG_MAX_LENGTH) > 0)
		if (result.vrp.prefix_length > result.vrp.max_prefix_length) {
			pr_err(
			    "Prefix length is greater than max prefix length");
			error = -EINVAL;
			goto release_comment;
		}

	/* Validate expected members */
	if (!json_valid_members_count(object, member_count)) {
		pr_err("Prefix assertion has unknown members (see RFC 8416 section 3.4.1)");
		error = -EINVAL;
		goto release_comment;
	}

	error = slurm_db_add_prefix_assertion(&result);
	if (error)
		goto release_comment;

	return 0;

release_comment:
	free(result.comment);
	return error;
}

static int
load_prefix_array(json_t *array, bool is_assertion)
{
	json_t *element;
	int index, error;

	json_array_foreach(array, index, element) {
		error = load_single_prefix(element, is_assertion);
		if (error) {
			if (error == -EEXIST)
				pr_err(
				    "The prefix %s element #%d, is duplicated or covered by another %s; SLURM loading will be stopped",
				    (is_assertion ? "assertion" : "filter"),
				    index + 1,
				    (is_assertion ? "assertion" : "filter"));
			else
				pr_err(
				    "Error at prefix %s, element #%d, SLURM loading will be stopped",
				    (is_assertion ? "assertions" : "filters"),
				    index + 1);

			return error;
		}
	}

	return 0;
}

static void
init_slurm_bgpsec(struct slurm_bgpsec *slurm_bgpsec)
{
	slurm_bgpsec->data_flag = SLURM_COM_FLAG_NONE;
	slurm_bgpsec->asn = 0;
	slurm_bgpsec->ski = NULL;
	slurm_bgpsec->router_public_key = NULL;
	slurm_bgpsec->comment = NULL;
}

static int
load_single_bgpsec(json_t *object, bool is_assertion)
{
	struct slurm_bgpsec result;
	size_t member_count;
	int error;

	if (!json_is_object(object))
		return pr_err("Not a valid JSON object");

	init_slurm_bgpsec(&result);
	member_count = 0;

	error = set_asn(object, is_assertion, &result.asn, &result.data_flag,
	    &member_count);
	if (error)
		return error;

	error = set_ski(object, is_assertion, &result, &member_count);
	if (error)
		return error;

	error = set_router_pub_key(object, is_assertion, &result,
	    &member_count);
	if (error)
		goto release_ski;

	error = set_comment(object, &result.comment, &result.data_flag,
	    &member_count);
	if (error)
		goto release_router_key;

	/* A single comment isn't valid */
	if (result.data_flag == SLURM_COM_FLAG_COMMENT) {
		pr_err("Single comments aren't valid");
		error = -EINVAL;
		goto release_comment;
	}

	/* A filter must have ASN and/or SKI */
	if (!is_assertion) {
		if ((result.data_flag &
		    (SLURM_COM_FLAG_ASN | SLURM_BGPS_FLAG_SKI)) == 0) {
			pr_err("BGPsec filter must have an asn and/or SKI");
			error = -EINVAL;
			goto release_comment;
		}

		/* Validate expected members */
		if (!json_valid_members_count(object, member_count)) {
			pr_err("BGPsec filter has unknown members (see RFC 8416 section 3.3.2)");
			error = -EINVAL;
			goto release_comment;
		}

		error = slurm_db_add_bgpsec_filter(&result);
		if (error)
			goto release_comment;

		return 0;
	}

	/* Validate expected members */
	if (!json_valid_members_count(object, member_count)) {
		pr_err("BGPsec assertion has unknown members (see RFC 8416 section 3.4.2)");
		error = -EINVAL;
		goto release_comment;
	}

	error = slurm_db_add_bgpsec_assertion(&result);
	if (error)
		goto release_comment;

	return 0;

release_comment:
	free(result.comment);
release_router_key:
	free(result.router_public_key);
release_ski:
	free(result.ski);
	return error;
}

static int
load_bgpsec_array(json_t *array, bool is_assertion)
{
	json_t *element;
	int index, error;

	json_array_foreach(array, index, element) {
		error = load_single_bgpsec(element, is_assertion);
		if (!error)
			continue;
		if (error == -EEXIST)
			pr_err(
			    "The bgpsec %s element #%d, is duplicated or covered by another %s; SLURM loading will be stopped",
			    (is_assertion ? "assertion" : "filter"),
			    index + 1,
			    (is_assertion ? "assertion" : "filter"));
		else
			pr_err(
			    "Error at bgpsec %s, element #%d, SLURM loading will be stopped",
			    (is_assertion ? "assertions" : "filters"),
			    index + 1);

		return error;
	}

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
	if (version != 1)
		return pr_err("'%s' must be 1", SLURM_VERSION);

	return 0;
}

static int
load_filters(json_t *root)
{
	json_t *filters, *prefix, *bgpsec;
	size_t expected_members;
	int error;

	filters = json_get_object(root, VALIDATION_OUTPUT_FILTERS);
	CHECK_REQUIRED(filters, VALIDATION_OUTPUT_FILTERS)

	prefix = json_get_array(filters, PREFIX_FILTERS);
	CHECK_REQUIRED(prefix, PREFIX_FILTERS)

	bgpsec = json_get_array(filters, BGPSEC_FILTERS);
	CHECK_REQUIRED(bgpsec, BGPSEC_FILTERS)

	expected_members = 2;
	if (!json_valid_members_count(filters, expected_members))
		return pr_err(
		    "SLURM '%s' must contain only %lu members (RFC 8416 section 3.2)",
		    VALIDATION_OUTPUT_FILTERS,
		    expected_members);

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
	size_t expected_members;
	int error;

	assertions = json_get_object(root, LOCALLY_ADDED_ASSERTIONS);
	CHECK_REQUIRED(assertions, LOCALLY_ADDED_ASSERTIONS)

	prefix = json_get_array(assertions, PREFIX_ASSERTIONS);
	CHECK_REQUIRED(prefix, PREFIX_ASSERTIONS)

	bgpsec = json_get_array(assertions, BGPSEC_ASSERTIONS);
	CHECK_REQUIRED(bgpsec, BGPSEC_ASSERTIONS)

	expected_members = 2;
	if (!json_valid_members_count(assertions, expected_members))
		return pr_err(
		    "SLURM '%s' must contain only %lu members (RFC 8416 section 3.2)",
		    LOCALLY_ADDED_ASSERTIONS,
		    expected_members);

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
	size_t expected_members;
	int error;

	if (!json_is_object(root))
		return pr_err("The root of the SLURM is not a JSON object.");

	error = load_version(root);
	if (error)
		return error;

	error = load_filters(root);
	if (error)
		return error;

	error = load_assertions(root);
	if (error)
		return error;

	expected_members = 3;
	if (!json_valid_members_count(root, expected_members))
		return pr_err(
		    "SLURM root must have only %lu members (RFC 8416 section 3.2)",
		    expected_members);

	return 0;
}
