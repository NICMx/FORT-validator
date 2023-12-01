#include "slurm/slurm_parser.h"

#include <errno.h>
#include <openssl/asn1.h>

#include "crypto/base64.h"
#include "algorithm.h"
#include "alloc.h"
#include "json_util.h"
#include "log.h"
#include "types/address.h"
#include "types/router_key.h"
#include "slurm/db_slurm.h"

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

#define COMPLAIN_REQUIRED(name) pr_op_err("SLURM member '" name "' is required")

static int handle_json(json_t *, struct db_slurm *);

/*
 * Try to parse the SLURM file(s)
 */
int
slurm_parse(char const *location, void *arg)
{
	json_t *json_root;
	json_error_t json_error;
	int error;

	json_root = json_load_file(location, JSON_REJECT_DUPLICATES,
	    &json_error);
	if (json_root == NULL)
		/* File wasn't read or has a content error */
		return pr_op_err("SLURM JSON error on line %d, column %d: %s",
		    json_error.line, json_error.column, json_error.text);

	error = handle_json(json_root, arg);
	json_decref(json_root);
	if (error)
		return error; /* File exists, but has a syntax error */

	return 0;
}

static int
set_asn(json_t *object, bool is_assertion, uint32_t *result, uint8_t *flag,
    size_t *members_loaded)
{
	int error;

	error = json_get_u32(object, ASN, result);
	if (error < 0)
		return error;
	if (error > 0)
		/* Optional for filters */
		return is_assertion ? pr_op_err("ASN is required") : 0;

	*flag = *flag | SLURM_COM_FLAG_ASN;
	(*members_loaded)++;
	return 0;
}

/* There's no need to store the comment */
static int
set_comment(json_t *object, uint8_t *flag, size_t *members_loaded)
{
	char const *comment;
	int error;

	error = json_get_str(object, COMMENT, &comment);
	if (error < 0)
		return error;
	if (comment == NULL)
		return 0;

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
	error = json_get_str(object, PREFIX, &str_prefix);
	if (error < 0)
		return error;
	if (str_prefix == NULL) {
		return is_assertion
		    ? pr_op_err("SLURM assertion prefix is required")
		    : 0; /* Optional for filters */
	}

	clone = pstrdup(str_prefix);

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
	uint32_t u32;
	unsigned int max;
	int error;

	error = json_get_u32(object, MAX_PREFIX_LENGTH, &u32);
	if (error < 0)
		return error;

	/* Filters */
	if (!is_assertion)
		return (error == 0)
		    ? pr_op_err("Prefix filter can't have a max prefix length")
		    : 0;

	/* Assertions */
	if (error > 0)
		return 0;

	max = (addr_fam == AF_INET) ? 32 : 128;
	if (max < u32)
		return pr_op_err("Max prefix length (%u) is out of range [0, %u].",
		    u32, max);

	*flag = *flag | SLURM_PFX_FLAG_MAX_LENGTH;
	*result = (uint8_t) u32;
	(*members_loaded)++;
	return 0;

}

static int
validate_base64url_encoded(const char *encoded)
{
	/*
	 * RFC 8416, sections 3.3.2 (SKI member), and 3.4.2 (SKI and
	 * routerPublicKey members): "{..} whose value is the Base64 encoding
	 * without trailing '=' (Section 5 of [RFC4648])"
	 */
	if (strrchr(encoded, '=') != NULL)
		return pr_op_err_st("The base64 encoded value has trailing '='");

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

	error = json_get_str(object, SKI, &str_encoded);
	if (error < 0)
		return error;
	if (str_encoded == NULL)
		return is_assertion
		    ? pr_op_err("SLURM assertion " SKI " is required")
		    : 0; /* Optional for filters */

	error = validate_base64url_encoded(str_encoded);
	if (error)
		return error;

	if (!base64url_decode(str_encoded, &result->ski, &ski_len))
		return op_crypto_err("The " SKI " could not be decoded.");

	/* Validate that's at least 20 octects long */
	if (ski_len != RK_SKI_LEN) {
		free(result->ski);
		return pr_op_err("The decoded SKI must be 20 octets long");
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
		return op_crypto_err("Not a valid router public key");

	ok = X509_PUBKEY_get0_param(&alg, NULL, NULL, &pa, spki);
	if (!ok) {
		X509_PUBKEY_free(spki);
		return op_crypto_err("X509_PUBKEY_get0_param() returned %d", ok);
	}

	error = validate_certificate_public_key_algorithm_bgpsec(pa);
	X509_PUBKEY_free(spki);
	return error; /* Error 0 is ok */
}

static int
set_router_pub_key(json_t *object, bool is_assertion,
    struct slurm_bgpsec *result, size_t *members_loaded)
{
	char const *encoded;
	size_t spk_len;
	int error;

	error = json_get_str(object, ROUTER_PUBLIC_KEY, &encoded);
	if (error < 0)
		return error;

	/* Filters */
	if (!is_assertion)
		return (error == 0)
		    ? pr_op_err("BGPsec filter can't have a router public key")
		    : 0;

	/* Assertions */
	if (encoded == NULL)
		return pr_op_err("SLURM assertion " ROUTER_PUBLIC_KEY " is required.");

	error = validate_base64url_encoded(encoded);
	if (error)
		return error;

	if (!base64url_decode(encoded, &result->router_public_key, &spk_len))
		return op_crypto_err("The " ROUTER_PUBLIC_KEY " could not be decoded.");

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
}

static int
load_single_prefix(json_t *object, struct db_slurm *db, bool is_assertion)
{
	struct slurm_prefix result;
	size_t member_count;
	int error;

	if (!json_is_object(object))
		return pr_op_err("Not a valid JSON object");

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

	error = set_comment(object, &result.data_flag, &member_count);
	if (error)
		return error;

	/* A single comment isn't valid */
	if (result.data_flag == SLURM_COM_FLAG_COMMENT)
		return pr_op_err("Single comments aren't valid");

	/* A filter must have ASN and/or prefix */
	if (!is_assertion) {
		if ((result.data_flag &
		    (SLURM_COM_FLAG_ASN | SLURM_PFX_FLAG_PREFIX)) == 0)
			return pr_op_err("Prefix filter must have an asn and/or prefix");

		/* Validate expected members */
		if (!json_valid_members_count(object, member_count))
			return pr_op_err("Prefix filter has unknown members (see RFC 8416 section 3.3.1)");

		error = db_slurm_add_prefix_filter(db, &result);
		if (error)
			return error;

		return 0;
	}

	/*
	 * An assertion must have ASN and prefix, the validation is done at
	 * set_asn and set_prefix
	 */

	if ((result.data_flag & SLURM_PFX_FLAG_MAX_LENGTH) > 0 &&
	    result.vrp.prefix_length > result.vrp.max_prefix_length)
		return pr_op_err("Prefix length is greater than max prefix length");

	/* Validate expected members */
	if (!json_valid_members_count(object, member_count))
		return pr_op_err("Prefix assertion has unknown members (see RFC 8416 section 3.4.1)");

	error = db_slurm_add_prefix_assertion(db, &result);
	if (error)
		return error;

	return 0;
}

static int
load_prefix_array(json_t *array, struct db_slurm *db, bool is_assertion)
{
	json_t *element;
	int index, error;

	json_array_foreach(array, index, element) {
		error = load_single_prefix(element, db, is_assertion);
		if (!error)
			continue;
		if (error == -EEXIST)
			pr_op_err(
			    "The prefix %s element \"%s\", covers or is covered by another assertion/filter; SLURM loading will be stopped. %s",
			    (is_assertion ? "assertion" : "filter"),
			    json_dumps(element, 0),
			    "TIP: More than 1 SLURM files were found, check if the prefix is contained in multiple files (see RFC 8416 section 4.2).");
		else
			pr_op_err(
			    "Error at prefix %s, element \"%s\", SLURM loading will be stopped",
			    (is_assertion ? "assertions" : "filters"),
			    json_dumps(element, 0));

		return error;
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
}

static int
load_single_bgpsec(json_t *object, struct db_slurm *db, bool is_assertion)
{
	struct slurm_bgpsec result;
	size_t member_count;
	int error;

	if (!json_is_object(object))
		return pr_op_err("Not a valid JSON object");

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

	error = set_comment(object, &result.data_flag, &member_count);
	if (error)
		goto release_router_key;

	/* A single comment isn't valid */
	if (result.data_flag == SLURM_COM_FLAG_COMMENT) {
		pr_op_err("Single comments aren't valid");
		error = -EINVAL;
		goto release_router_key;
	}

	/* A filter must have ASN and/or SKI */
	if (!is_assertion) {
		if ((result.data_flag &
		    (SLURM_COM_FLAG_ASN | SLURM_BGPS_FLAG_SKI)) == 0) {
			pr_op_err("BGPsec filter must have an asn and/or SKI");
			error = -EINVAL;
			goto release_router_key;
		}

		/* Validate expected members */
		if (!json_valid_members_count(object, member_count)) {
			pr_op_err("BGPsec filter has unknown members (see RFC 8416 section 3.3.2)");
			error = -EINVAL;
			goto release_router_key;
		}

		error = db_slurm_add_bgpsec_filter(db, &result);
		if (error)
			goto release_router_key;

		return 0;
	}

	/* Validate expected members */
	if (!json_valid_members_count(object, member_count)) {
		pr_op_err("BGPsec assertion has unknown members (see RFC 8416 section 3.4.2)");
		error = -EINVAL;
		goto release_router_key;
	}

	error = db_slurm_add_bgpsec_assertion(db, &result);
	if (error)
		goto release_router_key;

	return 0;

release_router_key:
	free(result.router_public_key);
release_ski:
	free(result.ski);
	return error;
}

static int
load_bgpsec_array(json_t *array, struct db_slurm *db, bool is_assertion)
{
	json_t *element;
	int index, error;

	json_array_foreach(array, index, element) {
		error = load_single_bgpsec(element, db, is_assertion);
		if (!error)
			continue;
		if (error == -EEXIST)
			pr_op_err(
			    "The ASN at bgpsec %s element \"%s\", is duplicated in another assertion/filter; SLURM loading will be stopped. %s",
			    (is_assertion ? "assertion" : "filter"),
			    json_dumps(element, 0),
			    "TIP: More than 1 SLURM files were found, check if the ASN is contained in multiple files (see RFC 8416 section 4.2).");
		else
			pr_op_err(
			    "Error at bgpsec %s, element \"%s\", SLURM loading will be stopped",
			    (is_assertion ? "assertions" : "filters"),
			    json_dumps(element, 0));

		return error;
	}

	return 0;
}

static int
load_version(json_t *root)
{
	uint32_t version;
	int error;

	error = json_get_u32(root, SLURM_VERSION, &version);
	if (error < 0)
		return error;
	if (error > 0)
		return COMPLAIN_REQUIRED(SLURM_VERSION);

	/* Validate data */
	if (version != 1)
		return pr_op_err("'" SLURM_VERSION "' must be 1");

	return 0;
}

static int
load_filters(json_t *root, struct db_slurm *db)
{
	json_t *filters, *prefix, *bgpsec;
	size_t expected_members;
	int error;

	error = json_get_object(root, VALIDATION_OUTPUT_FILTERS, &filters);
	if (error < 0)
		return error;
	if (error > 0)
		return COMPLAIN_REQUIRED(VALIDATION_OUTPUT_FILTERS);

	error = json_get_array(filters, PREFIX_FILTERS, &prefix);
	if (error < 0)
		return error;
	if (error > 0)
		return COMPLAIN_REQUIRED(PREFIX_FILTERS);

	error = json_get_array(filters, BGPSEC_FILTERS, &bgpsec);
	if (error < 0)
		return error;
	if (error > 0)
		return COMPLAIN_REQUIRED(BGPSEC_FILTERS);

	expected_members = 2;
	if (!json_valid_members_count(filters, expected_members))
		return pr_op_err(
		    "SLURM '%s' must contain only %lu members (RFC 8416 section 3.2)",
		    VALIDATION_OUTPUT_FILTERS,
		    expected_members);

	/* Arrays loaded, now iterate */
	error = load_prefix_array(prefix, db, false);
	if (error)
		return error;

	error = load_bgpsec_array(bgpsec, db, false);
	if (error)
		return error;

	return 0;
}

static int
load_assertions(json_t *root, struct db_slurm *db)
{
	json_t *assertions, *prefix, *bgpsec;
	size_t expected_members;
	int error;

	error = json_get_object(root, LOCALLY_ADDED_ASSERTIONS, &assertions);
	if (error < 0)
		return error;
	if (error > 0)
		return COMPLAIN_REQUIRED(LOCALLY_ADDED_ASSERTIONS);

	error = json_get_array(assertions, PREFIX_ASSERTIONS, &prefix);
	if (error < 0)
		return error;
	if (error > 0)
		return COMPLAIN_REQUIRED(PREFIX_ASSERTIONS);

	error = json_get_array(assertions, BGPSEC_ASSERTIONS, &bgpsec);
	if (error < 0)
		return error;
	if (error > 0)
		return COMPLAIN_REQUIRED(BGPSEC_ASSERTIONS);

	expected_members = 2;
	if (!json_valid_members_count(assertions, expected_members))
		return pr_op_err(
		    "SLURM '%s' must contain only %lu members (RFC 8416 section 3.2)",
		    LOCALLY_ADDED_ASSERTIONS,
		    expected_members);

	error = load_prefix_array(prefix, db, true);
	if (error)
		return error;

	error = load_bgpsec_array(bgpsec, db, true);
	if (error)
		return error;

	return 0;
}

static int
handle_json(json_t *root, struct db_slurm *db)
{
	size_t expected_members;
	int error;

	if (!json_is_object(root))
		return pr_op_err("The root of the SLURM is not a JSON object.");

	error = load_version(root);
	if (error)
		return error;

	/* Start working on the cache */
	db_slurm_start_cache(db);

	error = load_filters(root, db);
	if (error)
		return error;

	error = load_assertions(root, db);
	if (error)
		return error;

	expected_members = 3;
	if (!json_valid_members_count(root, expected_members))
		return pr_op_err(
		    "SLURM root must have only %lu members (RFC 8416 section 3.2)",
		    expected_members);

	/* Persist cached data */
	db_slurm_flush_cache(db);

	return 0;
}
