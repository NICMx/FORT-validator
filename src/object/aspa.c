#include "object/aspa.h"

#include "asn1/asn1c/ASProviderAttestation.h"
#include "asn1/decode.h"
#include "asn1/oid.h"
#include "asn1/signed_data.h"
#include "config.h"
#include "log.h"
#include "object/signed_object.h"
#include "thread_var.h"

#define ASID_MAX UINT32_MAX

static int
decode_aspa(struct signed_object *sobj, struct ASProviderAttestation **result)
{
	return asn1_decode_octet_string(
		sobj->sdata->encapContentInfo.eContent,
		&asn_DEF_ASProviderAttestation,
		(void **) result,
		true
	);
}

static int
validate_version(INTEGER_t *version)
{
	long primitive;

	if (version == NULL)
		return pr_val_err("Version number is NULL.");
	if (asn_INTEGER2long(version, &primitive) < 0)
		return pr_val_err("Version number %s", strerror(errno));
	if (primitive != 1)
		return pr_val_err("Version number is not 1: %ld", primitive);

	return 0;
}

static int
parse_asid(char const *what, ASId_t *asid, uint32_t *result)
{
	unsigned long primitive;

	if (asid == NULL)
		return pr_val_err("%s is NULL.", what);
	if (asn_INTEGER2ulong(asid, &primitive) < 0)
		return pr_val_err("%s %s", what, strerror(errno));
	if (primitive > ASID_MAX)
		return pr_val_err("%s out of range. (0-%u)", what, ASID_MAX);

	*result = primitive;
	return 0;
}

static int
parse_customer(ASId_t *asid, struct resources *parent, uint32_t *result)
{
	int error;

	error = parse_asid("customerASID", asid, result);
	if (error)
		return error;

	if (!resources_matches_asn(parent, *result))
		return pr_val_err(
		    "EE certificate's ASN extension does not exactly match customerASID %u.",
		    *result);

	return 0;
}

static int
parse_providers(ProviderASSet_t *set, struct aspa *aspa)
{
	uint32_t *providers;
	unsigned int limit;
	int i;
	int error;

	aspa->providers.asids = NULL;
	aspa->providers.count = 0;

	if (set == NULL)
		return pr_val_err("Providers set is NULL.");

	limit = config_get_max_aspa_providers();
	if (set->list.count > limit)
		return pr_val_err("Too many providers: %d > %u",
		    set->list.count, limit);

	providers = pcalloc(set->list.count, sizeof(uint32_t));
	for (i = 0; i < set->list.count; i++) {
		error = parse_asid("Provider", set->list.array[i], &providers[i]);
		if (error)
			goto cancel;

		if (providers[i] == aspa->customer) {
			error = pr_val_err("The Providers list contains the customer's ASID (%u).",
			    aspa->customer);
			goto cancel;
		}
		if (i != 0 && providers[i - 1] >= providers[i]) {
			error = pr_val_err("The Provider ASIDs are not listed in ascending order.");
			goto cancel;
		}
	}

	aspa->providers.asids = providers;
	aspa->providers.count = set->list.count;
	return 0;

cancel:	free(providers);
	return error;
}

static int
__handle_aspa(struct ASProviderAttestation *asn1, struct resources *parent)
{
	struct aspa *aspa;
	int error;

	error = validate_version(asn1->version);
	if (error)
		return error;

	aspa = pzalloc(sizeof(struct aspa));
	aspa->refs = 1;

	error = parse_customer(&asn1->customerASID, parent, &aspa->customer);
	if (error)
		goto end;

	error = parse_providers(&asn1->providers, aspa);
	if (error)
		goto end;

	error = vhandler_handle_aspa(aspa);

end:	aspa_refput(aspa);
	return error;
}

int
aspa_traverse(struct rpki_uri *uri, struct rpp *pp)
{
	static OID oid = OID_ASPA;
	struct oid_arcs arcs = OID2ARCS("aspa", oid);
	struct signed_object sobj;
	struct ee_cert ee;
	struct ASProviderAttestation *aspa;
	STACK_OF(X509_CRL) *crl;
	int error;

	/* Prepare */
	pr_val_debug("ASPA '%s' {", uri_val_get_printable(uri));
	fnstack_push_uri(uri);

	/* Decode */
	error = signed_object_decode(&sobj, uri);
	if (error)
		goto revert_log;
	error = decode_aspa(&sobj, &aspa);
	if (error)
		goto revert_sobj;

	/* Prepare validation arguments */
	error = rpp_crl(pp, &crl);
	if (error)
		goto revert_roa;
	eecert_init(&ee, EET_ASPA, crl, false);

	/* Validate and handle everything */
	error = signed_object_validate(&sobj, &arcs, &ee);
	if (error)
		goto revert_args;
	error = __handle_aspa(aspa, ee.res);
	if (error)
		goto revert_args;
	error = refs_validate_ee(&ee.refs, pp, uri); // XXX why last?

revert_args:
	eecert_cleanup(&ee);
revert_roa:
	ASN_STRUCT_FREE(asn_DEF_ASProviderAttestation, aspa);
revert_sobj:
	signed_object_cleanup(&sobj);
revert_log:
	fnstack_pop();
	pr_val_debug("}");
	return error;
}
