#include "object/aspa.h"

#include "asn1/asn1c/ASProviderAttestation.h"
#include "asn1/decode.h"
#include "config.h"
#include "log.h"
#include "object/signed_object.h"
#include "thread_var.h"
#include "types/aspa.h"

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
		return pr_err("Version number is NULL.");
	if (asn_INTEGER2long(version, &primitive) < 0)
		return pr_err("Version number %s", strerror(errno));
	if (primitive != 1)
		return pr_err("Version number is not 1: %ld", primitive);

	return 0;
}

static int
parse_asid(char const *what, ASId_t *asid, uint32_t *result)
{
	unsigned long primitive;

	if (asid == NULL)
		return pr_err("%s is NULL.", what);
	if (asn_INTEGER2ulong(asid, &primitive) < 0)
		return pr_err("%s %s", what, strerror(errno));
	if (primitive > ASID_MAX)
		return pr_err("%s out of range. (0-%u)", what, ASID_MAX);

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

	if (*result == 0)
		return pr_err("Customer 0 is not allowed...");

	if (!resources_matches_asn(parent, *result))
		return pr_err(
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
		return pr_err("Providers set is NULL.");

	limit = config_get_max_aspa_providers();
	if (set->list.count > limit)
		return pr_err("customerASID %u has too many providers: %d > %u",
		    aspa->customer, set->list.count, limit);

	providers = pcalloc(set->list.count, sizeof(uint32_t));
	for (i = 0; i < set->list.count; i++) {
		error = parse_asid("Provider", set->list.array[i], &providers[i]);
		if (error)
			goto cancel;

		if (providers[i] == aspa->customer) {
			error = pr_err("The Providers list contains the customer's ASID (%u).",
			    aspa->customer);
			goto cancel;
		}
		if (providers[i] == 0 && set->list.count != 1) {
			error = pr_err("Provider ASID '0' is not in a single item list.");
			goto cancel;
		}
		if (i != 0) {
			if (providers[i - 1] == providers[i]) {
				error = pr_err("Provider ASID '%u' is listed more than once.", providers[i]);
				goto cancel;
			}
			if (providers[i - 1] > providers[i]) {
				error = pr_err("The Provider ASIDs are not listed in ascending order.");
				goto cancel;
			}
		}
	}

	aspa->providers.asids = providers;
	aspa->providers.count = set->list.count;
	return 0;

cancel:	free(providers);
	return error;
}

static int
__handle_aspa(struct validation_thread *vt, struct ASProviderAttestation *asn1,
    struct resources *parent)
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

	error = rtrhandler_handle_aspa(vt->tbl, aspa);

end:	aspa_refput(aspa);
	return error;
}

int
aspa_traverse(struct validation_thread *vt, struct cache_mapping const *map,
    struct rpki_certificate *parent /* struct uri *uri, struct rpp *pp */)
{
	static OID oid = OID_ASPA;
	struct oid_arcs arcs = OID2ARCS("aspa", oid);
	struct signed_object so;
	struct rpki_certificate ee;
	struct ASProviderAttestation *aspa;
	int error;

	/* Prepare */
	pr_trc("ASPA '%s' {", uri_str(&map->url));
	fnstack_push_map(map);

	/* Decode */
	so.type = SOT_ASPA;
	error = signed_object_decode(&so, map);
	if (error)
		goto end1;
	error = decode_aspa(&so, &aspa);
	if (error)
		goto end2;

	/* Prepare validation arguments */
	cer_init_ee(&ee, parent, false);

	/* Validate and handle everything */
	error = signed_object_validate(&so, &ee, &arcs);
	if (error)
		goto end4;
	error = __handle_aspa(vt, aspa, ee.resources);

end4:	cer_cleanup(&ee);
	ASN_STRUCT_FREE(asn_DEF_ASProviderAttestation, aspa);
end2:	signed_object_cleanup(&so);
end1:	fnstack_pop();
	pr_trc("ASPA done.");
	return error;
}
