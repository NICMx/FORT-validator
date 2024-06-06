#include "certificate_refs.h"

#include "log.h"
#include "thread_var.h"

void
refs_init(struct certificate_refs *refs)
{
	memset(refs, 0, sizeof(struct certificate_refs));
}

void
refs_cleanup(struct certificate_refs *refs)
{
	free(refs->crldp);
	if (refs->caIssuers != NULL)
		map_refput(refs->caIssuers);
	if (refs->signedObject != NULL)
		map_refput(refs->signedObject);
}

static int
validate_cdp(struct certificate_refs *refs, struct rpp const *pp)
{
	struct cache_mapping *pp_crl;

	if (refs->crldp == NULL)
		pr_crit("Certificate's CRL Distribution Point was not recorded.");

	pp_crl = rpp_get_crl(pp);
	if (pp_crl == NULL)
		pr_crit("Manifest's CRL was not recorded.");

	if (strcmp(refs->crldp, map_get_url(pp_crl)) != 0) {
		return pr_val_err("Certificate's CRL Distribution Point ('%s') does not match manifest's CRL ('%s').",
		    refs->crldp, map_get_url(pp_crl));
	}

	return 0;
}

static int
validate_signedObject(struct certificate_refs *refs,
    struct cache_mapping *signedObject_map)
{
	if (refs->signedObject == NULL)
		pr_crit("Certificate's signedObject was not recorded.");

	if (!map_equals(refs->signedObject, signedObject_map)) {
		return pr_val_err("Certificate's signedObject ('%s') does not match the URI of its own signed object (%s).",
		    map_val_get_printable(refs->signedObject),
		    map_val_get_printable(signedObject_map));
	}

	return 0;
}

/**
 * Ensures the @refs URIs match the parent Manifest's URIs. Assumes @refs came
 * from a (non-TA) CA certificate.
 *
 * @refs: References you want validated.
 * @pp: Repository Publication Point, as described by the parent Manifest.
 */
int
refs_validate_ca(struct certificate_refs *refs, struct rpp const *pp)
{
	int error;

	error = validate_cdp(refs, pp);
	if (error)
		return error;

	if (refs->signedObject != NULL)
		pr_crit("CA summary has a signedObject ('%s').",
		    map_op_get_printable(refs->signedObject));

	return 0;
}

/**
 * Ensures the @refs URIs match the Manifest URIs. Assumes @refs came from an
 * EE certificate.
 *
 * @refs: References you want validated.
 * @pp: Repository Publication Point, as described by the Manifest.
 * @map: Mapping of the signed object that contains the EE certificate.
 */
int
refs_validate_ee(struct certificate_refs *refs, struct rpp const *pp,
    struct cache_mapping *map)
{
	int error;

	error = validate_cdp(refs, pp);
	if (error)
		return error;

	return validate_signedObject(refs, map);
}
