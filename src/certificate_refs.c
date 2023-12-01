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
		uri_refput(refs->caIssuers);
	if (refs->signedObject != NULL)
		uri_refput(refs->signedObject);
}

static int
validate_cdp(struct certificate_refs *refs, struct rpp const *pp)
{
	struct rpki_uri *pp_crl;

	if (refs->crldp == NULL)
		pr_crit("Certificate's CRL Distribution Point was not recorded.");

	pp_crl = rpp_get_crl(pp);
	if (pp_crl == NULL)
		pr_crit("Manifest's CRL was not recorded.");

	if (strcmp(refs->crldp, uri_get_global(pp_crl)) != 0) {
		return pr_val_err("Certificate's CRL Distribution Point ('%s') does not match manifest's CRL ('%s').",
		    refs->crldp, uri_get_global(pp_crl));
	}

	return 0;
}

static int
validate_signedObject(struct certificate_refs *refs,
    struct rpki_uri *signedObject_uri)
{
	if (refs->signedObject == NULL)
		pr_crit("Certificate's signedObject was not recorded.");

	if (!uri_equals(refs->signedObject, signedObject_uri)) {
		return pr_val_err("Certificate's signedObject ('%s') does not match the URI of its own signed object (%s).",
		    uri_val_get_printable(refs->signedObject),
		    uri_val_get_printable(signedObject_uri));
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
		    uri_op_get_printable(refs->signedObject));

	return 0;
}

/**
 * Ensures the @refs URIs match the Manifest URIs. Assumes @refs came from an
 * EE certificate.
 *
 * @refs: References you want validated.
 * @pp: Repository Publication Point, as described by the Manifest.
 * @uri: URL of the signed object that contains the EE certificate.
 */
int
refs_validate_ee(struct certificate_refs *refs, struct rpp const *pp,
    struct rpki_uri *uri)
{
	int error;

	error = validate_cdp(refs, pp);
	if (error)
		return error;

	return validate_signedObject(refs, uri);
}
