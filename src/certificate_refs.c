#include "certificate_refs.h"

#include <errno.h>
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
	free(refs->caIssuers);
	free(refs->signedObject);
}

static int
validate_cdp(struct certificate_refs *refs, struct rpp const *pp)
{
	struct rpki_uri const *pp_crl;

	if (refs->crldp == NULL)
		return pr_crit("Certificate's CRL Distribution Point was not recorded.");

	pp_crl = rpp_get_crl(pp);
	if (pp_crl == NULL)
		return pr_crit("Manifest's CRL was not recorded.");

	if (strcmp(refs->crldp, pp_crl->global) != 0) {
		return pr_err("Certificate's CRL Distribution Point ('%s') does not match manifest's CRL ('%s').",
		    refs->crldp, pp_crl->global);
	}

	return 0;
}

static int
validate_aia(struct certificate_refs *refs)
{
	struct validation *state;
	struct rpki_uri const *parent;

	if (refs->caIssuers == NULL)
		return pr_crit("Certificate's AIA was not recorded.");

	state = state_retrieve();
	if (state == NULL)
		return -EINVAL;
	parent = validation_peek_cert_uri(state);
	if (parent == NULL)
		return pr_crit("CA certificate has no parent.");

	if (strcmp(refs->caIssuers, parent->global) != 0) {
		return pr_err("Certificate's AIA ('%s') does not match parent's URI ('%s').",
		    refs->caIssuers, parent->global);
	}

	return 0;
}

static int
validate_signedObject(struct certificate_refs *refs,
    struct rpki_uri const *signedObject_uri)
{
	if (refs->signedObject == NULL)
		return pr_crit("Certificate's signedObject was not recorded.");

	if (strcmp(refs->signedObject, signedObject_uri->global) != 0) {
		return pr_err("Certificate's signedObject ('%s') does not match the URI of its own signed object (%s).",
		    refs->signedObject, signedObject_uri->global);
	}

	return 0;
}

/**
 * Ensures the @refs URIs match the parent Manifest's URIs. Assumes @refs came
 * from a CA certificate.
 *
 * @refs: References you want validated.
 * @pp: Repository Publication Point, as described by the parent Manifest.
 */
int
refs_validate_ca(struct certificate_refs *refs, struct rpp const *pp)
{
	int error;

	if (pp == NULL)
		return 0; /* This CA is the TA, and therefore lacks a parent. */

	error = validate_cdp(refs, pp);
	if (error)
		return error;

	error = validate_aia(refs);
	if (error)
		return error;

	if (refs->signedObject != NULL) {
		return pr_crit("CA summary has a signedObject ('%s').",
		    refs->signedObject);
	}

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
    struct rpki_uri const *uri)
{
	int error;

	error = validate_cdp(refs, pp);
	if (error)
		return error;

	error = validate_aia(refs);
	if (error)
		return error;

	return validate_signedObject(refs, uri);
}
