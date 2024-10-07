#include "certificate_refs.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"

int
validate_cdp(struct sia_uris *sias, char const *crl_url)
{
	if (sias->crldp == NULL)
		pr_crit("Certificate's CRL Distribution Point was not recorded.");

	if (crl_url == NULL)
		pr_crit("Manifest's CRL was not recorded.");

	if (strcmp(sias->crldp, crl_url) != 0) {
		return pr_val_err("Certificate's CRL Distribution Point ('%s') does not match manifest's CRL ('%s').",
		    sias->crldp, crl_url);
	}

	return 0;
}

static int
validate_signedObject(struct sia_uris *sias, char const *url)
{
	if (sias->signedObject == NULL)
		pr_crit("Certificate's signedObject was not recorded.");

	/* XXX the left one is no longer normalized */
	if (strcmp(sias->signedObject, url) != 0) {
		return pr_val_err("Certificate's signedObject ('%s') does not match the URI of its own signed object (%s).",
		    sias->signedObject, url);
	}

	return 0;
}

/**
 * Ensures the @refs URIs match the Manifest URIs. Assumes @refs came from an
 * EE certificate.
 *
 * @refs: References you want validated.
 * @url: URL of the signed object that contains the EE certificate.
 */
int
refs_validate_ee(struct sia_uris *sias, char const *crl_url, char const *url)
{
	int error;

	error = validate_cdp(sias, crl_url);
	if (error)
		return error;

	return validate_signedObject(sias, url);
}
