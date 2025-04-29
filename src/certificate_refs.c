#include "certificate_refs.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"

int
validate_cdp(struct sia_uris const *sias, struct uri const *crl_url)
{
	if (uri_str(&sias->crldp) == NULL)
		pr_crit("Certificate's CRL Distribution Point was not recorded.");
	if (uri_str(crl_url) == NULL)
		pr_crit("Manifest's CRL was not recorded.");

	if (uri_equals(&sias->crldp, crl_url) != 0) {
		return pr_val_err("Certificate's CRL Distribution Point ('%s') does not match manifest's CRL ('%s').",
		    uri_str(&sias->crldp), uri_str(crl_url));
	}

	return 0;
}

static int
validate_signedObject(struct sia_uris const *sias, struct uri const *url)
{
	if (uri_str(&sias->signedObject) == NULL)
		pr_crit("Certificate's signedObject was not recorded.");

	if (!uri_equals(&sias->signedObject, url))
		return pr_val_err("Certificate's signedObject ('%s') does not match the URI of its own signed object (%s).",
		    uri_str(&sias->signedObject), uri_str(url));

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
refs_validate_ee(struct sia_uris const *sias, struct uri const *crl_url,
    struct uri const *url)
{
	int error;

	error = validate_cdp(sias, crl_url);
	if (error)
		return error;

	return validate_signedObject(sias, url);
}
