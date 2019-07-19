#include "bgpsec.h"

#include "log.h"
#include "validation_handler.h"

struct resource_params {
	unsigned char const	*ski;
	unsigned char const	*spk;
	size_t			spk_len;
	struct resources	*resources;
};

static int
asn_cb(unsigned long asn, void *arg)
{
	struct resource_params *params = arg;

	if (!resources_contains_asn(params->resources, asn))
		return pr_err("BGPsec certificate is not allowed for ASN %lu.",
		    asn);

	return vhandler_handle_bgpsec(params->ski, asn, params->spk,
	    params->spk_len);
}

int
handle_bgpsec(X509 *cert, unsigned char const *ski, struct resources *resources)
{
	struct resource_params res_params;
	X509_PUBKEY *pub_key;
	unsigned char const *cert_spk;
	int cert_spk_len;
	int ok;

	pub_key = X509_get_X509_PUBKEY(cert);
	if (pub_key == NULL)
		return crypto_err("X509_get_X509_PUBKEY() returned NULL at BGPsec");

	ok = X509_PUBKEY_get0_param(NULL, &cert_spk, &cert_spk_len, NULL,
	    pub_key);
	if (!ok)
		return crypto_err("X509_PUBKEY_get0_param() returned %d at BGPsec",
		    ok);

	res_params.spk = cert_spk;
	res_params.spk_len = cert_spk_len;
	res_params.ski = ski;
	res_params.resources = resources;

	ok = resources_foreach_asn(resources, asn_cb, &res_params);
	return ok;
}
