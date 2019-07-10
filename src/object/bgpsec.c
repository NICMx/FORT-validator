#include "bgpsec.h"

#include "log.h"
#include "validation_handler.h"

struct resource_params {
	struct router_key *router_key;
	struct resources *resources;
};

static int
asn_cb(unsigned long asn, void *arg)
{
	struct resource_params *params = arg;
	struct router_key router_key;

	if (!resources_contains_asn(params->resources, asn))
		return pr_err("BGPsec certificate is not allowed for ASN %lu.",
		    asn);

	memcpy(&router_key, params->router_key, sizeof(*params->router_key));
	router_key.asn = asn;

	return vhandler_handle_bgpsec(&router_key);
}

int
handle_bgpsec(X509 *cert, unsigned char *ski, int ski_len,
    struct resources *resources)
{
	/*
	 * FIXME: Store the public key, SKI, and the resources
	 */
	struct resource_params res_params;
	struct router_key router_key;
	ASN1_OBJECT *cert_alg;
	X509_PUBKEY *pub_key;
	unsigned char const *cert_spk;
	int cert_spk_len;
	int ok;

	pub_key = X509_get_X509_PUBKEY(cert);
	if (pub_key == NULL)
		return crypto_err("X509_get_X509_PUBKEY() returned NULL at BGPsec");

	ok = X509_PUBKEY_get0_param(&cert_alg, &cert_spk, &cert_spk_len, NULL,
	    pub_key);
	if (!ok)
		return crypto_err("X509_PUBKEY_get0_param() returned %d at BGPsec",
		    ok);

	router_key.spk = cert_spk;
	router_key.spk_len = cert_spk_len;
	router_key.ski = ski;
	router_key.ski_len = ski_len;

	res_params.router_key = &router_key;
	res_params.resources = resources;

	ok = resources_foreach_asn(resources, asn_cb, &res_params);
	/* FIXME Maybe this should be released elsewhere.. */
	free(ski);
	return ok;
}
