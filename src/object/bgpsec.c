#include "bgpsec.h"

#include "log.h"
#include "validation_handler.h"

struct resource_params {
	unsigned char const	*ski;
	unsigned char const	*spk;
	struct resources	*resources;
};

static int
asn_cb(unsigned long asn, void *arg)
{
	struct resource_params *params = arg;

	if (!resources_contains_asn(params->resources, asn))
		return pr_val_err("BGPsec certificate is not allowed for ASN %lu.",
		    asn);

	return vhandler_handle_router_key(params->ski, asn, params->spk);
}

int
handle_bgpsec(X509 *cert, unsigned char const *ski, struct resources *resources)
{
	struct resource_params res_params;
	X509_PUBKEY *pub_key;
	unsigned char *cert_spk, *tmp;
	int cert_spk_len;
	int ok;

	pub_key = X509_get_X509_PUBKEY(cert);
	if (pub_key == NULL)
		return val_crypto_err("X509_get_X509_PUBKEY() returned NULL at BGPsec");

	cert_spk = malloc(RK_SPKI_LEN);
	if (cert_spk == NULL)
		return pr_enomem();

	/* Use a temporal pointer, since i2d_X509_PUBKEY moves it */
	tmp = cert_spk;
	cert_spk_len = i2d_X509_PUBKEY(pub_key, &tmp);
	if(cert_spk_len < 0)
		return val_crypto_err("i2d_X509_PUBKEY() returned error");

	res_params.spk = cert_spk;
	res_params.ski = ski;
	res_params.resources = resources;

	ok = resources_foreach_asn(resources, asn_cb, &res_params);
	free(cert_spk);
	return ok;
}
