#include "bgpsec.h"

#include "alloc.h"
#include "log.h"
#include "validation_handler.h"

struct resource_params {
	unsigned char const *ski;
	unsigned char const *spk;
	struct resources *parent_resources;
};

static int
asn_cb(struct asn_range const *range, void *arg)
{
	struct resource_params *params = arg;

	if (!resources_contains_asns(params->parent_resources, range))
		return pr_val_err("BGPsec certificate is not allowed to contain ASN range %u-%u.",
		    range->min, range->max);

	return vhandler_handle_router_key(params->ski, range, params->spk);
}

int
handle_bgpsec(X509 *cert, unsigned char const *ski, struct resources *resources)
{
	struct resource_params res_params;
	X509_PUBKEY *pub_key;
	unsigned char *cert_spk, *tmp;
	int cert_spk_len;
	int error;

	pub_key = X509_get_X509_PUBKEY(cert);
	if (pub_key == NULL)
		return val_crypto_err("X509_get_X509_PUBKEY() returned NULL at BGPsec");

	cert_spk = pmalloc(RK_SPKI_LEN);

	/* Use a temporal pointer, since i2d_X509_PUBKEY moves it */
	tmp = cert_spk;
	cert_spk_len = i2d_X509_PUBKEY(pub_key, &tmp);
	if(cert_spk_len < 0)
		return val_crypto_err("i2d_X509_PUBKEY() returned error");

	res_params.spk = cert_spk;
	res_params.ski = ski;
	res_params.parent_resources = resources;

	error = resources_foreach_asn(resources, asn_cb, &res_params);
	free(cert_spk);
	return error;
}
