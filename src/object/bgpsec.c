#include "object/bgpsec.h"

#include "alloc.h"
#include "log.h"
#include "object/certificate.h"
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
handle_bgpsec(X509 *cert, struct resources *parent_resources, struct rpp *pp)
{
	unsigned char *ski;
	enum rpki_policy policy;
	struct resources *resources;
	X509_PUBKEY *pub_key;
	unsigned char *cert_spk, *tmp;
	int cert_spk_len;
	struct resource_params res_params;
	int error;

	error = certificate_validate_rfc6487(cert, CERTYPE_BGPSEC);
	if (error)
		return error;
	error = certificate_validate_extensions_bgpsec(cert, &ski, &policy, pp);
	if (error)
		return error;

	resources = resources_create(policy, false);
	if (resources == NULL)
		goto revert_ski;
	error = certificate_get_resources(cert, resources, CERTYPE_BGPSEC);
	if (error)
		goto revert_resources;

	pub_key = X509_get_X509_PUBKEY(cert);
	if (pub_key == NULL) {
		error = val_crypto_err("X509_get_X509_PUBKEY() returned NULL at BGPsec");
		goto revert_resources;
	}

	cert_spk = pmalloc(RK_SPKI_LEN);

	/* Use a temporal pointer, since i2d_X509_PUBKEY moves it */
	tmp = cert_spk;
	cert_spk_len = i2d_X509_PUBKEY(pub_key, &tmp);
	if (cert_spk_len != RK_SPKI_LEN) {
		error = val_crypto_err("i2d_X509_PUBKEY() returned %d",
		    cert_spk_len);
		goto revert_spk;
	}

	res_params.spk = cert_spk;
	res_params.ski = ski;
	res_params.parent_resources = resources;

	error = resources_foreach_asn(resources, asn_cb, &res_params);
	/* Fall through */

revert_spk:
	free(cert_spk);
revert_resources:
	resources_destroy(resources);
revert_ski:
	free(ski);
	return error;
}
