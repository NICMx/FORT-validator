#include "rpp.h"

#include <stdlib.h>
#include "log.h"
#include "thread_var.h"
#include "uri.h"
#include "data_structure/array_list.h"
#include "object/certificate.h"
#include "object/crl.h"
#include "object/ghostbusters.h"
#include "object/roa.h"

ARRAY_LIST(uris, struct rpki_uri)

/** A Repository Publication Point (RFC 6481), as described by some manifest. */
struct rpp {
	struct uris certs; /* Certificates */

	struct rpki_uri crl; /* Certificate Revocation List */
	bool crl_set;

	/* The Manifest is not needed for now. */

	struct uris roas; /* Route Origin Attestations */

	struct uris ghostbusters;
};

struct rpp *
rpp_create(void)
{
	struct rpp *result;

	result = malloc(sizeof(struct rpp));
	if (result == NULL)
		return NULL;

	uris_init(&result->certs);
	result->crl_set = false;
	uris_init(&result->roas);
	uris_init(&result->ghostbusters);

	return result;
}

void
rpp_destroy(struct rpp *pp)
{
	uris_cleanup(&pp->certs, uri_cleanup);
	uri_cleanup(&pp->crl);
	uris_cleanup(&pp->roas, uri_cleanup);
	uris_cleanup(&pp->ghostbusters, uri_cleanup);
	free(pp);
}

int
rpp_add_cert(struct rpp *pp, struct rpki_uri *uri)
{
	return uris_add(&pp->certs, uri);
}

int
rpp_add_roa(struct rpp *pp, struct rpki_uri *uri)
{
	return uris_add(&pp->roas, uri);
}

int
rpp_add_ghostbusters(struct rpp *pp, struct rpki_uri *uri)
{
	return uris_add(&pp->ghostbusters, uri);
}

int
rpp_add_crl(struct rpp *pp, struct rpki_uri *uri)
{
	/* rfc6481#section-2.2 */
	if (pp->crl_set)
		return pr_err("Repository Publication Point has more than one CRL.");

	pp->crl = *uri;
	pp->crl_set = true;
	return 0;
}

static int
add_crl_to_stack(struct rpp *pp, STACK_OF(X509_CRL) *crls)
{
	X509_CRL *crl;
	int error;
	int idx;

	fnstack_push_uri(&pp->crl);

	error = crl_load(&pp->crl, &crl);
	if (error)
		goto end;

	idx = sk_X509_CRL_push(crls, crl);
	if (idx <= 0) {
		error = crypto_err("Could not add CRL to a CRL stack");
		X509_CRL_free(crl);
		goto end;
	}

end:
	fnstack_pop();
	return error;
}

struct rpki_uri const *
rpp_get_crl(struct rpp const *pp)
{
	return pp->crl_set ? &pp->crl : NULL;
}

int
rpp_traverse(struct rpp *pp)
{
	/*
	 * TODO is the stack supposed to have only the CRLs of this layer,
	 * or all of them?
	 */
	STACK_OF(X509_CRL) *crls;
	struct rpki_uri *uri;
	int error;

	crls = sk_X509_CRL_new_null();
	if (crls == NULL)
		return pr_enomem();
	error = add_crl_to_stack(pp, crls);
	if (error)
		goto end;

	/* Use CRL stack to validate certificates, and also traverse them. */
	ARRAYLIST_FOREACH(&pp->certs, uri)
		certificate_traverse(pp, uri, crls);

	/* Use valid address ranges to print ROAs that match them. */
	ARRAYLIST_FOREACH(&pp->roas, uri)
		roa_traverse(uri, pp, crls);

	ARRAYLIST_FOREACH(&pp->ghostbusters, uri)
		ghostbusters_traverse(uri, pp, crls);

end:
	sk_X509_CRL_pop_free(crls, X509_CRL_free);
	return error;
}
