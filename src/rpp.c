#include "rpp.h"

#include <stdlib.h>
#include "cert_stack.h"
#include "log.h"
#include "thread_var.h"
#include "uri.h"
#include "data_structure/array_list.h"
#include "object/certificate.h"
#include "object/crl.h"
#include "object/ghostbusters.h"
#include "object/roa.h"

ARRAY_LIST(uris, struct rpki_uri *)

/** A Repository Publication Point (RFC 6481), as described by some manifest. */
struct rpp {
	struct uris certs; /* Certificates */

	struct rpki_uri *crl; /* Certificate Revocation List */
	bool crl_set;
	/* Initialized lazily. Access via rpp_crl(). */
	STACK_OF(X509_CRL) *crl_stack;

	/* The Manifest is not needed for now. */

	struct uris roas; /* Route Origin Attestations */

	struct uris ghostbusters;

	/*
	 * Note that the reference counting functions are not prepared for
	 * multithreading, because this is not atomic.
	 */
	unsigned int references;
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
	result->crl_stack = NULL;
	uris_init(&result->roas);
	uris_init(&result->ghostbusters);
	result->references = 1;

	return result;
}

void
rpp_refget(struct rpp *pp)
{
	pp->references++;
}

void
__uri_refput(struct rpki_uri **uri)
{
	uri_refput(*uri);
}

void
rpp_refput(struct rpp *pp)
{
	pp->references--;
	if (pp->references == 0) {
		uris_cleanup(&pp->certs, __uri_refput);
		if (pp->crl_set)
			uri_refput(pp->crl);
		if (pp->crl_stack != NULL)
			sk_X509_CRL_pop_free(pp->crl_stack, X509_CRL_free);
		uris_cleanup(&pp->roas, __uri_refput);
		uris_cleanup(&pp->ghostbusters, __uri_refput);
		free(pp);
	}
}

/** Steals ownership of @uri. */
int
rpp_add_cert(struct rpp *pp, struct rpki_uri *uri)
{
	return uris_add(&pp->certs, &uri);
}

/** Steals ownership of @uri. */
int
rpp_add_roa(struct rpp *pp, struct rpki_uri *uri)
{
	return uris_add(&pp->roas, &uri);
}

/** Steals ownership of @uri. */
int
rpp_add_ghostbusters(struct rpp *pp, struct rpki_uri *uri)
{
	return uris_add(&pp->ghostbusters, &uri);
}

/** Steals ownership of @uri. */
int
rpp_add_crl(struct rpp *pp, struct rpki_uri *uri)
{
	/* rfc6481#section-2.2 */
	if (pp->crl_set)
		return pr_err("Repository Publication Point has more than one CRL.");

	pp->crl = uri;
	pp->crl_set = true;
	return 0;
}

struct rpki_uri *
rpp_get_crl(struct rpp const *pp)
{
	return pp->crl_set ? pp->crl : NULL;
}

static int
add_crl_to_stack(struct rpp *pp, STACK_OF(X509_CRL) *crls)
{
	X509_CRL *crl;
	int error;
	int idx;

	fnstack_push_uri(pp->crl);

	error = crl_load(pp->crl, &crl);
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

STACK_OF(X509_CRL) *
rpp_crl(struct rpp *pp)
{
	if (pp == NULL)
		return NULL;
	if (!pp->crl_set)
		return NULL;
	if (pp->crl_stack != NULL)
		return pp->crl_stack;

	pp->crl_stack = sk_X509_CRL_new_null();
	if (pp->crl_stack == NULL)
		return NULL;
	if (add_crl_to_stack(pp, pp->crl_stack) != 0) {
		sk_X509_CRL_pop_free(pp->crl_stack, X509_CRL_free);
		return NULL;
	}

	return pp->crl_stack;
}

static int
__cert_traverse(struct rpp *pp)
{
	struct validation *state;
	struct cert_stack *certstack;
	ssize_t i;
	struct deferred_cert deferred;
	int error;

	if (pp->certs.len == 0)
		return 0;

	state = state_retrieve();
	if (state == NULL)
		return -EINVAL;
	certstack = validation_certstack(state);

	deferred.pp = pp;
	/*
	 * The for is inverted, to achieve FIFO behavior since the separator.
	 * Not really important; it simply makes the traversal order more
	 * intuitive.
	 */
	for (i = pp->certs.len - 1; i >= 0; i--) {
		deferred.uri = pp->certs.array[i];
		error = deferstack_push(certstack, &deferred);
		if (error)
			return error;
	}

	return 0;
}

/**
 * Traverses through all of @pp's known files, validating them.
 */
void
rpp_traverse(struct rpp *pp)
{
	struct rpki_uri **uri;
	array_index i;

	/*
	 * A subtree should not invalidate the rest of the tree, so error codes
	 * are ignored.
	 * (Errors log messages anyway.)
	 */

	/*
	 * Certificates cannot be validated now, because then the algorithm
	 * would be recursive.
	 * Store them in the defer stack (see cert_stack.h), will get back to
	 * them later.
	 */
	__cert_traverse(pp);

	/* Validate ROAs, apply validation_handler on them. */
	ARRAYLIST_FOREACH(&pp->roas, uri, i)
		roa_traverse(*uri, pp);

	/*
	 * We don't do much with the ghostbusters right now.
	 * Just validate them.
	 */
	ARRAYLIST_FOREACH(&pp->ghostbusters, uri, i)
		ghostbusters_traverse(*uri, pp);
}
