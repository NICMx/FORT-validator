#include "rpp.h"

#include "alloc.h"
#include "cert_stack.h"
#include "log.h"
#include "object/certificate.h"
#include "object/crl.h"
#include "object/ghostbusters.h"
#include "object/roa.h"
#include "thread_var.h"
#include "types/arraylist.h"
#include "types/map.h"

/** A Repository Publication Point (RFC 6481), as described by some manifest. */
struct rpp {
	struct map_list certs; /* Certificates */

	/*
	 * map NULL implies stack NULL and error 0.
	 * If map is set, stack might or might not be set.
	 * error is only relevant when map is set and stack is unset.
	 */
	struct { /* Certificate Revocation List */
		struct cache_mapping *map;
		/*
		 * CRL in libcrypto-friendly form.
		 * Initialized lazily; access via rpp_crl().
		 */
		STACK_OF(X509_CRL) *stack;
		/*
		 * Some error code if we already tried to initialize @stack but
		 * failed. Prevents us from wasting time doing it again, and
		 * flooding the log with identical error messages.
		 */
		int error;
	} crl;

	/* The Manifest is not needed for now. */

	struct map_list roas; /* Route Origin Attestations */

	struct map_list ghostbusters;

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

	result = pmalloc(sizeof(struct rpp));

	maps_init(&result->certs);
	result->crl.map = NULL;
	result->crl.stack = NULL;
	result->crl.error = 0;
	maps_init(&result->roas);
	maps_init(&result->ghostbusters);
	result->references = 1;

	return result;
}

void
rpp_refget(struct rpp *pp)
{
	pp->references++;
}

void
rpp_refput(struct rpp *pp)
{
	pp->references--;
	if (pp->references == 0) {
		maps_cleanup(&pp->certs);
		if (pp->crl.map != NULL)
			map_refput(pp->crl.map);
		if (pp->crl.stack != NULL)
			sk_X509_CRL_pop_free(pp->crl.stack, X509_CRL_free);
		maps_cleanup(&pp->roas);
		maps_cleanup(&pp->ghostbusters);
		free(pp);
	}
}

/** Steals ownership of @map. */
void
rpp_add_cert(struct rpp *pp, struct cache_mapping *map)
{
	maps_add(&pp->certs, map);
}

/** Steals ownership of @map. */
void
rpp_add_roa(struct rpp *pp, struct cache_mapping *map)
{
	maps_add(&pp->roas, map);
}

/** Steals ownership of @map. */
void
rpp_add_ghostbusters(struct rpp *pp, struct cache_mapping *map)
{
	maps_add(&pp->ghostbusters, map);
}

/** Steals ownership of @map. */
int
rpp_add_crl(struct rpp *pp, struct cache_mapping *map)
{
	/* rfc6481#section-2.2 */
	if (pp->crl.map)
		return pr_val_err("Repository Publication Point has more than one CRL.");

	pp->crl.map = map;
	return 0;
}

struct cache_mapping *
rpp_get_crl(struct rpp const *pp)
{
	return pp->crl.map;
}

static int
add_crl_to_stack(struct rpp *pp, STACK_OF(X509_CRL) *crls)
{
	X509_CRL *crl;
	int error;
	int idx;

	fnstack_push_map(pp->crl.map);

	error = crl_load(pp->crl.map, &crl);
	if (error)
		goto end;

	idx = sk_X509_CRL_push(crls, crl);
	if (idx <= 0) {
		error = val_crypto_err("Could not add CRL to a CRL stack");
		X509_CRL_free(crl);
		goto end;
	}

end:
	fnstack_pop();
	return error;
}

/**
 * Returns the pp's CRL in stack form (which is how libcrypto functions want
 * it).
 * The stack belongs to @pp and should not be released. Can be NULL, in which
 * case you're currently validating the TA (since it lacks governing CRL).
 */
int
rpp_crl(struct rpp *pp, STACK_OF(X509_CRL) **result)
{
	STACK_OF(X509_CRL) *stack;

	/* -- Short circuits -- */
	if (pp == NULL) {
		/* No pp = currently validating TA. There's no CRL. */
		*result = NULL;
		return 0;
	}
	if (pp->crl.map == NULL) {
		/* rpp_crl() assumes the rpp has been populated already. */
		pr_crit("RPP lacks a CRL.");
	}
	if (pp->crl.stack != NULL) {
		/* Result already cached. */
		*result = pp->crl.stack;
		return 0;
	}
	if (pp->crl.error) {
		/* Pretend that we did everything below. */
		return pp->crl.error;
	}

	/* -- Actually initialize pp->crl.stack. -- */
	stack = sk_X509_CRL_new_null();
	if (stack == NULL)
		enomem_panic();
	pp->crl.error = add_crl_to_stack(pp, stack);
	if (pp->crl.error) {
		sk_X509_CRL_pop_free(stack, X509_CRL_free);
		return pp->crl.error;
	}

	pp->crl.stack = stack;
	*result = stack;
	return 0;
}

static int
__cert_traverse(struct rpp *pp)
{
	struct validation *state;
	struct cert_stack *certstack;
	ssize_t i;
	struct deferred_cert deferred;

	if (pp->certs.len == 0)
		return 0;

	state = state_retrieve();
	certstack = validation_certstack(state);

	deferred.pp = pp;
	/*
	 * The for is inverted, to achieve FIFO behavior since the separator.
	 * Not really important; it simply makes the traversal order more
	 * intuitive.
	 */
	for (i = pp->certs.len - 1; i >= 0; i--) {
		deferred.map = pp->certs.array[i];
		deferstack_push(certstack, &deferred);
	}

	return 0;
}

/**
 * Traverses through all of @pp's known files, validating them.
 */
void
rpp_traverse(struct rpp *pp)
{
	struct cache_mapping **map;

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
	ARRAYLIST_FOREACH(&pp->roas, map)
		roa_traverse(*map, pp);

	/*
	 * We don't do much with the ghostbusters right now.
	 * Just validate them.
	 */
	ARRAYLIST_FOREACH(&pp->ghostbusters, map)
		ghostbusters_traverse(*map, pp);
}
