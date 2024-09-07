#include "rpp.h"

#include "alloc.h"
#include "cert_stack.h"
#include "common.h"
#include "log.h"
#include "object/certificate.h"
#include "object/crl.h"
#include "object/ghostbusters.h"
#include "object/roa.h"
#include "thread_var.h"
#include "types/str.h"

STATIC_ARRAY_LIST(filelist, struct cache_mapping)

/* A Repository Publication Point (RFC 6481), as described by some manifest. */
struct rpp {
	struct filelist files;

	struct {
		struct cache_mapping map;
		STACK_OF(X509_CRL) *stack;
	} crl;

	/*
	 * Note that the reference counting functions are not prepared for
	 * multithreading, because this is not atomic.
	 */
	unsigned int references;
};

struct rpp *
rpp_create(void)
{
	struct rpp *result = pmalloc(sizeof(struct rpp));
	filelist_init(&result->files);
	memset(&result->crl, 0, sizeof(result->crl));
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
		filelist_cleanup(&pp->files, map_cleanup);
		free(pp->crl.map.url);
		free(pp->crl.map.path);
		sk_X509_CRL_pop_free(pp->crl.stack, X509_CRL_free);
		free(pp);
	}
}

static int
set_crl(struct rpp *pp, struct cache_mapping *map)
{
	X509_CRL *crl;
	int error;

	/* rfc6481#section-2.2 */
	if (pp->crl.stack != NULL)
		return pr_val_err("Repository Publication Point has more than one CRL.");

	error = crl_load(map->path, &crl);
	if (error)
		return error;

	pp->crl.stack = sk_X509_CRL_new_null();
	if (pp->crl.stack == NULL)
		enomem_panic();
	if (sk_X509_CRL_push(pp->crl.stack, crl) <= 0) {
		X509_CRL_free(crl);
		sk_X509_CRL_pop_free(pp->crl.stack, X509_CRL_free);
		pp->crl.stack = NULL;
		return val_crypto_err("Could not add CRL to a CRL stack");
	}

	pp->crl.map = *map;
	return 0;
}

/* Steals ownership of @map->* */
int
rpp_add_file(struct rpp *pp, struct cache_mapping *map)
{
	if (str_ends_with(map->url, ".crl") == 0)
		return set_crl(pp, map);

	filelist_add(&pp->files, map);
	return 0;
}

char const *
rpp_get_crl_url(struct rpp const *pp)
{
	return pp->crl.map.url;
}

/*
 * The stack belongs to @pp and should not be released. Can be NULL, in which
 * case you're currently validating the TA (since it lacks governing CRL).
 */
STACK_OF(X509_CRL) *
rpp_crl(struct rpp *pp)
{
	return pp->crl.stack;
}

/* Traverses through all of @pp's known files, validating them. */
void
rpp_traverse(struct rpp *pp)
{
	struct cert_stack *certstack;
	struct cache_mapping *map;

	/*
	 * A subtree should not invalidate the rest of the tree, so error codes
	 * are ignored.
	 * (Errors log messages anyway.)
	 */

	/*
	 * Certificates cannot be validated now, because then
	 * the algorithm would be recursive.
	 * Store them in the defer stack (see cert_stack.h),
	 * will get back to them later.
	 */

	certstack = validation_certstack(state_retrieve());

	ARRAYLIST_FOREACH(&pp->files, map) {
		char const *ext = map->url + strlen(map->url) - 4;
		if (strcmp(ext, ".cer") == 0)
			deferstack_push(certstack, map, pp);
		else if (strcmp(ext, ".roa") == 0)
			roa_traverse(map, pp);
		else if (strcmp(ext, ".gbr") == 0)
			ghostbusters_traverse(map, pp);
	}
}
