#include "state.h"

#include <errno.h>
#include "log.h"
#include "thread_var.h"
#include "object/certificate.h"

/**
 * The current state of the validation cycle.
 *
 * It is one of the core objects in this project. Every time a trust anchor
 * triggers a validation cycle, the validator creates one of these objects and
 * uses it to traverse the tree and keep track of validated data.
 */
struct validation {
	/**
	 * Encapsulated standard error.
	 * Needed because the crypto library won't write to stderr directly.
	 */
	BIO *err;

	/** https://www.openssl.org/docs/man1.1.1/man3/X509_STORE_load_locations.html */
	X509_STORE *store;

	/** Certificates we've already validated. */
	STACK_OF(X509) *trusted;
	/**
	 * The resources owned by the certificates from @trusted.
	 *
	 * (One for each certificate; these two stacks should practically always
	 * have the same size. The reason why I don't combine them is because
	 * libcrypto's validation function wants the stack of X509 and I'm not
	 * creating it over and over again.)
	 *
	 * (This is a SLIST and not a STACK_OF because the OpenSSL stack
	 * implementation is different than the LibreSSL one, and the latter is
	 * seemingly not intended to be used outside of its library.)
	 */
	struct restack *rsrcs;

	struct filename_stack *files;
};

/*
 * It appears that this function is called by LibreSSL whenever it finds an
 * error while validating.
 * It is expected to return "okay" status: Nonzero if the error should be
 * ignored, zero if the error is grounds to abort the validation.
 *
 * Note to myself: During my tests, this function was called in
 * X509_verify_cert(ctx) -> check_chain_extensions(0, ctx),
 * and then twice again in
 * X509_verify_cert(ctx) -> internal_verify(1, ctx).
 *
 * Regarding the ok argument: I'm not 100% sure that I get it; I don't
 * understand why this function would be called with ok = 1.
 * http://openssl.cs.utah.edu/docs/crypto/X509_STORE_CTX_set_verify_cb.html
 * The logic I implemented is the same as the second example: Always ignore the
 * error that's troubling the library, otherwise try to be as unintrusive as
 * possible.
 */
static int
cb(int ok, X509_STORE_CTX *ctx)
{
	int error;

	/*
	 * We need to handle two new critical extensions (IP Resources and ASN
	 * Resources), so unknown critical extensions are fine as far as
	 * LibreSSL is concerned.
	 * Unfortunately, LibreSSL has no way of telling us *which* is the
	 * unknown critical extension, but since RPKI defines its own set of
	 * valid extensions, we'll have to figure it out later anyway.
	 */
	error = X509_STORE_CTX_get_error(ctx);
	return (error == X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION) ? 1 : ok;
}

static int
init_trusted(struct validation *result, char *root)
{
	X509 *cert;
	int ok;
	int error;

	fnstack_push(root);

	error = certificate_load(root, &cert);
	if (error)
		goto abort1;

	result->trusted = sk_X509_new_null();
	if (result->trusted == NULL) {
		error = -EINVAL;
		goto abort2;
	}

	ok = sk_X509_push(result->trusted, cert);
	if (ok <= 0) {
		error = crypto_err(
		    "Could not add certificate to trusted stack: %d", ok);
		goto abort3;
	}

	fnstack_pop();
	return 0;

abort3:
	sk_X509_free(result->trusted);
abort2:
	X509_free(cert);
abort1:
	fnstack_pop();
	return error;
}

int
validation_create(struct validation **out, char *root)
{
	struct validation *result;
	struct resources *resources;
	int error;

	result = malloc(sizeof(struct validation));
	if (!result)
		return -ENOMEM;

	error = state_store(result);
	if (error)
		goto abort1;

	result->err = BIO_new_fp(stderr, BIO_NOCLOSE);
	if (result->err == NULL) {
		fprintf(stderr, "Failed to initialise standard error's BIO.\n");
		error = -ENOMEM;
		goto abort1;
	}

	result->store = X509_STORE_new();
	if (!result->store) {
		error = crypto_err("X509_STORE_new() returned NULL");
		goto abort2;
	}

	X509_STORE_set_verify_cb(result->store, cb);

	error = init_trusted(result, root);
	if (error)
		goto abort3;

	result->rsrcs = restack_create();
	if (!result->rsrcs)
		goto abort4;

	resources = resources_create();
	if (resources == NULL)
		goto abort5;

	fnstack_push(root);
	error = certificate_get_resources(validation_peek_cert(result),
	    resources);
	fnstack_pop();
	if (error)
		goto abort6;

	restack_push(result->rsrcs, resources);
	*out = result;
	return 0;

abort6:
	resources_destroy(resources);
abort5:
	restack_destroy(result->rsrcs);
abort4:
	sk_X509_pop_free(result->trusted, X509_free);
abort3:
	X509_STORE_free(result->store);
abort2:
	BIO_free_all(result->err);
abort1:
	free(result);
	return error;
}

void
validation_destroy(struct validation *state)
{
	int cert_num;

	/*
	 * Only the certificate created during validation_create() should
	 * remain.
	 */
	cert_num = sk_X509_num(state->trusted);
	if (cert_num != 1) {
		pr_err("Error: validation state has %d certificates. (1 expected)",
		    cert_num);
	}

	restack_destroy(state->rsrcs);
	sk_X509_pop_free(state->trusted, X509_free);
	X509_STORE_free(state->store);
	BIO_free_all(state->err);
	free(state);
}

BIO *
validation_stderr(struct validation *state)
{
	return state->err;
}

X509_STORE *
validation_store(struct validation *state)
{
	return state->store;
}

STACK_OF(X509) *
validation_certs(struct validation *state)
{
	return state->trusted;
}

struct restack *
validation_resources(struct validation *state)
{
	return state->rsrcs;
}

int
validation_push_cert(X509 *cert, struct resources *resources)
{
	struct validation *state;
	int ok;

	state = state_retrieve();
	if (state == NULL)
		return -EINVAL;

	ok = sk_X509_push(state->trusted, cert);
	if (ok <= 0) {
		crypto_err("Couldn't add certificate to trusted stack: %d", ok);
		return -ENOMEM; /* Presumably */
	}

	restack_push(state->rsrcs, resources);

	return 0;
}

int
validation_pop_cert(void)
{
	struct validation *state;

	state = state_retrieve();
	if (state == NULL)
		return -EINVAL;

	if (sk_X509_pop(state->trusted) == NULL) {
		return crypto_err(
		    "Programming error: Attempted to pop empty cert stack");
	}
	if (restack_pop(state->rsrcs) == NULL) {
		pr_err("Programming error: Attempted to pop empty resource stack");
		return -EINVAL;
	}

	return 0;
}

X509 *
validation_peek_cert(struct validation *state)
{
	return sk_X509_value(state->trusted, sk_X509_num(state->trusted) - 1);
}

struct resources *
validation_peek_resource(struct validation *state)
{
	return restack_peek(state->rsrcs);
}
