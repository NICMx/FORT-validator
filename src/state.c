#include "state.h"

#include <errno.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "common.h"
#include "log.h"
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
	 * Encapsulated standard output.
	 * Needed because the crypto library won't write to stdout directly.
	 */
	BIO *out;
	/**
	 * Encapsulated standard error.
	 * Needed because the crypto library won't write to stderr directly.
	 */
	BIO *err;

	/** https://www.openssl.org/docs/man1.1.1/man3/X509_STORE_load_locations.html */
	X509_STORE *store;

	/** Certificates we've already validated. */
	STACK_OF(X509) *trusted;
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

	cert = certificate_load(result, root);
	if (cert == NULL)
		return -EINVAL;

	result->trusted = sk_X509_new_null();
	if (result->trusted == NULL) {
		error = -EINVAL;
		goto abort1;
	}

	ok = sk_X509_push(result->trusted, cert);
	if (ok <= 0) {
		error = crypto_err(result,
		    "Could not add certificate to trusted stack: %d", ok);
		goto abort2;
	}

	return 0;

abort2:
	sk_X509_free(result->trusted);
abort1:
	X509_free(cert);
	return error;
}

int
validation_create(struct validation **out, char *root)
{
	struct validation *result;
	int error = -ENOMEM;

	result = malloc(sizeof(struct validation));
	if (!result)
		return -ENOMEM;

	result->out = BIO_new_fp(stdout, BIO_NOCLOSE);
	if (result->out == NULL) {
		fprintf(stderr, "Failed to initialise standard output's BIO.\n");
		goto abort1;
	}
	result->err = BIO_new_fp(stderr, BIO_NOCLOSE);
	if (result->out == NULL) {
		fprintf(stderr, "Failed to initialise standard error's BIO.\n");
		goto abort2;
	}

	result->store = X509_STORE_new();
	if (!result->store) {
		error = crypto_err(result, "X509_STORE_new() returned NULL");
		goto abort3;
	}

	X509_STORE_set_verify_cb(result->store, cb);

	error = init_trusted(result, root);
	if (error)
		goto abort4;

	*out = result;
	return 0;

abort4:
	X509_STORE_free(result->store);
abort3:
	BIO_free_all(result->err);
abort2:
	BIO_free_all(result->out);
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
		pr_err(state, "Error: validation state has %d certificates. (1 expected)",
		    cert_num);
	}

	sk_X509_pop_free(state->trusted, X509_free);
	X509_STORE_free(state->store);
	BIO_free_all(state->err);
	BIO_free_all(state->out);
	free(state);
}

/**
 * "Swallows" @cert; do not delete it.
 */
int
validation_push(struct validation *state, X509 *cert)
{
	/*
	 * TODO
	 * The only difference between -CAfile and -trusted, as it seems, is
	 * that -CAfile consults the default file location, while -trusted does
	 * not. As far as I can tell, this means that we absolutely need to use
	 * -trusted.
	 * So, just in case, enable -no-CAfile and -no-CApath.
	 */

	X509_STORE_CTX *ctx;
	int ok;

	ctx = X509_STORE_CTX_new();
	if (ctx == NULL) {
		crypto_err(state, "X509_STORE_CTX_new() returned NULL");
		goto end1;
	}

	/* Returns 0 or 1 , all callers test ! only. */
	ok = X509_STORE_CTX_init(ctx, state->store, cert, NULL);
	if (!ok) {
		crypto_err(state, "X509_STORE_CTX_init() returned %d", ok);
		goto end2;
	}

	X509_STORE_CTX_trusted_stack(ctx, state->trusted);

	/* Can return negative codes, all callers do <= 0. */
	ok = X509_verify_cert(ctx);
	if (ok <= 0) {
		crypto_err(state, "Certificate validation failed: %d", ok);
		goto end2;
	}

	/* Returns number of stack elements or 0 */
	ok = sk_X509_push(state->trusted, cert);
	if (ok <= 0) {
		crypto_err(state,
		    "Could not add certificate to trusted stack: %d", ok);
		goto end2;
	}

	X509_STORE_CTX_free(ctx);
	return 0;

end2:
	X509_STORE_CTX_free(ctx);
end1:
	X509_free(cert);
	return -EINVAL;
}

void
validation_pop(struct validation *state)
{
	X509 *cert = sk_X509_pop(state->trusted);
	X509_free(cert);
}

X509 *
validation_peek(struct validation *state)
{
	return sk_X509_value(state->trusted, sk_X509_num(state->trusted) - 1);
}

BIO *
validation_stdout(struct validation *state)
{
	return state->out;
}

BIO *
validation_stderr(struct validation *state)
{
	return state->err;
}
