#include "state.h"

#include <errno.h>
#include "log.h"
#include "thread_var.h"
#include "http/http.h"
#include "rpp/rpp_dl_status.h"

/**
 * The current state of the validation cycle.
 *
 * It is one of the core objects in this project. Every time a trust anchor
 * triggers a validation cycle, the validator creates one of these objects and
 * uses it to traverse the tree and keep track of validated data.
 */
struct validation {
	struct tal *tal;

	/* HTTP retriever. Reused because the documentation recommends it. */
	CURL *curl;

	struct x509_data {
		/** https://www.openssl.org/docs/man1.1.1/man3/X509_STORE_load_locations.html */
		X509_STORE *store;
		X509_VERIFY_PARAM *params;
	} x509_data;

	struct cert_stack *certstack;

	/* Download statuses. Prevents us from downloading something twice. */
	struct rpp_dl_status_db *downloads;

	/* Did the TAL's public key match the root certificate's public key? */
	enum pubkey_state pubkey_state;

	/**
	 * Two buffers calling code will store stringified IP addresses in,
	 * to prevent proliferation of similar buffers on the stack.
	 *
	 * They are meant to be large enough to contain both IPv4 and IPv6
	 * addresses.
	 */
	char addr_buffer1[INET6_ADDRSTRLEN];
	char addr_buffer2[INET6_ADDRSTRLEN];

	struct validation_handler validation_handler;
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

/**
 * Creates a struct validation and puts it in thread local.
 */
int
validation_prepare(struct tal *tal,
    struct validation_handler *validation_handler)
{
	struct validation *state;
	X509_VERIFY_PARAM *params;
	int error;

	state = malloc(sizeof(struct validation));
	if (!state)
		return pr_enomem();

	error = state_store(state);
	if (error)
		goto revert_state;

	state->tal = tal;

	state->curl = curl_create();
	if (state->curl == NULL) {
		error = pr_enomem();
		goto revert_state;
	}

	state->x509_data.store = X509_STORE_new();
	if (!state->x509_data.store) {
		error = val_crypto_err("X509_STORE_new() returned NULL");
		goto revert_curl;
	}

	params = X509_VERIFY_PARAM_new();
	if (params == NULL) {
		error = pr_enomem();
		goto revert_store;
	}

	X509_VERIFY_PARAM_set_flags(params, X509_V_FLAG_CRL_CHECK);
	X509_STORE_set1_param(state->x509_data.store, params);
	X509_STORE_set_verify_cb(state->x509_data.store, cb);

	error = certstack_create(&state->certstack);
	if (error)
		goto revert_params;

	state->downloads = rdsdb_create();
	if (state->downloads == NULL)
		goto revert_certstack;

	state->pubkey_state = PKS_UNTESTED;
	state->validation_handler = *validation_handler;
	state->x509_data.params = params; /* Ownership transfered */

	return 0;

revert_certstack:
	certstack_destroy(state->certstack);
revert_params:
	X509_VERIFY_PARAM_free(params);
revert_store:
	X509_STORE_free(state->x509_data.store);
revert_curl:
	curl_destroy(state->curl);
revert_state:
	free(state);
	return error;
}

void
validation_destroy(void)
{
	struct validation *state;

	state = state_retrieve();

	rdsdb_destroy(state->downloads);
	certstack_destroy(state->certstack);
	X509_VERIFY_PARAM_free(state->x509_data.params);
	X509_STORE_free(state->x509_data.store);
	curl_destroy(state->curl);
	free(state);
}

struct tal *
validation_tal(struct validation *state)
{
	return state->tal;
}

CURL *
validation_curl(struct validation *state)
{
	return state->curl;
}

X509_STORE *
validation_store(struct validation *state)
{
	return state->x509_data.store;
}

struct cert_stack *
validation_certstack(struct validation *state)
{
	return state->certstack;
}

void
validation_pubkey_valid(struct validation *state)
{
	state->pubkey_state = PKS_VALID;
}

void
validation_pubkey_invalid(struct validation *state)
{
	state->pubkey_state = PKS_INVALID;
}

enum pubkey_state
validation_pubkey_state(struct validation *state)
{
	return state->pubkey_state;
}

char *
validation_get_ip_buffer1(struct validation *state)
{
	return state->addr_buffer1;
}

char *
validation_get_ip_buffer2(struct validation *state)
{
	return state->addr_buffer2;
}

struct validation_handler const *
validation_get_validation_handler(struct validation *state)
{
	return &state->validation_handler;
}

struct rpp_dl_status_db *
validation_get_rppdb(struct validation *state)
{
	return state->downloads;
}
