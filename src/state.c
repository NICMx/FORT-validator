#include "state.h"

#include <sys/queue.h>
#include <errno.h>
#include <string.h>
#include "array_list.h"
#include "log.h"
#include "thread_var.h"
#include "object/certificate.h"

ARRAY_LIST(serial_numbers, BIGNUM *)
ARRAY_LIST(subjects, char *)

/**
 * Cached certificate data.
 */
struct certificate {
	struct rpki_uri uri;
	struct resources *resources;
	/*
	 * Serial numbers of the children.
	 * This is an unsorted array list for two reasons: Certificates usually
	 * don't have many children, and I'm running out of time.
	 */
	struct serial_numbers serials;
	struct subjects subjects;

	/** Used by certstack. Points to the next stacked certificate. */
	SLIST_ENTRY(certificate) next;
};

SLIST_HEAD(certstack, certificate);

/**
 * The current state of the validation cycle.
 *
 * It is one of the core objects in this project. Every time a trust anchor
 * triggers a validation cycle, the validator creates one of these objects and
 * uses it to traverse the tree and keep track of validated data.
 */
struct validation {
	struct tal *tal;

	/** https://www.openssl.org/docs/man1.1.1/man3/X509_STORE_load_locations.html */
	X509_STORE *store;

	/** Certificates we've already validated. */
	STACK_OF(X509) *trusted;

	/**
	 * Stacked additional data to each @trusted certificate.
	 *
	 * (These two stacks should always have the same size. The reason why I
	 * don't combine them is because libcrypto's validation function needs
	 * the X509 stack, and I'm not creating it over and over again.)
	 *
	 * (This is a SLIST and not a STACK_OF because the OpenSSL stack
	 * implementation is different than the LibreSSL one, and the latter is
	 * seemingly not intended to be used outside of its library.)
	 */
	struct certstack certs;

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

/** Creates a struct validation, puts it in thread local, and returns it. */
int
validation_prepare(struct validation **out, struct tal *tal)
{
	struct validation *result;
	int error;

	result = malloc(sizeof(struct validation));
	if (!result)
		return -ENOMEM;

	error = state_store(result);
	if (error)
		goto abort1;

	result->tal = tal;

	result->store = X509_STORE_new();
	if (!result->store) {
		error = crypto_err("X509_STORE_new() returned NULL");
		goto abort1;
	}

	X509_STORE_set_verify_cb(result->store, cb);

	result->trusted = sk_X509_new_null();
	if (result->trusted == NULL) {
		error = crypto_err("sk_X509_new_null() returned NULL");
		goto abort2;
	}

	SLIST_INIT(&result->certs);
	result->pubkey_state = PKS_UNTESTED;

	*out = result;
	return 0;

abort2:
	X509_STORE_free(result->store);
abort1:
	free(result);
	return error;
}

static void
serial_cleanup(BIGNUM **serial)
{
	BN_free(*serial);
}

static void
subject_cleanup(char **subject)
{
	free(*subject);
}

void
validation_destroy(struct validation *state)
{
	int cert_num;
	struct certificate *cert;
	unsigned int c;

	cert_num = sk_X509_num(state->trusted);
	if (cert_num != 0) {
		pr_err("Error: validation state has %d certificates. (0 expected)",
		    cert_num);
	}

	c = 0;
	while (!SLIST_EMPTY(&state->certs)) {
		cert = SLIST_FIRST(&state->certs);
		SLIST_REMOVE_HEAD(&state->certs, next);
		resources_destroy(cert->resources);
		serial_numbers_cleanup(&cert->serials, serial_cleanup);
		subjects_cleanup(&cert->subjects, subject_cleanup);
		free(cert);
		c++;
	}
	pr_debug("Deleted %u certificates from the stack.", c);

	sk_X509_pop_free(state->trusted, X509_free);
	X509_STORE_free(state->store);
	free(state);
}

struct tal *
validation_tal(struct validation *state)
{
	return state->tal;
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

void validation_pubkey_valid(struct validation *state)
{
	state->pubkey_state = PKS_VALID;
}

void validation_pubkey_invalid(struct validation *state)
{
	state->pubkey_state = PKS_INVALID;
}

enum pubkey_state validation_pubkey_state(struct validation *state)
{
	return state->pubkey_state;
}

/**
 * Ownership of @cert_uri's members will NOT be transferred to @state on
 * success, and they will be expected to outlive @x509.
 */
int
validation_push_cert(struct validation *state, struct rpki_uri const *cert_uri,
    X509 *x509, enum rpki_policy policy, bool is_ta)
{
	struct certificate *cert;
	int ok;
	int error;

	cert = malloc(sizeof(struct certificate));
	if (cert == NULL) {
		error = pr_enomem();
		goto end1;
	}

	cert->uri = *cert_uri;
	error = serial_numbers_init(&cert->serials);
	if (error)
		goto end2;
	error = subjects_init(&cert->subjects);
	if (error)
		goto end3;
	cert->resources = resources_create();
	if (cert->resources == NULL) {
		error = pr_enomem();
		goto end4;
	}

	resources_set_policy(cert->resources, policy);
	error = certificate_get_resources(x509, cert->resources);
	if (error)
		goto end5;

	/*
	 * rfc7730#section-2.2
	 * "The INR extension(s) of this trust anchor MUST contain a non-empty
	 * set of number resources."
	 * The "It MUST NOT use the "inherit" form of the INR extension(s)"
	 * part is already handled in certificate_get_resources().
	 */
	if (is_ta && resources_empty(cert->resources)) {
		error = pr_err("Trust Anchor certificate does not define any number resources.");
		goto end5;
	}

	ok = sk_X509_push(state->trusted, x509);
	if (ok <= 0) {
		error = crypto_err(
		    "Couldn't add certificate to trusted stack: %d", ok);
		goto end5;
	}

	SLIST_INSERT_HEAD(&state->certs, cert, next);

	return 0;

end5:	resources_destroy(cert->resources);
end4:	subjects_cleanup(&cert->subjects, subject_cleanup);
end3:	serial_numbers_cleanup(&cert->serials, serial_cleanup);
end2:	free(cert);
end1:	return error;
}

int
validation_pop_cert(struct validation *state)
{
	struct certificate *cert;

	if (sk_X509_pop(state->trusted) == NULL)
		return pr_crit("Attempted to pop empty certificate stack (1)");

	cert = SLIST_FIRST(&state->certs);
	if (cert == NULL)
		return pr_crit("Attempted to pop empty certificate stack (2)");
	SLIST_REMOVE_HEAD(&state->certs, next);
	resources_destroy(cert->resources);
	serial_numbers_cleanup(&cert->serials, serial_cleanup);
	subjects_cleanup(&cert->subjects, subject_cleanup);
	free(cert);

	return 0;
}

X509 *
validation_peek_cert(struct validation *state)
{
	return sk_X509_value(state->trusted, sk_X509_num(state->trusted) - 1);
}

struct rpki_uri const *
validation_peek_cert_uri(struct validation *state)
{
	struct certificate *cert = SLIST_FIRST(&state->certs);
	return (cert != NULL) ? &cert->uri : NULL;
}

struct resources *
validation_peek_resource(struct validation *state)
{
	struct certificate *cert = SLIST_FIRST(&state->certs);
	return (cert != NULL) ? cert->resources : NULL;
}

int
validation_store_serial_number(struct validation *state, BIGNUM *number)
{
	struct certificate *cert;
	BIGNUM **cursor;
	BIGNUM *duplicate;
	int error;

	cert = SLIST_FIRST(&state->certs);
	if (cert == NULL)
		return 0; /* The TA lacks siblings, so serial is unique. */

	ARRAYLIST_FOREACH(&cert->serials, cursor)
		if (BN_cmp(*cursor, number) == 0)
			return pr_err("Serial number is not unique.");

	duplicate = BN_dup(number);
	if (duplicate == NULL)
		return crypto_err("Could not duplicate a BIGNUM");

	error = serial_numbers_add(&cert->serials, &duplicate);
	if (error)
		BN_free(duplicate);

	return error;
}

int
validation_store_subject(struct validation *state, char *subject)
{
	struct certificate *cert;
	char **cursor;
	char *duplicate;
	int error;

	cert = SLIST_FIRST(&state->certs);
	if (cert == NULL)
		return 0; /* The TA lacks siblings, so subject is unique. */

	ARRAYLIST_FOREACH(&cert->subjects, cursor)
		if (strcmp(*cursor, subject) == 0)
			return pr_err("Subject name is not unique.");

	duplicate = strdup(subject);
	if (duplicate == NULL)
		return pr_err("Could not duplicate a String");

	error = subjects_add(&cert->subjects, &duplicate);
	if (error)
		free(duplicate);

	return error;
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
