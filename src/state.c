#include "state.h"

#include <sys/queue.h>
#include <errno.h>
#include <string.h>
#include "log.h"
#include "str.h"
#include "thread_var.h"
#include "data_structure/array_list.h"
#include "object/certificate.h"

struct serial_number {
	BIGNUM *number;
	char *file; /* File where this serial number was found. */
};

struct subject_name {
	struct rfc5280_name *name;
	char *file; /* File where this subject name was found. */
};

ARRAY_LIST(serial_numbers, struct serial_number)
ARRAY_LIST(subjects, struct subject_name)

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

/** Creates a struct validation, puts it in thread local, and returns it. */
int
validation_prepare(struct validation **out, struct tal *tal,
    struct validation_handler *validation_handler)
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
	result->validation_handler = *validation_handler;

	*out = result;
	return 0;

abort2:
	X509_STORE_free(result->store);
abort1:
	free(result);
	return error;
}

static void
serial_cleanup(struct serial_number *serial)
{
	BN_free(serial->number);
	free(serial->file);
}

static void
subject_cleanup(struct subject_name *subject)
{
	x509_name_put(subject->name);
	free(subject->file);
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
	cert->resources = resources_create(false);
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

static int
get_current_file_name(char **_result)
{
	char const *tmp;
	char *result;

	tmp = fnstack_peek();
	if (tmp == NULL)
		return pr_crit("The file name stack is empty.");

	result = strdup(tmp);
	if (result == NULL)
		return pr_enomem();

	*_result = result;
	return 0;
}

/**
 * This function will steal ownership of @number on success.
 */
int
validation_store_serial_number(struct validation *state, BIGNUM *number)
{
	struct certificate *cert;
	struct serial_number *cursor;
	struct serial_number duplicate;
	char *string;
	int error;

	/* Remember to free @number if you return 0 but don't store it. */

	cert = SLIST_FIRST(&state->certs);
	if (cert == NULL) {
		BN_free(number);
		return 0; /* The TA lacks siblings, so serial is unique. */
	}

	/*
	 * Note: This is is reported as a warning, even though duplicate serial
	 * numbers are clearly a violation of the RFC and common sense.
	 *
	 * But it cannot be simply upgraded into an error because we are
	 * realizing the problem too late; our traversal is depth-first, so we
	 * already approved the other bogus certificate and its children.
	 * (I don't think changing to a breath-first traversal would be a good
	 * idea; the RAM usage would skyrocket because, since we need the entire
	 * certificate path to the root to validate any certificate, we would
	 * end up having the entire tree loaded in memory by the time we're done
	 * traversing.)
	 *
	 * So instead of arbitrarily approving one certificate but not the
	 * other, we will accept both but report a warning.
	 *
	 * Also: It's pretty odd; a significant amount of certificates seem to
	 * be breaking this rule. Maybe we're the only ones catching it?
	 */
	ARRAYLIST_FOREACH(&cert->serials, cursor) {
		if (BN_cmp(cursor->number, number) == 0) {
			BN2string(number, &string);
			pr_warn("Serial number '%s' is not unique. (Also found in '%s'.)",
			    string, cursor->file);
			BN_free(number);
			free(string);
			return 0;
		}
	}

	duplicate.number = number;
	error = get_current_file_name(&duplicate.file);
	if (error)
		return error;

	error = serial_numbers_add(&cert->serials, &duplicate);
	if (error)
		free(duplicate.file);

	return error;
}

int
validation_store_subject(struct validation *state, struct rfc5280_name *subject)
{
	struct certificate *cert;
	struct subject_name *cursor;
	struct subject_name duplicate;
	int error;

	/*
	 * There's something that's not clicking with me:
	 *
	 * "Each distinct subordinate CA and
	 * EE certified by the issuer MUST be identified using a subject name
	 * that is unique per issuer.  In this context, 'distinct' is defined as
	 * an entity and a given public key."
	 *
	 * Does the last sentence have any significance to us? I don't even
	 * understand why the requirement exists. 5280 and 6487 don't even
	 * define "entity." I guess it's the same meaning from "End-Entity",
	 * and in this case it's supposed to function as a synonym for "subject
	 * name."
	 *
	 * "An issuer SHOULD use a different
	 * subject name if the subject's key pair has changed (i.e., when the CA
	 * issues a certificate as part of re-keying the subject.)"
	 *
	 * It's really weird that it seems to be rewording the same requirement
	 * except the first version is defined as MUST and the second one is
	 * defined as SHOULD.
	 *
	 * Ugh. Okay. Let's use some common sense. There are four possible
	 * situations:
	 *
	 * - Certificates do not share name nor public key. We should accept
	 *   this.
	 * - Certificates share name, but not public key. We should reject this.
	 * - Certificates share public key, but not name. This is basically
	 *   impossible, but fine nonetheless. Accept.
	 *   (But maybe issue a warning. It sounds like the two children can
	 *   impersonate each other.)
	 * - Certificates share name and public key. This likely means that we
	 *   are looking at two different versions of the same certificate, but
	 *   we can't tell for sure right now, and so we should accept it.
	 *
	 * This is all conjecture. We should probably mail the IETF.
	 *
	 * TODO (next iteration) The code below complains when certificates
	 * share names, and ignores public keys. I've decided to defer the
	 * fixing.
	 */

	cert = SLIST_FIRST(&state->certs);
	if (cert == NULL)
		return 0; /* The TA lacks siblings, so subject is unique. */

	/* See the large comment in validation_store_serial_number(). */
	ARRAYLIST_FOREACH(&cert->subjects, cursor) {
		if (x509_name_equals(cursor->name, subject)) {
			char const *serial = x509_name_serialNumber(subject);
			pr_warn("Subject name '%s%s%s' is not unique. (Also found in '%s'.)",
			    x509_name_commonName(subject),
			    (serial != NULL) ? "/" : "",
			    (serial != NULL) ? serial : "",
			    cursor->file);
			return 0;
		}
	}

	duplicate.name = subject;
	x509_name_get(subject);

	error = get_current_file_name(&duplicate.file);
	if (error)
		goto revert_name;

	error = subjects_add(&cert->subjects, &duplicate);
	if (error)
		goto revert_file;

	return 0;

revert_file:
	free(duplicate.file);
revert_name:
	x509_name_put(subject);
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

struct validation_handler const *
validation_get_validation_handler(struct validation *state)
{
	return &state->validation_handler;
}
