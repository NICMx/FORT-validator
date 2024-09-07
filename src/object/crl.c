#include "object/crl.h"

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <syslog.h>

#include "algorithm.h"
#include "extension.h"
#include "log.h"
#include "thread_var.h"
#include "types/name.h"

static int
__crl_load(char const *path, X509_CRL **result)
{
	X509_CRL *crl;
	BIO *bio;
	int error;

	bio = BIO_new(BIO_s_file());
	if (bio == NULL)
		return val_crypto_err("BIO_new(BIO_s_file()) returned NULL");
	if (BIO_read_filename(bio, path) <= 0) {
		error = val_crypto_err("Error reading CRL '%s'", path);
		goto end;
	}

	crl = d2i_X509_CRL_bio(bio, NULL);
	if (crl == NULL) {
		error = val_crypto_err("Error parsing CRL '%s'", path);
		goto end;
	}

	*result = crl;
	error = 0;

end:
	BIO_free(bio);
	return error;
}

static void
debug_revoked(ASN1_INTEGER const *serial_int)
{
	BIGNUM *serial_bn;
	char *serial_str;

	serial_bn = ASN1_INTEGER_to_BN(serial_int, NULL);
	if (serial_bn == NULL) {
		val_crypto_err("Could not parse revoked serial number");
		return;
	}

	serial_str = BN_bn2dec(serial_bn);
	if (serial_str == NULL) {
		val_crypto_err("Could not convert BN to string");
		goto end;
	}

	pr_val_debug("Revoked: %s", serial_str);

	free(serial_str);
end:	BN_free(serial_bn);
}

static int
validate_revoked(X509_CRL *crl)
{
	STACK_OF(X509_REVOKED) *revoked_stack;
	X509_REVOKED *revoked;
	ASN1_INTEGER const *serial_int;
	int i;

	revoked_stack = X509_CRL_get_REVOKED(crl);
	if (revoked_stack == NULL)
		return 0; /* Guess the RFC doesn't enforce this thing. */

	for (i = 0; i < sk_X509_REVOKED_num(revoked_stack); i++) {
		revoked = sk_X509_REVOKED_value(revoked_stack, i);

		serial_int = X509_REVOKED_get0_serialNumber(revoked);
		if (serial_int == NULL) {
			return pr_val_err("CRL's revoked entry #%d lacks a serial number.",
			    i + 1);
		}

		if (log_val_enabled(LOG_DEBUG))
			debug_revoked(serial_int);

		if (X509_REVOKED_get0_revocationDate(revoked) == NULL) {
			return pr_val_err("CRL's revoked entry #%d lacks a revocation date.",
			    i + 1);
		}
		if (X509_REVOKED_get0_extensions(revoked) != NULL) {
			return pr_val_err("CRL's revoked entry #%d has extensions.",
			    i + 1);
		}
	}

	return 0;
}

static int
handle_crlnum(void *ext, void *arg)
{
	/*
	 * We're allowing only one CRL per RPP, so there's nothing to do here I
	 * think.
	 */
	return 0;
}

static int
validate_extensions(X509_CRL *crl)
{
	struct extension_handler handlers[] = {
	   /* ext        reqd   handler        arg */
	    { ext_aki(), true,  handle_aki,              },
	    { ext_cn(),  true,  handle_crlnum,           },
	    { NULL },
	};

	return handle_extensions(handlers, X509_CRL_get0_extensions(crl));
}

static int
crl_validate(X509_CRL *crl)
{
	long version;
	int error;

	version = X509_CRL_get_version(crl);
	if (version != 1)
		return pr_val_err("CRL version (%ld) is not v2 (%d).", version, 1);

	error = validate_certificate_signature_algorithm(
	    X509_CRL_get_signature_nid(crl), "CRL");
	if (error)
		return error;

	error = validate_issuer_name("CRL", X509_CRL_get_issuer(crl));
	if (error)
		return error;

	error = validate_revoked(crl);
	if (error)
		return error;

	return validate_extensions(crl);
}

int
crl_load(char const *path, X509_CRL **result)
{
	int error;

	pr_val_debug("CRL '%s' {", path);

	error = __crl_load(path, result);
	if (error)
		goto end;

	error = crl_validate(*result);
	if (error)
		X509_CRL_free(*result);

end:
	pr_val_debug("}");
	return error;
}
