#include "object/crl.h"

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <syslog.h>

#include "algorithm.h"
#include "ext.h"
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
		error = val_crypto_err("Error reading CRL");
		goto end;
	}

	crl = d2i_X509_CRL_bio(bio, NULL);
	if (crl == NULL) {
		error = val_crypto_err("Error parsing CRL");
		goto end;
	}

	*result = crl;
	error = 0;

end:
	BIO_free(bio);
	return error;
}

static void
pr_clutter_revoked(ASN1_INTEGER const *serial_int)
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

	pr_clutter("Revoked: %s", serial_str);

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

		if (pr_clutter_enabled())
			pr_clutter_revoked(serial_int);

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
	 * TODO (fine) update RFC name later
	 *
	 * From draft-spaghetti-sidrops-rpki-crl-numbers:
	 *
	 * In the RPKI, a wellformed Manifest FileList contains exactly one
	 * entry for its associated CRL, together with a collision-resistant
	 * message digest of that CRLs contents (see Section 2.2 of RFC6481
	 * and Section 2 of RFC9286). Additionally, the target of the CRL
	 * Distribution Points extension in an RPKI Resource Certificate is the
	 * same CRL object listed on the issuing CAs current manifest (see
	 * Section 4.8.6 of RFC6487). Together, these properties guarantee
	 * that RPKI RPs will always be able to unambiguously identify exactly
	 * one current CRL for each RPKI CA. Thus, in the RPKI, the ordering
	 * functionality provided by CRL Numbers is fully subsumed by monotonically
	 * increasing Manifest Numbers (Section 4.2.1 of RFC9286), thereby
	 * obviating the need for RPKI RPs to process CRL Number extensions.
	 */

	return 0;
}

static int
validate_extensions(X509_CRL *crl, X509 *parent)
{
	struct extension_handler handlers[] = {
	   /* ext        reqd   handler        arg */
	    { ext_aki(), true,  handle_aki,    parent    },
	    { ext_cn(),  true,  handle_crlnum,           },
	    { NULL },
	};

	return handle_extensions(handlers, X509_CRL_get0_extensions(crl));
}

static int
crl_validate(X509_CRL *crl, X509 *parent)
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

	error = validate_issuer_name(X509_CRL_get_issuer(crl), parent);
	if (error)
		return error;

	error = validate_revoked(crl);
	if (error)
		return error;

	return validate_extensions(crl, parent);
}

int
crl_load(struct cache_mapping *map, X509 *parent, X509_CRL **result)
{
	int error;

	fnstack_push_map(map);

	error = __crl_load(map->path, result);
	if (error)
		goto end;

	error = crl_validate(*result, parent);
	if (error)
		X509_CRL_free(*result);

end:	fnstack_pop();
	return error;
}
