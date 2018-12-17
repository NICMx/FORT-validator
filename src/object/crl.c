#include "crl.h"

#include "log.h"

static void
print_serials(X509_CRL *crl)
{
#ifdef DEBUG
	STACK_OF(X509_REVOKED) *revokeds;
	X509_REVOKED *revoked;
	ASN1_INTEGER const *serial_int;
	BIGNUM *serial_bn;
	int i;

	revokeds = X509_CRL_get_REVOKED(crl);

	for (i = 0; i < sk_X509_REVOKED_num(revokeds); i++) {
		revoked = sk_X509_REVOKED_value(revokeds, i);
		if (revoked == NULL) {
			pr_err("??");
			continue;
		}

		serial_int = X509_REVOKED_get0_serialNumber(revoked);
		if (serial_int == NULL) {
			pr_err("??");
			continue;
		}

		serial_bn = ASN1_INTEGER_to_BN(serial_int, NULL);
		if (serial_bn == NULL) {
			crypto_err("Could not parse revoked serial number");
			continue;
		}

		pr_debug_prefix();
		fprintf(stdout, "Revoked: ");
		BN_print_fp(stdout, serial_bn);
		fprintf(stdout, "\n");
		BN_free(serial_bn);
	}
#endif
}

static int
__crl_load(const char *file, X509_CRL **result)
{
	X509_CRL *crl = NULL;
	BIO *bio;
	int error;

	bio = BIO_new(BIO_s_file());
	if (bio == NULL)
		return crypto_err("BIO_new(BIO_s_file()) returned NULL");
	if (BIO_read_filename(bio, file) <= 0) {
		error = crypto_err("Error reading CRL '%s'", file);
		goto end;
	}

	crl = d2i_X509_CRL_bio(bio, NULL);
	if (crl == NULL) {
		error = crypto_err("Error parsing CRL '%s'", file);
		goto end;
	}

	print_serials(crl);

	*result = crl;
	error = 0;

end:
	BIO_free(bio);
	return error;
}

int
crl_load(char const *file, X509_CRL **result)
{
	int error;

	pr_debug_add("CRL %s {", file);
	error = __crl_load(file, result);
	pr_debug_rm("}");

	return error;
}
