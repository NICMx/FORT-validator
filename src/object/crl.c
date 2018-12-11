#include "crl.h"

#include "log.h"

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

	pr_debug_add("CRL {");
	error = __crl_load(file, result);
	pr_debug_rm("}");

	return error;
}
