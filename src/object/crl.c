#include "crl.h"

#include <libcmscodec/SubjectInfoAccessSyntax.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "common.h"
#include "log.h"
#include "manifest.h"
#include "asn1/decode.h"

static int
__crl_load(struct validation *state, const char *file, X509_CRL **result)
{
	X509_CRL *crl = NULL;
	BIO *bio;
	int error;

	bio = BIO_new(BIO_s_file());
	if (bio == NULL)
		return crypto_err(state, "BIO_new(BIO_s_file()) returned NULL");
	if (BIO_read_filename(bio, file) <= 0) {
		error = crypto_err(state, "Error reading CRL '%s'", file);
		goto end;
	}

	crl = d2i_X509_CRL_bio(bio, NULL);
	if (crl == NULL) {
		error = crypto_err(state, "Error parsing CRL '%s'", file);
		goto end;
	}

	*result = crl;
	error = 0;

end:
	BIO_free(bio);
	return error;
}

int
crl_load(struct validation *state, char const *file, X509_CRL **result)
{
	int error;

	pr_debug_add("CRL {");
	error = __crl_load(state, file, result);
	pr_debug_rm("}");

	return error;
}
