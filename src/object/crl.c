#include "crl.h"

#include <libcmscodec/SubjectInfoAccessSyntax.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "common.h"
#include "log.h"
#include "manifest.h"
#include "asn1/decode.h"

bool is_crl(char const *file_name)
{
	return file_has_extension(file_name, "crl");
}

static X509_CRL *
load_crl(struct validation *state, const char *file)
{
	X509_CRL *crl = NULL;
	BIO *bio;

	bio = BIO_new(BIO_s_file());
	if (bio == NULL) {
		crypto_err(state, "BIO_new(BIO_s_file()) returned NULL");
		goto end;
	}
	if (BIO_read_filename(bio, file) <= 0) {
		crypto_err(state, "Error reading CRL '%s'", file);
		goto end;
	}

	crl = d2i_X509_CRL_bio(bio, NULL);
	if (crl == NULL)
		crypto_err(state, "Error parsing CRL '%s'", file);

end:
	BIO_free(bio);
	return crl;
}

static int
handle_authority_key_identifier(struct validation *state, X509_EXTENSION *ext)
{
	/* TODO */
	pr_debug(state, "Unimplemented still: Authority Key Identifier");
	/* AUTHORITY_KEYID *aki = X509V3_EXT_d2i(ext); */
	/* AUTHORITY_KEYID_free(aki); */
	return 0;
}

static int
handle_revoked(struct validation *state, X509_REVOKED *revoked)
{
	const ASN1_INTEGER *serialNumber;
	const ASN1_TIME *revocationDate;

	serialNumber = X509_REVOKED_get0_serialNumber(revoked);
	revocationDate = X509_REVOKED_get0_revocationDate(revoked);

	if (serialNumber == NULL) {
		pr_err(state, "Revoked entry's serial number is NULL.");
		return -EINVAL;
	}
	if (revocationDate == NULL) {
		pr_err(state, "Revoked entry's revocation date is NULL.");
		return -EINVAL;
	}
	if (X509_REVOKED_get0_extensions(revoked) != NULL) {
		pr_err(state, "Revoked entry's extension list is not NULL.");
		return -EINVAL;
	}

	pr_debug(state, "Revoked:%ld", ASN1_INTEGER_get(serialNumber));
//	ASN1_TIME_print(bio_err, revocationDate);
//	printf("\n");
	return 0;
}

static int
handle_revoked_list(struct validation *state, X509_CRL *crl)
{
	STACK_OF(X509_REVOKED) *list;
	unsigned int i;
	int error;

	list = X509_CRL_get_REVOKED(crl);
	for (i = 0; i < sk_X509_REVOKED_num(list); i++) {
		error = handle_revoked(state, sk_X509_REVOKED_value(list, i));
		if (error)
			return error;
	}

	return 0;
}

static int
handle_crl_number(struct validation *state, X509_EXTENSION *ext)
{
	pr_debug(state, "Unimplemented still: CRL Number"); /* TODO */
	return 0;
}

static int
handle_extensions(struct validation *state, X509_CRL *crl)
{
	const STACK_OF(X509_EXTENSION) *exts;
	X509_EXTENSION *ext;
	unsigned int i;
	int nid;
	int error;

	exts = X509_CRL_get0_extensions(crl);
	for (i = 0; i < sk_X509_EXTENSION_num(exts); i++) {
		ext = sk_X509_EXTENSION_value(exts, i);
		nid = OBJ_obj2nid(X509_EXTENSION_get_object(ext));

		switch (nid) {
		case NID_authority_key_identifier:
			error = handle_authority_key_identifier(state, ext);
			break;
		case NID_crl_number:
			error = handle_crl_number(state, ext);
			break;
		default:
			pr_err(state, "CRL has illegal extension: NID %d", nid);
			return -EINVAL;
		}

		if (error)
			return error;
	}

	return 0;
}

int
handle_crl(struct validation *state, char const *file)
{
	X509_CRL *crl;
	int error;

	pr_debug_add(state, "CRL {");

	crl = load_crl(state, file);
	if (!crl) {
		/* TODO get the right one through the ERR_* functions. */
		error = -EINVAL;
		goto abort2;
	}

	error = handle_revoked_list(state, crl);
	if (error)
		goto abort3;

	error = handle_extensions(state, crl);

abort3:
	X509_CRL_free(crl);
abort2:
	pr_debug_rm(state, "}");
	return error;
}
