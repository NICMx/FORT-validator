#include "certificate.h"

#include <libcmscodec/SubjectInfoAccessSyntax.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "common.h"
#include "log.h"
#include "manifest.h"
#include "asn1/decode.h"

/*
 * The X509V3_EXT_METHOD that references NID_sinfo_access uses the AIA item.
 * The SIA's d2i function, therefore, returns AIAs.
 * They are the same as far as LibreSSL is concerned.
 */
typedef AUTHORITY_INFO_ACCESS SIGNATURE_INFO_ACCESS;

bool is_certificate(char const *file_name)
{
	return file_has_extension(file_name, "cer");
}

X509 *
certificate_load(struct validation *state, const char *file)
{
	X509 *cert = NULL;
	BIO *bio;

	bio = BIO_new(BIO_s_file());
	if (bio == NULL) {
		crypto_err(state, "BIO_new(BIO_s_file()) returned NULL");
		goto end;
	}
	if (BIO_read_filename(bio, file) <= 0) {
		crypto_err(state, "Error reading certificate '%s'", file);
		goto end;
	}

	cert = d2i_X509_bio(bio, NULL);
	if (cert == NULL)
		crypto_err(state, "Error parsing certificate '%s'", file);

end:
	BIO_free(bio);
	return cert;
}

int
certificate_handle_extensions(struct validation *state, X509 *cert)
{
	SIGNATURE_INFO_ACCESS *sia;
	ACCESS_DESCRIPTION *ad;
	char const *uri;
	char *luri;
	int nid;
	int i;
	int error;

	sia = X509_get_ext_d2i(cert, NID_sinfo_access, &error, NULL);
	if (sia == NULL) {
		switch (error) {
		case -1:
			pr_err(state, "Certificate lacks an SIA extension.");
			return -ESRCH;
		case -2:
			pr_err(state, "Certificate has more than one SIA extension.");
			return -EINVAL;
		default:
			pr_err(state,
			    "X509_get_ext_d2i() returned unknown error code %d.",
			    error);
			return -EINVAL;
		}
	}

	pr_debug_add(state, "SIA {");
	error = 0;

	for (i = 0; i < sk_ACCESS_DESCRIPTION_num(sia); i++) {
		ad = sk_ACCESS_DESCRIPTION_value(sia, i);
		nid = OBJ_obj2nid(ad->method);

		if (nid == NID_rpkiManifest) {
			error = gn2uri(state, ad->location, &uri);
			if (error)
				goto end;
			error = uri_g2l(state, uri, &luri);
			if (error)
				goto end;
			error = handle_manifest(state, luri);
			free(luri);
			if (error)
				goto end;

		} else if (nid == NID_rpkiNotify) {
			/* TODO Another fucking RFC... */
			pr_debug(state, "Unimplemented thingy: rpkiNotify");

		} else if (nid == NID_caRepository) {
			error = gn2uri(state, ad->location, &uri);
			if (error)
				goto end;
			/* TODO no idea what to do with this. */
			pr_debug(state, "CA Repository URI: %s", uri);

		} else {
			pr_debug(state, "Unknown NID: %d", nid);
			goto end;
		}
	}

end:
	AUTHORITY_INFO_ACCESS_free(sia);
	pr_debug_rm(state, "}");
	return error;
}

int
certificate_handle(struct validation *state, char const *file)
{
	X509 *certificate;
	int error;

	pr_debug_add(state, "Certificate {");

	certificate = certificate_load(state, file);
	if (certificate == NULL) {
		/* TODO get the right one through the ERR_* functions. */
		error = -EINVAL;
		goto end;
	}

	error = validation_push(state, certificate);
	if (error)
		goto end;

	error = certificate_handle_extensions(state, certificate);
	validation_pop(state);

end:
	pr_debug_rm(state, "}");
	return error;
}
