#include "certificate.h"

#include <err.h>
#include <libcmscodec/SubjectInfoAccessSyntax.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "common.h"
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

static X509 *
load_certificate(BIO *bio_err, const char *file)
{
	X509 *cert = NULL;
	BIO *bio;

	bio = BIO_new(BIO_s_file());
	if (bio == NULL) {
		BIO_printf(bio_err, "BIO_new(BIO_s_file()) returned NULL.\n");
		ERR_print_errors(bio_err);
		goto end;
	}
	if (BIO_read_filename(bio, file) <= 0) {
		BIO_printf(bio_err, "Error reading certificate '%s'.\n", file);
		ERR_print_errors(bio_err);
		goto end;
	}

	cert = d2i_X509_bio(bio, NULL);
	if (cert == NULL) {
		BIO_printf(bio_err, "Error parsing certificate '%s'.\n", file);
		ERR_print_errors(bio_err);
	}

end:
	BIO_free(bio);
	return cert;
}

static int
handle_extensions(X509 *cert)
{
	SIGNATURE_INFO_ACCESS *sia;
	ACCESS_DESCRIPTION *ad;
	char const *uri;
	char *luri;
	int nid;
	int i;
	int error;

	sia = X509_get_ext_d2i(cert, NID_sinfo_access, &error, NULL);
	if (!sia) {
		switch (error) {
		case -1:
			warnx("The certificate lacks an SIA extension.");
			return -ESRCH;
		case -2:
			warnx("The certificate has more than one SIA extension.");
			return -EINVAL;
		default:
			warnx("X509_get_ext_d2i() returned unknown error code %d.",
			    error);
			return -EINVAL;
		}
	}

	pr_debug0_add("SIA {");
	error = 0;

	for (i = 0; i < sk_ACCESS_DESCRIPTION_num(sia); i++) {
		ad = sk_ACCESS_DESCRIPTION_value(sia, i);
		nid = OBJ_obj2nid(ad->method);

		if (nid == NID_rpkiManifest) {
			error = gn2uri(ad->location, &uri);
			if (error)
				goto end;
			error = uri_g2l(uri, &luri);
			if (error)
				goto end;
			error = handle_manifest(luri);
			free(luri);
			if (error)
				goto end;

		} else if (nid == NID_rpkiNotify) {
			/* TODO Another fucking RFC... */
			pr_debug0("Unimplemented thingy: rpkiNotify");

		} else if (nid == NID_caRepository) {
			error = gn2uri(ad->location, &uri);
			if (error)
				goto end;
			/* TODO no idea what to do with this. */
			pr_debug("CA Repository URI: %s", uri);

		} else {
			pr_debug("Unknown NID: %d", nid);
			goto end;
		}
	}

end:
	AUTHORITY_INFO_ACCESS_free(sia);
	pr_debug0_rm("}");
	return error;
}

int
handle_certificate(char const *file)
{
	X509 *certificate;
	BIO *bio_err;
	int error;

	pr_debug0_add("Certificate {");

	bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
	if (bio_err == NULL) {
		warnx("Failed to initialise bio_err.");
		/* TODO get the right one through the ERR_* functions. */
		error = -ENOMEM;
		goto abort1;
	}

	certificate = load_certificate(bio_err, file);
	if (!certificate) {
		/* TODO get the right one through the ERR_* functions. */
		error = -EINVAL;
		goto abort2;
	}

	error = handle_extensions(certificate);
	X509_free(certificate);

abort2:
	BIO_free_all(bio_err);
abort1:
	pr_debug0_rm("}");
	return error;
}
