#include "asn1/asn1c/Certificate.h"

#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include "extension.h"
#include "libcrypto_util.h"

static json_t *
validity2json(X509 *x)
{
	json_t *root;

	root = json_object();
	if (root == NULL)
		return NULL;

	if (json_object_set_new(root, "notBefore", asn1time2json(X509_get0_notBefore(x))) < 0)
		goto fail;
	if (json_object_set_new(root, "notAfter", asn1time2json(X509_get0_notAfter(x))) < 0)
		goto fail;

	return root;

fail:	json_decref(root);
	return NULL;
}

static json_t *
pk2json(X509 const *x)
{
	json_t *root;
	ASN1_OBJECT *xpoid;
	EVP_PKEY *pkey;
	BIO *bio;

	root = json_object();
	if (root == NULL)
		return NULL;

	/* algorithm */
	if (!X509_PUBKEY_get0_param(&xpoid, NULL, NULL, NULL, X509_get_X509_PUBKEY(x)))
		goto fail;
	bio = BIO_new(BIO_s_mem());
	if (bio == NULL)
		goto fail;
	if (i2a_ASN1_OBJECT(bio, xpoid) <= 0) {
		BIO_free_all(bio);
		goto fail;
	}
	if (json_object_set_new(root, "algorithm", bio2json(bio)))
		goto fail;

	/* Actual pk */
	pkey = X509_get0_pubkey(x);
	if (pkey == NULL)
		goto fail;
	bio = BIO_new(BIO_s_mem());
	if (bio == NULL)
		goto fail;
	if (PEM_write_bio_PUBKEY(bio, pkey) <= 0) {
		BIO_free_all(bio);
		goto fail;
	}
	if (json_object_set_new(root, "subjectPublicKey", bio2json(bio)))
		goto fail;

	return root;

fail:	json_decref(root);
	return NULL;
}

static json_t *
iuid2json(X509 const *x)
{
	const ASN1_BIT_STRING *iuid;
	X509_get0_uids(x, &iuid, NULL);
	return asn1str2json(iuid);
}

static json_t *
suid2json(X509 const *x)
{
	const ASN1_BIT_STRING *suid;
	X509_get0_uids(x, NULL, &suid);
	return asn1str2json(suid);
}

static json_t *
tbsCert2json(X509 *x)
{
	json_t *tbsCert;

	tbsCert = json_object();
	if (tbsCert == NULL)
		return NULL;

	if (json_object_set_new(tbsCert, "version", json_integer(X509_get_version(x))) < 0)
		goto fail;
	if (json_object_set_new(tbsCert, "serialNumber", asn1int2json(X509_get0_serialNumber(x))) < 0)
		goto fail;
	if (json_object_set_new(tbsCert, "signature", json_string(OBJ_nid2sn(X509_get_signature_nid(x)))) < 0)
		goto fail;
	if (json_object_set_new(tbsCert, "issuer", name2json(X509_get_issuer_name(x))) < 0)
		goto fail;
	if (json_object_set_new(tbsCert, "validity", validity2json(x)) < 0)
		goto fail;
	if (json_object_set_new(tbsCert, "subject", name2json(X509_get_subject_name(x))) < 0)
		goto fail;
	if (json_object_set_new(tbsCert, "subjectPublicKeyInfo", pk2json(x)) < 0)
		goto fail;
	if (json_object_set_new(tbsCert, "issuerUniqueID", iuid2json(x)) < 0)
		goto fail;
	if (json_object_set_new(tbsCert, "subjectUniqueID", suid2json(x)) < 0)
		goto fail;
	if (json_object_set_new(tbsCert, "extensions", exts2json(X509_get0_extensions(x))) < 0)
		goto fail;

	return tbsCert;

fail:	json_decref(tbsCert);
	return NULL;
}

static json_t *
sigAlgorithm2json(X509 *cert)
{
	const X509_ALGOR *palg;
	const ASN1_OBJECT *paobj;

	X509_get0_signature(NULL, &palg, cert);
	X509_ALGOR_get0(&paobj, NULL, NULL, palg);

	return oid2json(paobj);
}

static json_t *
sigValue2json(X509 *cert)
{
	const ASN1_BIT_STRING *signature;
	X509_get0_signature(&signature, NULL, cert);
	return asn1str2json(signature);
}

static json_t *
x509_to_json(X509 *x)
{
	json_t *root;

	root = json_object();
	if (root == NULL)
		return NULL;

	if (json_object_set_new(root, "tbsCertificate", tbsCert2json(x)) < 0)
		goto fail;
	if (json_object_set_new(root, "signatureAlgorithm", sigAlgorithm2json(x)) < 0)
		goto fail;
	if (json_object_set_new(root, "signatureValue", sigValue2json(x)) < 0)
		goto fail;

	return root;

fail:	json_decref(root);
	return NULL;
}

json_t *
Certificate_any2json(ANY_t *ber)
{
	const unsigned char *tmp;
	X509 *cert;
	json_t *root;

	/*
	 * "If the call is successful *in is incremented to the byte following
	 * the parsed data."
	 * (https://www.openssl.org/docs/man1.0.2/crypto/d2i_X509_fp.html)
	 * We don't want @ber->buf modified, so use a dummy pointer.
	 */
	tmp = (const unsigned char *) ber->buf;

	cert = d2i_X509(NULL, &tmp, ber->size);
	if (cert == NULL)
		return NULL;

	root = x509_to_json(cert);

	X509_free(cert);
	return root;
}

json_t *
Certificate_file2json(FILE *file)
{
	X509 *cert;
	json_t *root;

	cert = d2i_X509_fp(file, NULL);
	if (cert == NULL)
		return NULL;

	root = x509_to_json(cert);

	X509_free(cert);
	return root;
}
