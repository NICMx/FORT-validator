#include "asn1/asn1c/CRL.h"

#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include "extension.h"
#include "libcrypto_util.h"

static json_t *
revokedCerts2json(X509_CRL *crl)
{
	STACK_OF(X509_REVOKED) *revokeds = X509_CRL_get_REVOKED(crl);
	json_t *root, *child;
	X509_REVOKED *rv;
	int r;

	root = json_array();
	if (root == NULL)
		return NULL;

	for (r = 0; r < sk_X509_REVOKED_num(revokeds); r++) {
		rv = sk_X509_REVOKED_value(revokeds, 0);
		if (json_array_append_new(root, child = json_object()) < 0)
			goto fail;
		if (json_object_set_new(child, "userCertificate", asn1int2json(X509_REVOKED_get0_serialNumber(rv))) < 0)
			goto fail;
		if (json_object_set_new(child, "revocationDate", asn1time2json(X509_REVOKED_get0_revocationDate(rv))) < 0)
			goto fail;
		if (json_object_set_new(child, "crlEntryExtensions", exts2json(X509_REVOKED_get0_extensions(rv))) < 0)
			goto fail;
	}

	return root;

fail:	json_decref(root);
	return NULL;
}

static json_t *
tbsCertList2json(X509_CRL *crl)
{
	json_t *root;

	root = json_object();
	if (root == NULL)
		return NULL;

	if (json_object_set_new(root, "version", json_integer(X509_CRL_get_version(crl))) < 0)
		goto fail;
	if (json_object_set_new(root, "signature", json_string(OBJ_nid2sn(X509_CRL_get_signature_nid(crl)))) < 0)
		goto fail;
	if (json_object_set_new(root, "issuer", name2json(X509_CRL_get_issuer(crl))) < 0)
		goto fail;
	if (json_object_set_new(root, "thisUpdate", asn1time2json(X509_CRL_get0_lastUpdate(crl))) < 0)
		goto fail;
	if (json_object_set_new(root, "nextUpdate", asn1time2json(X509_CRL_get0_nextUpdate(crl))) < 0)
		goto fail;
	if (json_object_set_new(root, "revokedCertificates", revokedCerts2json(crl)) < 0)
		goto fail;
	if (json_object_set_new(root, "crlExtensions", exts2json(X509_CRL_get0_extensions(crl))) < 0)
		goto fail;

	return root;

fail:	json_decref(root);
	return NULL;
}

static json_t *
sigAlgorithm2json(X509_CRL *crl)
{
	const X509_ALGOR *palg;
	const ASN1_OBJECT *paobj;

	X509_CRL_get0_signature(crl, NULL, &palg);
	X509_ALGOR_get0(&paobj, NULL, NULL, palg);

	return oid2json(paobj);
}

static json_t *
sigValue2json(X509_CRL *crl)
{
	const ASN1_BIT_STRING *signature;
	X509_CRL_get0_signature(crl, &signature, NULL);
	return asn1str2json(signature);
}

static json_t *
crl2json(X509_CRL *crl)
{
	json_t *root;

	root = json_object();
	if (root == NULL)
		return NULL;

	if (json_object_set_new(root, "tbsCertList", tbsCertList2json(crl)) < 0)
		goto fail;
	if (json_object_set_new(root, "signatureAlgorithm", sigAlgorithm2json(crl)) < 0)
		goto fail;
	if (json_object_set_new(root, "signatureValue", sigValue2json(crl)) < 0)
		goto fail;

	return root;

fail:	json_decref(root);
	return NULL;
}

json_t *
CRL_encode_json(ANY_t *ber)
{
	const unsigned char *tmp = (const unsigned char *) ber->buf;
	X509_CRL *crl;
	json_t *root;

	crl = d2i_X509_CRL(NULL, &tmp, ber->size);
	if (crl == NULL)
		return NULL;

	root = crl2json(crl);

	X509_CRL_free(crl);
	return root;
}
