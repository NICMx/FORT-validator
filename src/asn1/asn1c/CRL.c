#include "asn1/asn1c/CRL.h"

#include <openssl/x509v3.h>
#include <openssl/pem.h>

#include "extension.h"
#include "json_util.h"
#include "libcrypto_util.h"

static json_t *
revokedCerts2json(X509_CRL *crl)
{
	STACK_OF(X509_REVOKED) *revokeds = X509_CRL_get_REVOKED(crl);
	json_t *root;
	json_t *parent;
	json_t *child;
	X509_REVOKED *rv;
	int r;

	root = json_array_new();
	if (root == NULL)
		return NULL;

	for (r = 0; r < sk_X509_REVOKED_num(revokeds); r++) {
		rv = sk_X509_REVOKED_value(revokeds, r);

		if (json_array_add(root, parent = json_obj_new()))
			goto fail;

		child = asn1int2json(X509_REVOKED_get0_serialNumber(rv));
		if (json_object_add(parent, "userCertificate", child))
			goto fail;
		child = asn1time2json(X509_REVOKED_get0_revocationDate(rv));
		if (json_object_add(parent, "revocationDate", child))
			goto fail;
		child = exts2json(X509_REVOKED_get0_extensions(rv));
		if (json_object_add(parent, "crlEntryExtensions", child))
			goto fail;
	}

	return root;

fail:	json_decref(root);
	return NULL;
}

static json_t *
tbsCertList2json(X509_CRL *crl)
{
	json_t *parent;
	json_t *child;

	parent = json_obj_new();
	if (parent == NULL)
		return NULL;

	child = json_int_new(X509_CRL_get_version(crl));
	if (json_object_add(parent, "version", child))
		goto fail;
	child = json_str_new(OBJ_nid2sn(X509_CRL_get_signature_nid(crl)));
	if (json_object_add(parent, "signature", child))
		goto fail;
	child = name2json(X509_CRL_get_issuer(crl));
	if (json_object_add(parent, "issuer", child))
		goto fail;
	child = asn1time2json(X509_CRL_get0_lastUpdate(crl));
	if (json_object_add(parent, "thisUpdate", child))
		goto fail;
	child = asn1time2json(X509_CRL_get0_nextUpdate(crl));
	if (json_object_add(parent, "nextUpdate", child))
		goto fail;
	child = revokedCerts2json(crl);
	if (json_object_add(parent, "revokedCertificates", child))
		goto fail;
	child = exts2json(X509_CRL_get0_extensions(crl));
	if (json_object_add(parent, "crlExtensions", child))
		goto fail;

	return parent;

fail:	json_decref(parent);
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
	json_t *parent;
	json_t *child;

	parent = json_obj_new();
	if (parent == NULL)
		return NULL;

	child = tbsCertList2json(crl);
	if (json_object_add(parent, "tbsCertList", child))
		goto fail;
	child = sigAlgorithm2json(crl);
	if (json_object_add(parent, "signatureAlgorithm", child))
		goto fail;
	child = sigValue2json(crl);
	if (json_object_add(parent, "signatureValue", child))
		goto fail;

	return parent;

fail:	json_decref(parent);
	return NULL;
}

json_t *
CRL_bio2json(BIO *bio)
{
	X509_CRL *crl;
	json_t *json;

	crl = d2i_X509_CRL_bio(bio, NULL);
	if (crl == NULL)
		return NULL;

	json = crl2json(crl);

	X509_CRL_free(crl);
	return json;
}
