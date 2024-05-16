#include "asn1/asn1c/Certificate.h"

#include <openssl/x509v3.h>

#include "extension.h"
#include "json_util.h"
#include "libcrypto_util.h"

static json_t *
validity2json(X509 *x)
{
	json_t *parent;
	json_t *child;

	parent = json_obj_new();
	if (parent == NULL)
		return NULL;

	child = asn1time2json(X509_get0_notBefore(x));
	if (json_object_add(parent, "notBefore", child))
		goto fail;
	child = asn1time2json(X509_get0_notAfter(x));
	if (json_object_add(parent, "notAfter", child))
		goto fail;

	return parent;

fail:	json_decref(parent);
	return NULL;
}

static json_t *
pk2json(X509 const *x)
{
	json_t *root;
	json_t *child;
	X509_PUBKEY *pubkey;
	ASN1_OBJECT *oid;

	root = json_obj_new();
	if (root == NULL)
		return NULL;

	pubkey = X509_get_X509_PUBKEY(x);
	if (pubkey == NULL)
		goto fail;
	if (!X509_PUBKEY_get0_param(&oid, NULL, NULL, NULL, pubkey))
		goto fail;

	child = oid2json(oid);
	if (json_object_add(root, "algorithm", child))
		goto fail;
	child = pubkey2json(X509_PUBKEY_get0(pubkey));
	if (json_object_add(root, "subjectPublicKey", child))
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
	json_t *parent;
	json_t *child;

	parent = json_obj_new();
	if (parent == NULL)
		return NULL;

	child = json_int_new(X509_get_version(x));
	if (json_object_add(parent, "version", child))
		goto fail;
	child = asn1int2json(X509_get0_serialNumber(x));
	if (json_object_add(parent, "serialNumber", child))
		goto fail;
	child = json_str_new(OBJ_nid2sn(X509_get_signature_nid(x)));
	if (json_object_add(parent, "signature", child))
		goto fail;
	child = name2json(X509_get_issuer_name(x));
	if (json_object_add(parent, "issuer", child))
		goto fail;
	child = validity2json(x);
	if (json_object_add(parent, "validity", child))
		goto fail;
	child = name2json(X509_get_subject_name(x));
	if (json_object_add(parent, "subject", child))
		goto fail;
	child = pk2json(x);
	if (json_object_add(parent, "subjectPublicKeyInfo", child))
		goto fail;
	child = iuid2json(x);
	if (json_object_add(parent, "issuerUniqueID", child))
		goto fail;
	child = suid2json(x);
	if (json_object_add(parent, "subjectUniqueID", child))
		goto fail;
	child = exts2json(X509_get0_extensions(x));
	if (json_object_add(parent, "extensions", child))
		goto fail;

	return parent;

fail:	json_decref(parent);
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
	json_t *parent;
	json_t *child;

	parent = json_obj_new();
	if (parent == NULL)
		return NULL;

	child = tbsCert2json(x);
	if (json_object_add(parent, "tbsCertificate", child))
		goto fail;
	child = sigAlgorithm2json(x);
	if (json_object_add(parent, "signatureAlgorithm", child))
		goto fail;
	child = sigValue2json(x);
	if (json_object_add(parent, "signatureValue", child))
		goto fail;

	return parent;

fail:	json_decref(parent);
	return NULL;
}

json_t *
Certificate_any2json(ANY_t *ber)
{
	const unsigned char *tmp;
	X509 *cert;
	json_t *json;

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

	json = x509_to_json(cert);

	X509_free(cert);
	return json;
}

json_t *
Certificate_bio2json(BIO *bio)
{
	X509 *cert;
	json_t *json;

	cert = d2i_X509_bio(bio, NULL);
	if (cert == NULL)
		return NULL;

	json = x509_to_json(cert);

	X509_free(cert);
	return json;
}
