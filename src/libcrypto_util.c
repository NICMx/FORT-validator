#include "libcrypto_util.h"

#include <stdlib.h>
#include <openssl/asn1.h>

#include "alloc.h"

/* Swallows @bio. */
char *
bio2str(BIO *bio)
{
	BUF_MEM *buffer;
	char *str;

	str = (BIO_get_mem_ptr(bio, &buffer) > 0)
	    ? pstrndup(buffer->data, buffer->length)
	    : NULL;

	BIO_free_all(bio);
	return str;
}

/* Swallows @bio. */
json_t *
bio2json(BIO *bio)
{
	BUF_MEM *buffer;
	json_t *json;

	json = (BIO_get_mem_ptr(bio, &buffer) > 0)
	    ? json_stringn(buffer->data, buffer->length)
	    : NULL;

	BIO_free_all(bio);
	return json;
}

json_t *
oid2json(ASN1_OBJECT const *oid)
{
	return oid ? json_string(OBJ_nid2sn(OBJ_obj2nid(oid))) : json_null();
}

json_t *
asn1int2json(ASN1_INTEGER const *asn1int)
{
	BIGNUM *bignum;
	char *str;
	json_t *json;

	if (asn1int == NULL)
		return json_null();

	bignum = ASN1_INTEGER_to_BN(asn1int, NULL);
	str = BN_bn2hex(bignum);

	json = json_string(str);

	OPENSSL_free(str);
	BN_free(bignum);

	return json;
}

json_t *
asn1str2json(ASN1_STRING const *str)
{
	BIO *bio;
	int i;

	if (str == NULL)
		return json_null();

	bio = BIO_new(BIO_s_mem());
	if (bio == NULL)
		return NULL;

	for (i = 0; i < str->length; i++) {
		if (BIO_printf(bio, "%02x", str->data[i]) <= 0) {
			BIO_free_all(bio);
			return NULL;
		}
	}

	return bio2json(bio);
}

json_t *
asn1time2json(ASN1_TIME const *time)
{
	BIO *bio;

	if (time == NULL)
		return json_null();

	bio = BIO_new(BIO_s_mem());
	if (bio == NULL)
		return NULL;

	if (!ASN1_TIME_print_ex(bio, time, ASN1_DTFLGS_ISO8601)) {
		BIO_free_all(bio);
		return NULL;
	}

	return bio2json(bio);
}

json_t *
name2json(X509_NAME const *name)
{
	json_t *root;
	json_t *child;
	int i;

	if (name == NULL)
		return json_null();

	root = json_object();
	if (root == NULL)
		return NULL;

	for (i = 0; i < X509_NAME_entry_count(name); i++) {
		X509_NAME_ENTRY *entry;
		int nid;
		const ASN1_STRING *data;

		entry = X509_NAME_get_entry(name, i);
		nid = OBJ_obj2nid(X509_NAME_ENTRY_get_object(entry));

		data = X509_NAME_ENTRY_get_data(entry);
		if (data == NULL)
			goto fail;
		child = json_stringn((char *)data->data, data->length);

		if (json_object_set_new(root, OBJ_nid2sn(nid), child) < 0)
			goto fail;
	}

	return root;

fail:	json_decref(root);
	return NULL;
}

json_t *
gn2json(GENERAL_NAME const *gn)
{
	ASN1_IA5STRING *str;
	int type;

	if (gn == NULL)
		return json_null();

	str = GENERAL_NAME_get0_value(gn, &type); // FIXME open call hierarchy FIXME getter review
	return (type == GEN_URI)
	    ? json_stringn((char const *)str->data, str->length)
	    : json_string("<Not implemented for now>");
}

json_t *
gns2json(GENERAL_NAMES const *gns)
{
	json_t *root;
	int n;

	if (gns == NULL)
		return json_null();

	root = json_array();
	if (root == NULL)
		return NULL;

	for (n = 0; n < sk_GENERAL_NAME_num(gns); n++)
		if (json_array_append_new(root, gn2json(sk_GENERAL_NAME_value(gns, n))) < 0)
			goto fail;

	return root;

fail:	json_decref(root);
	return NULL;
}
