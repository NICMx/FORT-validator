/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "RPKI-ROA"
 * 	found in "rfc6482.asn1"
 * 	`asn1c -Werror -fcompound-names -fwide-types -D asn1/asn1c -no-gen-PER -no-gen-example`
 */

#include "asn1/asn1c/ROAIPAddressFamily.h"

#include "asn1/asn1c/constr_SEQUENCE_OF.h"
#include "json_util.h"
#include "types/address.h"

static json_t *
prefix2json(char const *prefix, uint8_t length)
{
	json_t *root;

	root = json_obj_new();
	if (root == NULL)
		return NULL;
	if (json_object_add(root, "prefix", json_str_new(prefix)))
		goto fail;
	if (json_object_add(root, "length", json_int_new(length)))
		goto fail;

	return root;

fail:	json_decref(root);
	return NULL;
}

static json_t *
prefix4_to_json(struct ROAIPAddress *addr)
{
	struct ipv4_prefix prefix4;
	char buff[INET_ADDRSTRLEN];

	if (prefix4_decode(&addr->address, &prefix4) != 0)
		return NULL;
	if (inet_ntop(AF_INET, &prefix4.addr, buff, INET_ADDRSTRLEN) == NULL)
		return NULL;

	return prefix2json(buff, prefix4.len);
}

static json_t *
prefix6_to_json(struct ROAIPAddress *addr)
{
	struct ipv6_prefix prefix6;
	char buff[INET6_ADDRSTRLEN];

	if (prefix6_decode(&addr->address, &prefix6) != 0)
		return NULL;
	if (inet_ntop(AF_INET6, &prefix6.addr, buff, INET6_ADDRSTRLEN) == NULL)
		return NULL;

	return prefix2json(buff, prefix6.len);
}

static json_t *
AddrBlock2json(struct ROAIPAddressFamily const *riaf, char const *ipname,
    json_t *(*pref2json)(struct ROAIPAddress *))
{
	json_t *root, *addrs;
	json_t *pfx, *maxlen;
	struct ROAIPAddress *src;
	int i;

	root = json_obj_new();
	if (root == NULL)
		return NULL;

	if (json_object_add(root, "addressFamily", json_str_new(ipname)))
		goto fail;
	if (json_object_add(root, "addresses", addrs = json_array_new()))
		goto fail;

	for (i = 0; i < riaf->addresses.list.count; i++) {
		src = riaf->addresses.list.array[i];

		pfx = pref2json(src);
		if (json_array_add(addrs, pfx))
			goto fail;

		maxlen = asn_DEF_INTEGER.op->json_encoder(&asn_DEF_INTEGER,
							  src->maxLength);
		if (json_object_add(pfx, "maxLength", maxlen))
			goto fail;
	}

	return root;

fail:	json_decref(root);
	return NULL;
}

static json_t *
ROAIPAddressFamily_encode_json(const asn_TYPE_descriptor_t *td, const void *sptr)
{
	struct ROAIPAddressFamily const *riaf = sptr;
	OCTET_STRING_t const *af;

	if (!riaf)
		return json_null();

	af = &riaf->addressFamily;
	if (af->size == 2 && af->buf[0] == 0 && af->buf[1] == 1)
		return AddrBlock2json(riaf, "IPv4", prefix4_to_json);
	if (af->size == 2 && af->buf[0] == 0 && af->buf[1] == 2)
		return AddrBlock2json(riaf, "IPv6", prefix6_to_json);

	return SEQUENCE_encode_json(td, sptr);
}

static asn_TYPE_operation_t asn_OP_ROAIPAddressFamily = {
	SEQUENCE_free,
	SEQUENCE_print,
	SEQUENCE_compare,
	SEQUENCE_decode_ber,
	SEQUENCE_encode_der,
	ROAIPAddressFamily_encode_json,
	SEQUENCE_encode_xer,
	NULL	/* Use generic outmost tag fetcher */
};

static int
memb_addressFamily_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	const OCTET_STRING_t *st = (const OCTET_STRING_t *)sptr;
	size_t size;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	size = st->size;
	
	if((size >= 2 && size <= 3)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static int
memb_addresses_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	size_t size;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	/* Determine the number of elements */
	size = _A_CSEQUENCE_FROM_VOID(sptr)->count;
	
	if((size >= 1)) {
		/* Perform validation of the inner elements */
		return SEQUENCE_OF_constraint(td, sptr, ctfailcb, app_key);
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_TYPE_member_t asn_MBR_addresses_3[] = {
	{ ATF_POINTER, 0, 0,
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_ROAIPAddress,
		NULL,
		{ NULL, NULL, NULL },
		NULL, NULL, /* No default value */
		""
		},
};
static const ber_tlv_tag_t asn_DEF_addresses_tags_3[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_SET_OF_specifics_t asn_SPC_addresses_specs_3 = {
	sizeof(struct ROAIPAddressFamily__addresses),
	offsetof(struct ROAIPAddressFamily__addresses, _asn_ctx),
	0,	/* XER encoding is XMLDelimitedItemList */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_addresses_3 = {
	"addresses",
	"addresses",
	&asn_OP_SEQUENCE_OF,
	asn_DEF_addresses_tags_3,
	sizeof(asn_DEF_addresses_tags_3)
		/sizeof(asn_DEF_addresses_tags_3[0]), /* 1 */
	asn_DEF_addresses_tags_3,	/* Same as above */
	sizeof(asn_DEF_addresses_tags_3)
		/sizeof(asn_DEF_addresses_tags_3[0]), /* 1 */
	{ NULL, NULL, SEQUENCE_OF_constraint },
	asn_MBR_addresses_3,
	1,	/* Single element */
	&asn_SPC_addresses_specs_3	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_ROAIPAddressFamily_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct ROAIPAddressFamily, addressFamily),
		(ASN_TAG_CLASS_UNIVERSAL | (4 << 2)),
		0,
		&asn_DEF_OCTET_STRING,
		NULL,
		{ NULL, NULL,  memb_addressFamily_constraint_1 },
		NULL, NULL, /* No default value */
		"addressFamily"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct ROAIPAddressFamily, addresses),
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_addresses_3,
		NULL,
		{ NULL, NULL,  memb_addresses_constraint_1 },
		NULL, NULL, /* No default value */
		"addresses"
		},
};
static const ber_tlv_tag_t asn_DEF_ROAIPAddressFamily_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_ROAIPAddressFamily_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (4 << 2)), 0, 0, 0 }, /* addressFamily */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 1, 0, 0 } /* addresses */
};
asn_SEQUENCE_specifics_t asn_SPC_ROAIPAddressFamily_specs_1 = {
	sizeof(struct ROAIPAddressFamily),
	offsetof(struct ROAIPAddressFamily, _asn_ctx),
	asn_MAP_ROAIPAddressFamily_tag2el_1,
	2,	/* Count of tags in the map */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_ROAIPAddressFamily = {
	"ROAIPAddressFamily",
	"ROAIPAddressFamily",
	&asn_OP_ROAIPAddressFamily,
	asn_DEF_ROAIPAddressFamily_tags_1,
	sizeof(asn_DEF_ROAIPAddressFamily_tags_1)
		/sizeof(asn_DEF_ROAIPAddressFamily_tags_1[0]), /* 1 */
	asn_DEF_ROAIPAddressFamily_tags_1,	/* Same as above */
	sizeof(asn_DEF_ROAIPAddressFamily_tags_1)
		/sizeof(asn_DEF_ROAIPAddressFamily_tags_1[0]), /* 1 */
	{ NULL, NULL, SEQUENCE_constraint },
	asn_MBR_ROAIPAddressFamily_1,
	2,	/* Elements count */
	&asn_SPC_ROAIPAddressFamily_specs_1	/* Additional specs */
};
