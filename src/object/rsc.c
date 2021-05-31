#include "object/rsc.h"

#include "algorithm.h"
#include "log.h"
#include "thread_var.h"
#include "asn1/oid.h"
#include "asn1/decode.h"
#include "asn1/asn1c/RpkiSignedChecklist.h"
#include "object/signed_object.h"

/* Returns @sobj's EE certificate. */
static int
get_certificate(struct signed_object *sobj, X509 **result)
{
	struct SignedData *decoded_object;
	ANY_t *encoded_certificate;
	X509 *decoded_certificate;
	const unsigned char *tmp;

	*result = NULL; /* Warning shutupper */
	decoded_object = sobj->sdata.decoded;

	if (decoded_object->certificates == NULL)
		return pr_val_err("The SignedData does not contain certificates.");
	if (decoded_object->certificates->list.count != 1) {
		return pr_val_err("The SignedData contains %d certificates, one expected.",
		    decoded_object->certificates->list.count);
	}

	encoded_certificate = decoded_object->certificates->list.array[0];

	/*
	 * "If the call is successful *in is incremented to the byte following
	 * the parsed data."
	 * (https://www.openssl.org/docs/man1.0.2/crypto/d2i_X509_fp.html)
	 * We definitely don't want @any->buf to be modified, so use a dummy
	 * pointer.
	 */
	tmp = (const unsigned char *) encoded_certificate->buf;

	decoded_certificate = d2i_X509(NULL, &tmp, encoded_certificate->size);
	if (decoded_certificate == NULL)
		return val_crypto_err("Signed object's 'certificate' element does not decode into a Certificate");

	*result = decoded_certificate;
	return 0;
}

/* "Find (and return) the Authority Information Access extension" */
static int
find_aia(STACK_OF(X509_EXTENSION) const *extensions,
    AUTHORITY_INFO_ACCESS **result)
{
	int e;
	X509_EXTENSION *ext;
	int nid;
	AUTHORITY_INFO_ACCESS *aia;

	for (e = 0; e < sk_X509_EXTENSION_num(extensions); e++) {
		ext = sk_X509_EXTENSION_value(extensions, e);
		nid = OBJ_obj2nid(X509_EXTENSION_get_object(ext));
		if (nid == NID_info_access) {
			aia = X509V3_EXT_d2i(ext);
			if (aia == NULL)
				return pr_val_err("Embedded EE certificate's Authority Information Access extension seems to be malformed.");
			*result = aia;
			return 0;
		}
	}

	return pr_val_err("Embedded EE certificate appears to have no Authority Information Access extension.");
}

/* "Store Acess Descriptors" (in the validation state) */
static int
store_ads(AUTHORITY_INFO_ACCESS *aia)
{
	struct validation *state;
	unsigned int ad;

	struct rpki_uri **rsc_uris;
	unsigned int uri;

	int error;

	rsc_uris = calloc(sk_ACCESS_DESCRIPTION_num(aia),
	    sizeof(struct rpki_uri *));
	if (rsc_uris == NULL)
		return pr_enomem();
	uri = 0;

	for (ad = 0; ad < sk_ACCESS_DESCRIPTION_num(aia); ad++) {
		error = uri_create_ad(&rsc_uris[uri],
		    sk_ACCESS_DESCRIPTION_value(aia, ad),
		    URI_VALID_RSYNC | URI_VALID_HTTPS);
		if (error == ENOTSUPPORTED)
			continue; /* Unknown; whatever. */
		if (error)
			goto revert;

		pr_val_info("Found AIA: %s\n",
		    uri_val_get_printable(rsc_uris[uri]));
		uri++;
	}

	state = state_retrieve();
	if (!state) {
		error = -EINVAL;
		goto revert;
	}

	/* TODO (RSC) this is not being freed. Probably not important. */
	validation_set_rsc_uris(state, rsc_uris, uri);
	return 0;

revert:
	for (ad = 0; ad < sk_ACCESS_DESCRIPTION_num(aia); ad++)
		if (rsc_uris[uri] != NULL)
			uri_refput(rsc_uris[uri]);
	free(rsc_uris);
	return error;
}

int
rsc_store_aias(void)
{
	char const *rsc_uri;
	struct signed_object sobj;
	X509 *certificate;
	AUTHORITY_INFO_ACCESS *aia;
	int error;

	rsc_uri = config_get_rsc();

	/* Prepare */
	pr_val_debug("Signed Checklist '%s' {", rsc_uri);
	fnstack_push(rsc_uri);

	/* Decode */
	error = signed_object_decode(&sobj, rsc_uri);
	if (error)
		goto revert_log;

	error = get_certificate(&sobj, &certificate);
	if (error)
		goto revert_decode;

	error = find_aia(X509_get0_extensions(certificate), &aia);
	if (error)
		goto revert_certificate;

	error = store_ads(aia);

	AUTHORITY_INFO_ACCESS_free(aia);

revert_certificate:
	X509_free(certificate);
revert_decode:
	signed_object_cleanup(&sobj);
revert_log:
	pr_val_debug("}");
	fnstack_pop();
	return error;
}

static int
decode_checklist(struct signed_object *sobj,
    struct RpkiSignedChecklist **result)
{
	return asn1_decode_octet_string(
		sobj->sdata.decoded->encapContentInfo.eContent,
		&asn_DEF_RpkiSignedChecklist,
		(void **) result,
		true,
		false
	);
}

static bool
is_portable_character(uint8_t chara)
{
	if (0x20 <= chara && chara <= 0x7E)
		return true;
	if (0x07 <= chara && chara <= 0x0D)
		return true;
	return chara == 0;
}

static int
validate_filename(IA5String_t *filename)
{
	size_t i;

	if (filename == NULL)
		return 0;
	if (filename->buf == NULL)
		return pr_val_err("fileName contains a NULL buffer.");

	for (i = 0; i < filename->size; i++)
		if (!is_portable_character(filename->buf[i]))
			return pr_val_err("fileName contains invalid character %u.", filename->buf[i]);

	return 0;
}

static int
print_checklist(struct RpkiSignedChecklist *rsc)
{
	struct FileNameAndHash *fnah;
	int error;
	int i;

	if (rsc->checkList.list.array == NULL)
		return pr_val_err("RSC's checklist is a NULL array.");

	for (i = 0; i < rsc->checkList.list.count; i++) {
		fnah = rsc->checkList.list.array[i];
		error = validate_filename(fnah->fileName);
		if (error)
			return error;
		if (asn_fprint(stdout, &asn_DEF_FileNameAndHash, fnah) != 0) {
			error = errno;
			return pr_val_errno(error,
			    "Error printing FileNameAndHash");
		}
	}

	return 0;
}

static int
validate_resources_asID(struct resources *parent, struct AsList *asid)
{
	return 0;
	/* TODO (RSC) ? */

//	struct ASIdOrRange *aor;
//	int a;
//
//	if (asid == NULL)
//		return 0;
//	if (asid->list.array == NULL)
//		return pr_val_err("rsc->resources.asID contains a NULL array.");
//
//	for (a = 0; a < asid->list.count; a++) {
//		aor = asid->list.array[a];
//
//		switch (aor->choice) {
//		case ASIdOrRange_PR_NOTHING:
//			return pr_val_err("ASIdOrRange is neither id nor range.");
//		case ASIdOrRange_PR_id:
//			// aor->choice.id;
//			break;
//		case ASIdOrRange_PR_range:
//
//		}
//	}
}

static int
validate_prefix4(struct resources *parent, struct IPAddressFamilyItem *iafi)
{
	struct ipv4_prefix prefix;
	int error;

	error = prefix4_decode(&iafi->iPAddressOrRange.choice.addressPrefix,
	    &prefix);
	if (error)
		return error;

	if (!resources_contains_ipv4(parent, &prefix)) {
		return pr_val_err("RSC is not allowed to contain %s/%u.",
		    v4addr2str(&prefix.addr), prefix.len);
	}

	pr_val_debug("%s/%u: Approved.", v4addr2str(&prefix.addr), prefix.len);
	return 0;
}

static int
validate_prefix6(struct resources *parent, struct IPAddressFamilyItem *iafi)
{
	struct ipv6_prefix prefix;
	int error;

	error = prefix6_decode(&iafi->iPAddressOrRange.choice.addressPrefix,
	    &prefix);
	if (error)
		return error;

	if (!resources_contains_ipv6(parent, &prefix)) {
		return pr_val_err("RSC is not allowed to contain %s/%u.",
		    v6addr2str(&prefix.addr), prefix.len);
	}

	pr_val_debug("%s/%u: Approved.", v6addr2str(&prefix.addr), prefix.len);
	return 0;
}

static int
validate_range4(struct resources *parent, struct IPAddressFamilyItem *iafi)
{
	struct ipv4_range range;
	int error;

	error = range4_decode(&iafi->iPAddressOrRange.choice.addressRange,
	    &range);
	if (error)
		return error;

	if (!resources_contains_range4(parent, &range)) {
		return pr_val_err("RSC is not allowed to contain %s-%s.",
		    v4addr2str(&range.min), v4addr2str2(&range.max));
	}

	pr_val_debug("%s-%s: Approved.", v4addr2str(&range.min),
	    v4addr2str2(&range.max));
	return 0;
}

static int
validate_range6(struct resources *parent, struct IPAddressFamilyItem *iafi)
{
	struct ipv6_range range;
	int error;

	error = range6_decode(&iafi->iPAddressOrRange.choice.addressRange,
	    &range);
	if (error)
		return error;

	if (!resources_contains_range6(parent, &range)) {
		return pr_val_err("RSC is not allowed to contain %s-%s.",
		    v6addr2str(&range.min), v6addr2str2(&range.max));
	}

	pr_val_debug("%s-%s: Approved.", v6addr2str(&range.min),
	    v6addr2str2(&range.max));
	return 0;
}

static int
validate_resources_ipAddrBlocks(struct resources *parent, struct IPList *ips)
{
	struct IPAddressFamilyItem *iafi;
	int error;
	int i;

	if (ips == NULL)
		return 0;
	if (ips->list.array == NULL)
		return pr_val_err("rsc->resources.ipAddrBlocks contains a NULL array.");

	error = 0;
	for (i = 0; i < ips->list.count; i++) {
		iafi = ips->list.array[i];

		if (iafi == NULL)
			return pr_val_err("IPAddressFamilyItem array element is NULL.");

		if (iafi->addressFamily.size != 2)
			goto family_error;
		if (iafi->addressFamily.buf[0] != 0)
			goto family_error;

		/* TODO (RSC) what about resources->policy? */
		switch (iafi->addressFamily.buf[1]) {
		case 1:
			switch (iafi->iPAddressOrRange.present) {
			case IPAddressOrRange_PR_addressPrefix:
				error = validate_prefix4(parent, iafi);
				break;
			case IPAddressOrRange_PR_addressRange:
				error = validate_range4(parent, iafi);
				break;
			case IPAddressOrRange_PR_NOTHING:
				goto pr_nothing;
			}
			break;
		case 2:
			switch (iafi->iPAddressOrRange.present) {
			case IPAddressOrRange_PR_addressPrefix:
				error = validate_prefix6(parent, iafi);
				break;
			case IPAddressOrRange_PR_addressRange:
				error = validate_range6(parent, iafi);
				break;
			case IPAddressOrRange_PR_NOTHING:
				goto pr_nothing;
			}
			break;
		default:
			goto family_error;
		}
	}

	return error;

family_error:
	return pr_val_err("IPAddressFamilyItem's IP family is not v4 or v6.");
pr_nothing:
	return pr_val_err("IPAddressFamilyItem has neither a prefix nor a range.");
}

static int
__handle_checklist(struct RpkiSignedChecklist *rsc, struct resources *parent)
{
	unsigned long version;
	int error;

	pr_val_debug("eContent {");
	if (rsc->version != NULL) {
		error = asn_INTEGER2ulong(rsc->version, &version);
		if (error) {
			if (errno)
				pr_val_errno(errno, "Error casting RSC's version");
			error = pr_val_err("The RSC's version isn't a valid long");
			goto end;
		}
		/* draft#section-4.1 */
		if (version != 0) {
			error = pr_val_err("RSC's version (%lu) is nonzero.",
			    version);
			goto end;
		}
	}

	/* draft#section-4.2 */
	error = validate_resources_asID(parent, rsc->resources.asID);
	if (error)
		goto end;
	error = validate_resources_ipAddrBlocks(parent,
	    rsc->resources.ipAddrBlocks);
	if (error)
		goto end;

	/* draft#section-4.3 */
	error = validate_cms_hashing_algorithm(&rsc->digestAlgorithm,
	    "digestAlgorithm");
	if (error)
		return error;

	/* draft#section-4.4 */
	error = print_checklist(rsc);
	/* Fall through */

end:
	pr_val_debug("}");
	return error;
}

void
rsc_traverse(struct rpp *pp)
{
	static OID oid = OID_SIGNED_CHECKLIST;
	struct oid_arcs arcs = OID2ARCS("signed checklist", oid);
	char const *rsc_uri;
	struct signed_object sobj;
	struct signed_object_args sobj_args;
	struct RpkiSignedChecklist *checklist;
	STACK_OF(X509_CRL) *crl;
	int error;

	rsc_uri = config_get_rsc();

	/* Prepare */
	pr_val_debug("Signed Checklist '%s' {", rsc_uri);
	fnstack_push(rsc_uri);

	/* Decode */
	error = signed_object_decode(&sobj, rsc_uri);
	if (error)
		goto revert_log;
	error = decode_checklist(&sobj, &checklist);
	if (error)
		goto revert_sobj;

	/* Prepare validation arguments */
	error = rpp_crl(pp, &crl);
	if (error)
		goto revert_checklist;
	error = signed_object_args_init(&sobj_args, crl, false);
	if (error)
		goto revert_checklist;
	sobj_args.cert_type = EE_CHECKLIST;

	/* Validate everything */
	error = signed_object_validate(&sobj, &arcs, &sobj_args);
	if (error)
		goto revert_args;
	error = __handle_checklist(checklist, sobj_args.res);
	if (error)
		goto revert_args;
	/*
	 * TODO (RSC) why is this validated last? The hashes were already
	 * printed.
	 */
	error = refs_validate_ee_checklist(&sobj_args.refs, pp);

revert_args:
	signed_object_args_cleanup(&sobj_args);
revert_checklist:
	ASN_STRUCT_FREE(asn_DEF_RpkiSignedChecklist, checklist);
revert_sobj:
	signed_object_cleanup(&sobj);
revert_log:
	fnstack_pop();
	pr_val_debug("}");
}
