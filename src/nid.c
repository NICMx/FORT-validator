#include "nid.h"

#include <errno.h>
#include <openssl/objects.h>

#include "log.h"

static int rpki_manifest_nid;
static int signed_object_nid;
static int rpki_notify_nid;
static int cert_policy_rpki_nid;
static int cert_policy_rpki_v2_nid;
static int ip_addr_blocks_v2_nid;
static int autonomous_sys_ids_v2_nid;
static int bgpsec_router_nid;

static int
register_oid(const char *oid, const char *sn, const char *ln)
{
	int nid;

	/* Note: Object has to be registered for OBJ_txt2nid to work. */
	nid = OBJ_txt2nid(oid);
	if (nid == NID_undef) {
		/* Note: Implicit object registration happens in OBJ_create. */
		nid = OBJ_create(oid, sn, ln);
		if (nid == 0)
			return op_crypto_err("Unable to register the %s NID.", sn);
		pr_op_debug("%s registered. Its nid is %d.", sn, nid);

	} else {
		pr_op_debug("%s retrieved. Its nid is %d.", sn, nid);
	}

	return nid;
}

/**
 * Registers the RPKI-specific OIDs in the SSL library.
 * Modern libcrypto implementations should have them, but older
 * versions might not.
 */
int
nid_init(void)
{
	rpki_manifest_nid = register_oid("1.3.6.1.5.5.7.48.10",
	    "rpkiManifest",
	    "RPKI Manifest (RFC 6487)");
	if (rpki_manifest_nid == 0)
		return -EINVAL;

	signed_object_nid = register_oid("1.3.6.1.5.5.7.48.11",
	    "signedObject",
	    "RPKI Signed Object (RFC 6487)");
	if (signed_object_nid == 0)
		return -EINVAL;

	rpki_notify_nid = register_oid("1.3.6.1.5.5.7.48.13",
	    "rpkiNotify",
	    "RPKI Update Notification File (RFC 8182)");
	if (rpki_notify_nid == 0)
		return -EINVAL;

	cert_policy_rpki_nid = register_oid("1.3.6.1.5.5.7.14.2",
	    "id-cp-ipAddr-asNumber (RFC 6484)",
	    "Certificate Policy (CP) for the Resource PKI (RPKI)");
	if (cert_policy_rpki_nid == 0)
		return -EINVAL;

	cert_policy_rpki_v2_nid = register_oid("1.3.6.1.5.5.7.14.3",
	    "id-cp-ipAddr-asNumber-v2 (RFC 8360)",
	    "Certificate Policy for Use with Validation Reconsidered in the RPKI");
	if (cert_policy_rpki_v2_nid == 0)
		return -EINVAL;

	ip_addr_blocks_v2_nid = register_oid("1.3.6.1.5.5.7.1.28",
	    "id-pe-ipAddrBlocks-v2",
	    "Amended IP Resources (RFC 8360)");
	if (ip_addr_blocks_v2_nid == 0)
		return -EINVAL;

	autonomous_sys_ids_v2_nid = register_oid("1.3.6.1.5.5.7.1.29",
	    "id-pe-autonomousSysIds-v2",
	    "Amended AS Resources (RFC 8360)");
	if (autonomous_sys_ids_v2_nid == 0)
		return -EINVAL;

	bgpsec_router_nid = register_oid("1.3.6.1.5.5.7.3.30",
	    "id-kp-bgpsec-router",
	    "BGPsec Extended Key Usage (RFC 8209)");
	if (bgpsec_router_nid == 0)
		return -EINVAL;

	return 0;
}

void
nid_destroy(void)
{
	OBJ_cleanup();
}

int nid_rpkiManifest(void)
{
	return rpki_manifest_nid;
}

int nid_signedObject(void)
{
	return signed_object_nid;
}

int nid_rpkiNotify(void)
{
	return rpki_notify_nid;
}

int nid_certPolicyRpki(void)
{
	return cert_policy_rpki_nid;
}

int nid_certPolicyRpkiV2(void)
{
	return cert_policy_rpki_v2_nid;
}

int nid_ipAddrBlocksv2(void)
{
	return ip_addr_blocks_v2_nid;
}

int nid_autonomousSysIdsv2(void)
{
	return autonomous_sys_ids_v2_nid;
}

int nid_bgpsecRouter(void)
{
	return bgpsec_router_nid;
}
