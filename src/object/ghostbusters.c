#include "object/ghostbusters.h"

#include "log.h"
#include "thread_var.h"
#include "asn1/oid.h"
#include "object/signed_object.h"
#include "vcard.h"

static int
handle_vcard(struct signed_object *sobj)
{
	return handle_ghostbusters_vcard(
		sobj->sdata.decoded->encapContentInfo.eContent
	);
}

int
ghostbusters_traverse(struct rpki_uri *uri, struct rpp *pp)
{
	static OID oid = OID_GHOSTBUSTERS;
	struct oid_arcs arcs = OID2ARCS("ghostbusters", oid);
	struct signed_object sobj;
	struct signed_object_args sobj_args;
	STACK_OF(X509_CRL) *crl;
	int error;

	/* Prepare */
	pr_val_debug("Ghostbusters '%s' {", uri_val_get_printable(uri));
	fnstack_push_uri(uri);

	/* Decode */
	error = signed_object_decode(&sobj, uri);
	if (error)
		goto revert_log;

	/* Prepare validation arguments */
	error = rpp_crl(pp, &crl);
	if (error)
		goto revert_sobj;
	signed_object_args_init(&sobj_args, uri, crl, true);

	/* Validate everything */
	error = signed_object_validate(&sobj, &arcs, &sobj_args);
	if (error)
		goto revert_args;
	error = handle_vcard(&sobj);
	if (error)
		goto revert_args;
	error = refs_validate_ee(&sobj_args.refs, pp, sobj_args.uri);

revert_args:
	signed_object_args_cleanup(&sobj_args);
revert_sobj:
	signed_object_cleanup(&sobj);
revert_log:
	pr_val_debug("}");
	fnstack_pop();
	return error;
}
