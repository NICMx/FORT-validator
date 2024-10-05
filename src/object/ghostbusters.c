#include "object/ghostbusters.h"

#include <errno.h>

#include "log.h"
#include "object/signed_object.h"
#include "object/vcard.h"
#include "thread_var.h"

static int
handle_vcard(struct signed_object *sobj)
{
	return handle_ghostbusters_vcard(
		sobj->sdata->encapContentInfo.eContent
	);
}

int
ghostbusters_traverse(struct cache_mapping *map,
    struct rpki_certificate *parent)
{
	static OID oid = OID_GHOSTBUSTERS;
	struct oid_arcs arcs = OID2ARCS("ghostbusters", oid);
	struct signed_object sobj;
	struct rpki_certificate ee;
	int error;

	/* Prepare */
	fnstack_push_map(map);

	/* Decode */
	error = signed_object_decode(&sobj, map->path);
	if (error)
		goto end1;

	/* Prepare validation arguments */
	rpki_certificate_init_ee(&ee, parent, true);

	/* Validate everything */
	error = signed_object_validate(&sobj, &arcs, &ee);
	if (error)
		goto end3;
	error = handle_vcard(&sobj);
	if (error)
		goto end3;
	error = refs_validate_ee(&ee.sias, parent->rpp.crl.map->url, map->url);

end3:	rpki_certificate_cleanup(&ee);
	signed_object_cleanup(&sobj);
end1:	fnstack_pop();
	return error;
}
