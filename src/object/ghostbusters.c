#include "object/ghostbusters.h"

#include <errno.h>

#include "log.h"
#include "object/signed_object.h"
#include "object/vcard.h"
#include "thread_var.h"

static int
handle_vcard(struct signed_object *so)
{
	return handle_ghostbusters_vcard(
		so->sdata->encapContentInfo.eContent
	);
}

int
ghostbusters_traverse(struct cache_mapping *map,
    struct rpki_certificate *parent)
{
	static OID oid = OID_GHOSTBUSTERS;
	struct oid_arcs arcs = OID2ARCS("ghostbusters", oid);
	struct signed_object so;
	struct rpki_certificate ee;
	int error;

	/* Prepare */
	fnstack_push_map(map);

	/* Decode */
	error = signed_object_decode(&so, map);
	if (error)
		goto end1;

	/* Prepare validation arguments */
	cer_init_ee(&ee, parent, true);

	/* Validate everything */
	error = signed_object_validate(&so, &ee, &arcs);
	if (error)
		goto end3;
	error = handle_vcard(&so);

end3:	cer_cleanup(&ee);
	signed_object_cleanup(&so);
end1:	fnstack_pop();
	return error;
}
