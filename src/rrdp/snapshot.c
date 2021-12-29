#include "rrdp/snapshot.h"

#include "thread_var.h"
#include "http/http.h"
#include "xml/relax_ng.h"

static int
xml_read_snapshot(xmlTextReaderPtr reader, void *arg)
{
	static xmlChar const *PUBLISH = BAD_CAST "publish";
	static xmlChar const *SNAPSHOT = BAD_CAST "snapshot";
	struct rrdp_notification *notif;
	xmlChar const *name;

	/* TODO (aaaa) probably make sure the directory is empty before exploding */

	if (xmlTextReaderNodeType(reader) != XML_READER_TYPE_ELEMENT)
		return 0;

	notif = arg;
	name = xmlTextReaderConstLocalName(reader);

	if (xmlStrEqual(name, PUBLISH))
		return handle_publish_tag(reader, notif);
	if (xmlStrEqual(name, SNAPSHOT))
		return validate_header_tag(reader, &notif->session);

	return pr_val_err("Unexpected tag: '%s'", name);
}

int
rrdp_parse_snapshot(struct rrdp_notification *notification)
{
	struct rpki_uri *uri;
	int error;

	uri = notification->snapshot.uri;

	pr_val_debug("RRDP Snapshot '%s' {", uri_val_get_printable(uri));
	fnstack_push_uri(uri);

	error = http_get(uri, -1);
	if (error)
		goto pop;

	error = rrdp_file_metadata_validate_hash(&notification->snapshot);
	if (error)
		goto pop;

	error = relax_ng_parse(uri, xml_read_snapshot, notification);

pop:	fnstack_pop();
	pr_val_debug("}");
	return error;
}
