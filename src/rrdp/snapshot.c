#include "rrdp/snapshot.h"

#define _XOPEN_SOURCE 500
#include <ftw.h>

#include "thread_var.h"
#include "http/http.h"
#include "xml/relax_ng.h"

static int
rm_file(const char *fpath, const struct stat *sb, int typeflag,
    struct FTW *ftwbuf)
{
	int error;

	error = remove(fpath);
	if (error) {
		pr_val_errno(errno, "Could not clean file or directory '%s'",
		    fpath);
	}

	return error;
}

/* Deletes (if any) all the old files from the RPP owned by @notif. */
static int
clear_caged_directory(struct rrdp_notification *notif)
{
	struct rpki_uri *cage;
	int error;

	error = uri_create_caged(NULL, notif, &cage);
	if (error)
		return error;

	pr_val_debug("Making sure '%s' is empty.", uri_get_local(cage));
	error = nftw(uri_get_local(cage), rm_file, 32, FTW_DEPTH | FTW_PHYS);

	uri_refput(cage);
	return error;
}

static int
xml_read_snapshot(xmlTextReaderPtr reader, void *arg)
{
	static xmlChar const *PUBLISH = BAD_CAST "publish";
	static xmlChar const *SNAPSHOT = BAD_CAST "snapshot";
	struct rrdp_notification *notif;
	xmlChar const *name;

	if (xmlTextReaderNodeType(reader) != XML_READER_TYPE_ELEMENT)
		return 0;

	notif = arg;
	name = xmlTextReaderConstLocalName(reader);

	if (xmlStrEqual(name, PUBLISH))
		return handle_publish_tag(reader, false, notif);
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

	error = clear_caged_directory(notification);
	if (error)
		goto pop;

	error = relax_ng_parse(uri_get_local(uri), xml_read_snapshot,
	    notification);

pop:	fnstack_pop();
	pr_val_debug("}");
	return error;
}
