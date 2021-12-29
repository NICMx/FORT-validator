#include "rrdp/notification.h"

#include <sys/types.h> /* stat() */
#include <sys/stat.h> /* stat() */
#include <unistd.h> /* stat() */

#include "file.h"
#include "http/http.h"
#include "xml/relax_ng.h"

static int
parse_notification_snapshot(xmlTextReaderPtr reader,
    struct rrdp_file_metadata *snapshot)
{
	int error;

	error = parse_simple_uri_attribute(reader, snapshot);
	if (error)
		return error;
	error = parse_hash_attribute(reader, true, snapshot);
	if (error)
		uri_refput(snapshot->uri);

	return error;
}

static int
parse_notification_delta(xmlTextReaderPtr reader,
    struct rrdp_notification_deltas *deltas)
{
	struct rrdp_notification_delta delta;
	int error;

	error = xml_parse_long(reader, "serial", &delta.serial);
	if (error)
		return error;
	error = parse_simple_uri_attribute(reader, &delta.meta);
	if (error)
		return error;
	error = parse_hash_attribute(reader, true, &delta.meta);
	if (error) {
		uri_refput(delta.meta.uri);
		return error;
	}

	error = rrdp_notification_deltas_add(deltas, &delta);
	if (error)
		rrdp_file_metadata_cleanup(&delta.meta);

	return error;
}

static int
xml_read_notification(xmlTextReaderPtr reader, void *arg)
{
	static const xmlChar *NOTIFICATION = BAD_CAST "notification";
	static const xmlChar *SNAPSHOT = BAD_CAST "snapshot";
	static const xmlChar *DELTA = BAD_CAST "delta";

	struct rrdp_notification *notification;
	xmlChar const *name;

	if (xmlTextReaderNodeType(reader) != XML_READER_TYPE_ELEMENT)
		return 0; /* Meh */

	notification = arg;
	name = xmlTextReaderConstLocalName(reader);

	if (xmlStrEqual(name, NOTIFICATION))
		return parse_header_tag(reader, &notification->session);
	if (xmlStrEqual(name, SNAPSHOT))
		return parse_notification_snapshot(reader,
		    &notification->snapshot);
	if (xmlStrEqual(name, DELTA))
		return parse_notification_delta(reader,
		    &notification->deltas_list);

	return pr_val_err("Unexpected '%s' element", name);
}

static int
swap_until_sorted(struct rrdp_notification_delta *deltas, unsigned int i,
    unsigned long min, unsigned long max)
{
	unsigned int target_slot;
	struct rrdp_notification_delta tmp;

	while (true) {
		if (deltas[i].serial < min || max < deltas[i].serial) {
			return pr_val_err("Deltas: Serial '%lu' is out of bounds. (min:%lu, max:%lu)",
			    deltas[i].serial, min, max);
		}

		target_slot = deltas[i].serial - min;
		if (i == target_slot)
			return 0;
		if (deltas[target_slot].serial == deltas[i].serial) {
			return pr_val_err("Deltas: Serial '%lu' is not unique.",
			    deltas[i].serial);
		}

		/* Simple swap */
		tmp = deltas[target_slot];
		deltas[target_slot] = deltas[i];
		deltas[i] = tmp;
	}
}

static int
deltas_head_sort(struct rrdp_notification_deltas *deltas,
    unsigned long max_serial)
{
	unsigned long min_serial;
	struct rrdp_notification_delta *cursor;
	array_index i;
	int error;

	if (max_serial + 1 < deltas->len)
		return pr_val_err("Deltas: Too many deltas (%zu) for serial %lu. (Negative serials not implemented.)",
		    deltas->len, max_serial);

	min_serial = max_serial + 1 - deltas->len;

	ARRAYLIST_FOREACH(deltas, cursor, i) {
		error = swap_until_sorted(deltas->array, i, min_serial,
		    max_serial);
		if (error)
			return error;
	}

	return 0;
}

static int
read_notification(struct rrdp_notification *notification)
{
	int error;

	error = relax_ng_parse(notification->uri, xml_read_notification,
	    notification);
	if (error)
		return error;

	return deltas_head_sort(&notification->deltas_list,
	    notification->session.serial);
}

/*
 * Download Update Notification file from @uri, and return its contents in
 * @old and @new. (@old is the already existing notification, @new is the
 * downloaded one.)
 *
 * On success, @old might not be populated, @new always will.
 *
 * Zero if the notification was successfully downloaded, nonzero otherwise.
 * (Note, ENOTCHANGED is not an error in this case.)
 */
int
rrdp_parse_notification(struct rrdp_notification *old,
    struct rrdp_notification *new)
{
	long ims;
	int error;

	ims = file_get_modification_time(uri_get_local(old->uri));

	if (ims != -1) /* Approx. "file exists and readable?" */ {
		if (read_notification(old) != 0)
			pr_val_warn("Old Update Notification file exists, but I can't read it. Ignoring.");
	}

	error = http_get(new->uri, ims);
	if (error)
		return error;

	return read_notification(new);
}
