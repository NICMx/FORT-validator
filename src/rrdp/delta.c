#include "rrdp/delta.h"

#include "common.h"
#include "log.h"
#include "thread_var.h"
#include "http/http.h"
#include "xml/relax_ng.h"
#include "rrdp/snapshot.h"

/* Context while reading a delta */
struct rdr_delta_ctx {
	/* Parent data to validate session ID */
	struct rrdp_notification *notification;
	/* Current serial loaded from update notification deltas list */
	unsigned long expected_serial;
};

static int
parse_withdraw_tag(xmlTextReaderPtr reader, struct rrdp_notification *notif,
    struct rrdp_file_metadata *meta)
{
	int error;

	error = parse_caged_uri_attribute(reader, notif, meta);
	if (error)
		return error;
	return parse_hash_attribute(reader, true, meta);
}

/*
 * This function will call 'xmlTextReaderRead' so there's no need to expect any
 * other type at the caller.
 */
static int
handle_withdraw_tag(xmlTextReaderPtr reader, struct rrdp_notification *notif)
{
	struct rrdp_file_metadata meta;
	int error;

	rrdp_file_metadata_init(&meta);

	error = parse_withdraw_tag(reader, notif, &meta);
	if (error)
		goto end;

	error = rrdp_file_metadata_validate_hash(&meta);
	if (error)
		goto end;

	error = delete_dir_recursive_bottom_up(uri_get_local(meta.uri));

end:	rrdp_file_metadata_cleanup(&meta);
	return error;
}

static int
xml_read_delta(xmlTextReaderPtr reader, void *arg)
{
	static const xmlChar *PUBLISH = BAD_CAST "publish";
	static const xmlChar *WITHDRAW = BAD_CAST "withdraw";
	static const xmlChar *DELTA = BAD_CAST "delta";

	struct rdr_delta_ctx *ctx;
	xmlChar const *name;
	struct rrdp_session expected;

	if (xmlTextReaderNodeType(reader) != XML_READER_TYPE_ELEMENT)
		return 0;

	ctx = arg;
	name = xmlTextReaderConstLocalName(reader);

	if (xmlStrEqual(name, PUBLISH))
		return handle_publish_tag(reader, ctx->notification);
	if (xmlStrEqual(name, WITHDRAW))
		return handle_withdraw_tag(reader, ctx->notification);
	if (xmlStrEqual(name, DELTA)) {
		expected.id = ctx->notification->session.id;
		expected.serial = ctx->expected_serial;
		return validate_header_tag(reader, &expected);
	}

	return pr_val_err("Unexpected '%s' element", name);
}

/* TODO (aaaa) Remember to delete snapshots and deltas at some point */
static int
process_delta(struct rrdp_notification_delta *deltas,
    struct rrdp_notification *notification)
{
	struct rpki_uri *uri;
	struct rdr_delta_ctx ctx;
	int error;

	uri = deltas->meta.uri;

	pr_val_debug("RRDP Delta '%s' {", uri_val_get_printable(uri));
	fnstack_push_uri(uri);

	error = http_get(uri, -1);
	if (error)
		goto pop;

	error = rrdp_file_metadata_validate_hash(&deltas->meta);
	if (error)
		goto pop;

	ctx.notification = notification;
	ctx.expected_serial = deltas->serial;
	error = relax_ng_parse(uri_get_local(uri), xml_read_delta, &ctx);

pop:	fnstack_pop();
	pr_val_debug("}");
	return error;
}

int
rrdp_process_deltas(struct rrdp_notification *old,
    struct rrdp_notification *new)
{
	unsigned long from;
	unsigned long to;
	size_t start;
	size_t d;

	if (new->deltas_list.len == 0) {
		pr_val_warn("There's no delta list to process.");
		goto snapshot;
	}

	from = old->session.serial;
	to = new->session.serial;
	pr_val_debug("Getting RRDP deltas from serial %lu to %lu.", from, to);
	start = new->deltas_list.len - (to - from);
	for (d = start; d < new->deltas_list.len; d++) {
		if (process_delta(&new->deltas_list.array[d], new) != 0)
			goto snapshot;
	}

	return 0;

snapshot:
	pr_val_debug("Delta update failed; trying snapshot.");
	return rrdp_parse_snapshot(new);
}
