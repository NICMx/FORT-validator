#include "rrdp_parser.h"

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <errno.h>
#include <stdlib.h>

#include "http/http.h"
#include "xml/relax_ng.h"
#include "log.h"

/* XML Elements */
#define RRDP_ELEM_NOTIFICATION	"notification"
#define RRDP_ELEM_SNAPSHOT	"snapshot"
#define RRDP_ELEM_DELTA		"delta"

/* XML Attributes */
#define RRDP_ATTR_VERSION	"version"
#define RRDP_ATTR_SESSION_ID	"session_id"
#define RRDP_ATTR_SERIAL	"serial"
#define RRDP_ATTR_URI		"uri"
#define RRDP_ATTR_HASH		"hash"


static int
get_root_element(xmlDoc *doc, xmlNode **result)
{
	xmlNode *tmp;

	tmp = xmlDocGetRootElement(doc);
	if (tmp == NULL)
		return pr_err("XML file doesn't have a root element");

	*result = tmp;
	return 0;
}

static int
parse_string(xmlNode *root, char const *attr, char **result)
{
	xmlChar *xml_value;
	char *tmp;

	xml_value = xmlGetProp(root, BAD_CAST attr);
	if (xml_value == NULL)
		return pr_err("RRDP file: Couldn't find xml attribute %s",
		    attr);

	tmp = malloc(xmlStrlen(xml_value) + 1);
	if (tmp == NULL) {
		xmlFree(xml_value);
		return pr_enomem();
	}

	memcpy(tmp, xml_value, xmlStrlen(xml_value));
	tmp[xmlStrlen(xml_value)] = '\0';
	xmlFree(xml_value);

	*result = tmp;
	return 0;
}

static int
parse_long(xmlNode *root, char const *attr, unsigned long *result)
{
	xmlChar *xml_value;
	unsigned long tmp;

	xml_value = xmlGetProp(root, BAD_CAST attr);
	if (xml_value == NULL)
		return pr_err("RRDP file: Couldn't find xml attribute %s",
		    attr);

	errno = 0;
	tmp = strtoul((char *) xml_value, NULL, 10);
	if (errno) {
		xmlFree(xml_value);
		pr_errno(errno, "RRDP file: Invalid long value '%s'",
		   xml_value);
		return -EINVAL;
	}
	xmlFree(xml_value);

	(*result) = tmp;
	return 0;
}

static int
parse_hex_string(xmlNode *root, char const *attr, unsigned char **result,
    size_t *result_len)
{
	xmlChar *xml_value;
	unsigned char *tmp, *ptr;
	char *xml_cur;
	char buf[2];
	size_t tmp_len;

	xml_value = xmlGetProp(root, BAD_CAST attr);
	if (xml_value == NULL)
		return pr_err("RRDP file: Couldn't find xml attribute %s",
		    attr);

	/* The rest of the checks are done at the schema */
	if (xmlStrlen(xml_value) % 2 != 0) {
		xmlFree(xml_value);
		return pr_err("RRDP file: Attribute %s isn't a valid hash",
		    attr);
	}

	tmp_len = xmlStrlen(xml_value) / 2;
	tmp = malloc(tmp_len);
	if (tmp == NULL) {
		xmlFree(xml_value);
		return pr_enomem();
	}
	memset(tmp, 0, tmp_len);

	ptr = tmp;
	xml_cur = (char *) xml_value;
	while (ptr - tmp < tmp_len) {
		memcpy(buf, xml_cur, 2);
		*ptr = strtol(buf, NULL, 16);
		xml_cur+=2;
		ptr++;
	}
	xmlFree(xml_value);

	*result = tmp;
	(*result_len) = tmp_len;
	return 0;
}

/* @gdata elements are allocated */
static int
parse_global_data(xmlNode *root, struct global_data *gdata)
{
	int error;

	error = parse_string(root, RRDP_ATTR_SESSION_ID, &gdata->session_id);
	if (error)
		return error;

	error = parse_long(root, RRDP_ATTR_SERIAL, &gdata->serial);
	if (error) {
		free(gdata->session_id);
		return error;
	}

	return 0;
}

/* @data elements are allocated */
static int
parse_doc_data(xmlNode *root, bool parse_hash, struct doc_data *data)
{
	int error;

	error = parse_string(root, RRDP_ATTR_URI, &data->uri);
	if (error)
		return error;

	if (!parse_hash)
		return 0;

	error = parse_hex_string(root, RRDP_ATTR_HASH, &data->hash,
	    &data->hash_len);
	if (error) {
		free(data->uri);
		return error;
	}

	return 0;
}

static int
parse_notification_deltas(xmlNode *root, struct deltas_head *deltas)
{
	struct delta_head delta;
	int error;

	error = parse_long(root, RRDP_ATTR_SERIAL, &delta.serial);
	if (error)
		return error;

	error = parse_doc_data(root, true, &delta.doc_data);
	if (error)
		return error;

	error = update_notification_deltas_add(deltas, delta.serial,
	    &delta.doc_data.uri, &delta.doc_data.hash, delta.doc_data.hash_len);
	if (error) {
		doc_data_cleanup(&delta.doc_data);
		return error;
	}

	return 0;
}

static int
parse_notification_data(xmlNode *root, struct update_notification *file)
{
	xmlNode *cur_node;
	int error;

	for (cur_node = root->children; cur_node; cur_node = cur_node->next) {
		if (xmlStrEqual(cur_node->name, BAD_CAST RRDP_ELEM_DELTA))
			error = parse_notification_deltas(cur_node,
			    &file->deltas_list);
		else if (xmlStrEqual(cur_node->name,
		    BAD_CAST RRDP_ELEM_SNAPSHOT))
			error = parse_doc_data(cur_node, true, &file->snapshot);

		if (error)
			return error;
	}

	return 0;
}

static int
parse_notification(const char *path,
    struct update_notification **file)
{
	xmlDoc *doc;
	xmlNode *root;
	struct update_notification *tmp;
	int error;

	root = NULL;

	error = relax_ng_validate(path, &doc);
	if (error)
		return error;

	error = update_notification_create(&tmp);
	if (error)
		goto release_doc;

	error = get_root_element(doc, &root);
	if (error)
		return error;

	/* FIXME (now) validate version, namespace, etc. */
	error = parse_global_data(root, &tmp->gdata);
	if (error)
		goto release_update;

	error = parse_notification_data(root, tmp);
	if (error)
		goto release_update;

	*file = tmp;
	/* Error 0 is ok */
	goto release_doc;

release_update:
	update_notification_destroy(tmp);
release_doc:
	xmlFreeDoc(doc);
	return error;
}

static size_t
write_local(unsigned char *content, size_t size, size_t nmemb, void *arg)
{
	FILE *fd = arg;
	size_t read = size * nmemb;
	size_t written;

	written = fwrite(content, size, nmemb, fd);
	if (written != nmemb)
		return -EINVAL;

	return read;
}

/* FIXME (now) Receive an **update_notification? */
int
rrdp_parse_notification(struct rpki_uri *uri)
{
	struct update_notification *tmp;
	int error;

	if (uri == NULL || uri_is_rsync(uri))
		pr_crit("Wrong call, trying to parse a non HTTPS URI");

	error = http_download_file(uri, write_local);
	if (error)
		return error;

	error = parse_notification(uri_get_local(uri), &tmp);
	if (error)
		return error;

	/* FIXME (now) This is just a test, must be removed */
	update_notification_destroy(tmp);

	/* result = tmp; */
	return 0;
}
