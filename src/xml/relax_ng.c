#include "relax_ng.h"

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/relaxng.h>
#include <errno.h>
#include <stdlib.h>

#include "log.h"

xmlRelaxNGPtr schema;
xmlRelaxNGParserCtxtPtr rngparser;

/* Initialize global schema to parse RRDP files */
int
relax_ng_init(void)
{
	int error;

	xmlInitParser();

	rngparser = xmlRelaxNGNewMemParserCtxt(RRDP_V1_RNG, RRDP_V1_RNG_SIZE);
	if (rngparser == NULL) {
		error = pr_err("xmlRelaxNGNewMemParserCtxt() returned NULL");
		goto cleanup_parser;
	}

	schema = xmlRelaxNGParse(rngparser);
	if (schema == NULL) {
		error = pr_err("xmlRelaxNGParse() returned NULL");
		goto free_parser_ctx;
	}

	/*
	 * FIXME (now) Use xmlRelaxNGValidityErrorFunc and
	 * xmlRelaxNGValidityWarningFunc?
	 */
	return 0;
free_parser_ctx:
	xmlRelaxNGFreeParserCtxt(rngparser);
cleanup_parser:
	xmlCleanupParser();
	return error;
}

/*
 * Validate file at @path against globally loaded schema. The file must be
 * parsed using @cb (will receive @arg as argument).
 */
int
relax_ng_parse(const char *path, xml_read_cb cb, void *arg)
{
	xmlTextReaderPtr reader;
	int read;
	int error;

	reader = xmlNewTextReaderFilename(path);
	if (reader == NULL)
		return pr_err("Couldn't get XML '%s' file.", path);

	error = xmlTextReaderRelaxNGSetSchema(reader, schema);
	if (error) {
		error = pr_err("Couldn't set Relax NG schema.");
		goto free_reader;
	}

	while ((read = xmlTextReaderRead(reader)) == 1) {
		error = cb(reader, arg);
		if (error)
			goto free_reader;
	}

	if (read < 0) {
		error = pr_err("Error parsing XML document.");
		goto free_reader;
	}

	if (xmlTextReaderIsValid(reader) <= 0) {
		error = pr_err("XML document isn't valid.");
		goto free_reader;
	}

	xmlFreeTextReader(reader);
	return 0;
free_reader:
	xmlFreeTextReader(reader);
	return error;
}

void
relax_ng_cleanup(void)
{
	xmlRelaxNGFree(schema);
	xmlRelaxNGFreeParserCtxt(rngparser);
	xmlCleanupParser();
}
