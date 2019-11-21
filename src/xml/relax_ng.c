#include "relax_ng.h"

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/relaxng.h>
#include <errno.h>
#include <stdlib.h>

#include "log.h"

xmlRelaxNGPtr schema;
xmlRelaxNGValidCtxtPtr validctxt;
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

	validctxt = xmlRelaxNGNewValidCtxt(schema);
	if (validctxt == NULL) {
		error = pr_err("xmlRelaxNGNewValidCtxt() returned NULL");
		goto free_schema;
	}

	/*
	 * FIXME (now) Use xmlRelaxNGValidityErrorFunc and
	 * xmlRelaxNGValidityWarningFunc?
	 */
	return 0;
free_schema:
	xmlRelaxNGFree(schema);
free_parser_ctx:
	xmlRelaxNGFreeParserCtxt(rngparser);
cleanup_parser:
	xmlCleanupParser();
	return error;
}

/*
 * Validate file at @path against globally loaded schema. If the file is valid,
 * the result is set at @doc, returns error otherwise
 */
int
relax_ng_validate(const char *path, xmlDoc **doc)
{
	xmlDoc *tmp;
	int error;

	tmp = xmlParseFile(path);
	error = xmlRelaxNGValidateDoc(validctxt, tmp);
	if (error) {
		xmlFreeDoc(tmp);
		return -EINVAL;
	}

	*doc = tmp;
	return 0;
}

void
relax_ng_cleanup(void)
{
	xmlRelaxNGFreeValidCtxt(validctxt);
	xmlRelaxNGFree(schema);
	xmlRelaxNGFreeParserCtxt(rngparser);
	xmlCleanupParser();
}
