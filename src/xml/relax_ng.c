#include "relax_ng.h"

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/relaxng.h>
#include <errno.h>
#include <stdlib.h>

#include "log.h"

#define LOG_MSG_LEN 512

static xmlRelaxNGPtr schema;
static xmlRelaxNGParserCtxtPtr rngparser;

#define VLOG_MSG(level)							\
	char log_msg[LOG_MSG_LEN];					\
	va_list args;							\
	va_start(args, msg);						\
	vsnprintf(log_msg, LOG_MSG_LEN, msg, args);			\
	va_end(args);							\
	pr_val_##level("%s", log_msg);

/*
 * Log callbacks for libxml errors
 */
static void
relax_ng_log_err(void *ctx, const char *msg, ...)
{
	VLOG_MSG(err)
}

static void
relax_ng_log_warn(void *ctx, const char *msg, ...)
{
	VLOG_MSG(warn)
}

/* Initialize global schema to parse RRDP files */
int
relax_ng_init(void)
{
	int error;

	xmlInitParser();

	rngparser = xmlRelaxNGNewMemParserCtxt(RRDP_V1_RNG, RRDP_V1_RNG_SIZE);
	if (rngparser == NULL) {
		error = pr_op_err("XML parser init error: xmlRelaxNGNewMemParserCtxt() returned NULL");
		goto cleanup_parser;
	}

	schema = xmlRelaxNGParse(rngparser);
	if (schema == NULL) {
		error = pr_op_err("XML parser init error: xmlRelaxNGParse() returned NULL");
		goto free_parser_ctx;
	}

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
	xmlRelaxNGValidCtxtPtr rngvalidctx;
	int read;
	int error;

	reader = xmlNewTextReaderFilename(path);
	if (reader == NULL)
		return pr_val_err("Couldn't get XML '%s' file.", path);

	error = xmlTextReaderRelaxNGSetSchema(reader, schema);
	if (error) {
		error = pr_val_err("Couldn't set Relax NG schema.");
		goto free_reader;
	}

	rngvalidctx = xmlRelaxNGNewValidCtxt(schema);
	if (rngvalidctx == NULL) {
		error = pr_val_err("xmlRelaxNGNewValidCtxt() returned NULL");
		goto free_reader;
	}

	xmlRelaxNGSetValidErrors(rngvalidctx, relax_ng_log_err,
	    relax_ng_log_warn, NULL);

	xmlRelaxNGSetParserErrors(rngvalidctx, relax_ng_log_err,
		    relax_ng_log_warn, NULL);

	error = xmlTextReaderRelaxNGValidateCtxt(reader, rngvalidctx, 1);
	if (error) {
		error = pr_val_err("Invalid XML document");
		goto free_valid_ctx;
	}

	while ((read = xmlTextReaderRead(reader)) == 1) {
		error = cb(reader, arg);
		if (error)
			goto free_valid_ctx;
	}

	if (read < 0) {
		error = pr_val_err("Error parsing XML document.");
		goto free_valid_ctx;
	}

	if (xmlTextReaderIsValid(reader) <= 0) {
		error = pr_val_err("XML document isn't valid.");
		goto free_valid_ctx;
	}

	xmlRelaxNGFreeValidCtxt(rngvalidctx);
	xmlFreeTextReader(reader);
	return 0;
free_valid_ctx:
	xmlRelaxNGFreeValidCtxt(rngvalidctx);
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
