#include "xml/relax_ng.h"

#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

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

/* Signature changed at libxml2 commit 61034116d0a3c8b295c6137956adc3ae55720. */
#if LIBXML_VERSION >= 21200
#define XMLERROR_PARAMTYPE const xmlError *
#else
#define XMLERROR_PARAMTYPE xmlErrorPtr
#endif

static void
relax_ng_log_str_err(void *userData, XMLERROR_PARAMTYPE error)
{
	pr_val_err("%s (at line %d)", error->message, error->line);
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

	xmlRelaxNGSetParserErrors(rngparser, relax_ng_log_err,
	    relax_ng_log_warn, NULL);

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

	error = xmlTextReaderRelaxNGValidateCtxt(reader, rngvalidctx, 0);
	if (error) {
		error = pr_val_err("Invalid XML document");
		goto free_valid_ctx;
	}

	xmlTextReaderSetStructuredErrorHandler(reader, relax_ng_log_str_err,
	    NULL);

	while ((read = xmlTextReaderRead(reader)) == 1) {
		if (xmlTextReaderIsValid(reader) <= 0) {
			error = pr_val_err("XML document isn't valid.");
			goto free_valid_ctx;
		}

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
