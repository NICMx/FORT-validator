#include "prometheus.h"

#include <stdio.h>
#include <string.h>
#include <microhttpd.h>

#include "config.h"
#include "log.h"
#include "stats.h"

#if MHD_VERSION > 0x00097000
#define MHD_RESULT enum MHD_Result
#else
#define MHD_RESULT int
#endif

#define OPENMETRICS_CT \
	"application/openmetrics-text; version=1.0.0; charset=utf-8"
#define PLAINTEXT_CT \
	"text/plain; version=0.0.4; charset=utf-8"

static struct MHD_Daemon *prometheus_daemon;

static MHD_RESULT
respond(struct MHD_Connection *conn, char *msg, unsigned int status)
{
	struct MHD_Response *response;
	MHD_RESULT result;

	response = MHD_create_response_from_buffer(strlen(msg), msg,
	    MHD_RESPMEM_PERSISTENT);
	result = MHD_queue_response(conn, status, response);
	MHD_destroy_response(response);

	return result;
}

static float
find_q(char const *accept, char const *ct)
{
	char const *value;
	char const *limit;
	char const *qstr;
	float q;

	value = strstr(accept, ct);
	if (!value)
		return 0;

	limit = strchr(value, ',');
	if (!limit)
		limit = value + strlen(value);

	qstr = strstr(value, ";q=");
	if (!qstr || qstr > limit)
		return 1;
	return (sscanf(qstr, ";q=%f", &q) == EOF) ? 0.5 /* Shrug */ : q;
}

static void
set_content_type(struct MHD_Connection *conn, struct MHD_Response *res)
{
	char const *accept;
	float om_q, txt_q;
	char const *ct;
	MHD_RESULT ret;

	accept = MHD_lookup_connection_value (conn, MHD_HEADER_KIND,
	    MHD_HTTP_HEADER_ACCEPT);
	if (accept != NULL) {
		om_q = find_q(accept, "application/openmetrics-text");
		txt_q = find_q(accept, "text/plain");

		if (om_q < 0.001f && txt_q < 0.001f)
			/* Likely a browser; these tend to prefer plaintext. */
			ct = PLAINTEXT_CT;
		else
			ct = (om_q >= txt_q) ? OPENMETRICS_CT : PLAINTEXT_CT;
	} else {
		ct = OPENMETRICS_CT;
	}

	ret = MHD_add_response_header(res, "Content-Type", ct);
	if (ret != MHD_YES) {
		pr_op_debug("Could not set Content-Type HTTP header.");
		/* Keep going; maybe the client won't care. */
	}
}

static MHD_RESULT
send_metrics(struct MHD_Connection *conn)
{
	char *stats;
	struct MHD_Response *res;
	MHD_RESULT ret;

	pr_op_debug("Handling Prometheus request...");

	stats = stats_export();

#if MHD_VERSION > 0x00096000
	res = MHD_create_response_from_buffer_with_free_callback(strlen(stats),
	    stats, free);
#else
	res = MHD_create_response_from_buffer(strlen(stats), stats,
	    MHD_RESPMEM_MUST_FREE);
#endif

	set_content_type(conn, res);

	ret = MHD_queue_response(conn, MHD_HTTP_OK, res);
	MHD_destroy_response(res);

	pr_op_debug("Prometheus request handled.");
	return ret;
}

static MHD_RESULT
handle_prometheus_req(void *cls, struct MHD_Connection *conn,
		const char *url, const char *method, const char *version,
		const char *upload, size_t *uplen, void **state)
{
	if (strcmp(method, "GET") != 0)
		return respond(conn, "Invalid HTTP Method\n", MHD_HTTP_BAD_REQUEST);

	if (strcmp(url, "/") == 0)
		return respond(conn, "OK\n", MHD_HTTP_OK);
	if (strcmp(url, "/metrics") == 0)
		return send_metrics(conn);

	return respond(conn, "Bad Request\n", MHD_HTTP_BAD_REQUEST);
}

int
prometheus_setup(void)
{
	unsigned int port;

	port = config_get_prometheus_port();
	if (config_get_mode() != SERVER || port == 0)
		return 0;

	pr_op_debug("Starting Prometheus server...");

	prometheus_daemon = MHD_start_daemon(
	    MHD_USE_THREAD_PER_CONNECTION,	/* flags */
	    port,				/* port */
	    NULL, NULL,				/* accept policy */
	    &handle_prometheus_req, NULL,	/* handler */
	    MHD_OPTION_END			/* options */
	);

	if (prometheus_daemon == NULL)
		return pr_op_err("Could not start Prometheus server; Unknown error");

	pr_op_debug("Prometheus server started.");
	return 0;
}

void
prometheus_teardown(void)
{
	MHD_stop_daemon(prometheus_daemon);
}
