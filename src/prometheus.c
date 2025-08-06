#include "prometheus.h"

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

#define CONTENT_TYPE "application/openmetrics-text; version=1.0.0; charset=utf-8"

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

static MHD_RESULT
send_metrics(struct MHD_Connection *conn)
{
	char *stats;
	struct MHD_Response *res;
	MHD_RESULT ret;

	pr_op_debug("Handling Prometheus request...");

	stats = stats_export();
	res = MHD_create_response_from_buffer_with_free_callback(strlen(stats),
	    stats, free);

	ret = MHD_add_response_header(res, "Content-Type", CONTENT_TYPE);
	if (ret != MHD_YES) {
		pr_op_debug("Could not set Content-Type HTTP header.");
		/* Keep going; maybe the client won't care. */
	}

	ret = MHD_queue_response(conn, MHD_HTTP_OK, res);
	MHD_destroy_response(res);

	pr_op_debug("Prometheus request handled.");
	return MHD_YES;
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
