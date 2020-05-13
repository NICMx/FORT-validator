#include "http.h"

#include <curl/curl.h>
#include <sys/stat.h>
#include "common.h"
#include "config.h"
#include "file.h"
#include "log.h"

/* HTTP Response Code 200 (OK) */
#define HTTP_OK			200
/* HTTP Response Code 304 (Not Modified) */
#define HTTP_NOT_MODIFIED	304
/* HTTP Response Code 400 (Bad Request) */
#define HTTP_BAD_REQUEST	400

struct http_handler {
	CURL *curl;
	char errbuf[CURL_ERROR_SIZE];
};

int
http_init(void)
{
	CURLcode res;
	res = curl_global_init(CURL_GLOBAL_SSL);
	if (res != CURLE_OK)
		return pr_err("Error initializing global curl (%s)",
		    curl_easy_strerror(res));

	return 0;
}

void
http_cleanup(void)
{
	curl_global_cleanup();
}

static int
http_easy_init(struct http_handler *handler)
{
	CURL *tmp;

	tmp = curl_easy_init();
	if (tmp == NULL)
		return pr_enomem();

	/* Use header always */
	if (config_get_http_user_agent() != NULL)
		curl_easy_setopt(tmp, CURLOPT_USERAGENT,
		    config_get_http_user_agent());
	/* Only utilizes if indicated, otherwise use system default */
	if (config_get_http_ca_path() != NULL)
		curl_easy_setopt(tmp, CURLOPT_CAPATH,
		    config_get_http_ca_path());

	curl_easy_setopt(tmp, CURLOPT_CONNECTTIMEOUT,
	    config_get_http_connect_timeout());
	curl_easy_setopt(tmp, CURLOPT_TIMEOUT,
	    config_get_http_transfer_timeout());
	if (config_get_http_idle_timeout() > 0) {
		curl_easy_setopt(tmp, CURLOPT_LOW_SPEED_TIME,
		    config_get_http_idle_timeout());
		curl_easy_setopt(tmp, CURLOPT_LOW_SPEED_LIMIT, 1);
	} else {
		/* Disabled */
		curl_easy_setopt(tmp, CURLOPT_LOW_SPEED_TIME, 0);
		curl_easy_setopt(tmp, CURLOPT_LOW_SPEED_LIMIT, 0);
	}

	/* Always expect HTTPS usage */
	curl_easy_setopt(tmp, CURLOPT_SSL_VERIFYHOST, 2);
	curl_easy_setopt(tmp, CURLOPT_SSL_VERIFYPEER, 1);

	/* Currently all requests use GET */
	curl_easy_setopt(tmp, CURLOPT_HTTPGET, 1);

	/*
	 * Response codes >= 400 will be treated as errors
	 *
	 * "This method is not fail-safe and there are occasions where
	 * non-successful response codes will slip through, especially when
	 * authentication is involved (response codes 401 and 407)."
	 *
	 * Well, be ready for those scenarios when performing the requests.
	 */
	curl_easy_setopt(tmp, CURLOPT_FAILONERROR, 1L);

	/* Refer to its error buffer */
	curl_easy_setopt(tmp, CURLOPT_ERRORBUFFER, handler->errbuf);

	handler->curl = tmp;

	return 0;
}

static char const *
curl_err_string(struct http_handler *handler, CURLcode res)
{
	return strlen(handler->errbuf) > 0 ?
	    handler->errbuf : curl_easy_strerror(res);
}

/*
 * Fetch data from @uri and write result using @cb (which will receive @arg).
 */
static int
http_fetch(struct http_handler *handler, char const *uri, long *response_code,
    long *cond_met, bool log_operation, http_write_cb cb, void *arg)
{
	CURLcode res;
	long unmet = 0;

	handler->errbuf[0] = 0;
	curl_easy_setopt(handler->curl, CURLOPT_URL, uri);
	curl_easy_setopt(handler->curl, CURLOPT_WRITEFUNCTION, cb);
	curl_easy_setopt(handler->curl, CURLOPT_WRITEDATA, arg);

	pr_debug("Doing HTTP GET to '%s'.", uri);
	res = curl_easy_perform(handler->curl);
	curl_easy_getinfo(handler->curl, CURLINFO_RESPONSE_CODE, response_code);
	if (res == CURLE_OK) {
		if (*response_code != HTTP_OK)
			return 0;
		/*
		 * Scenario: Received an OK code, but the time condition wasn't
		 * actually met, handle this as a "Not Modified" code.
		 *
		 * This check is due to old libcurl versions, where the impl
		 * doesn't let us get the response content since the library
		 * does the time validation, resulting in "The requested
		 * document is not new enough".
		 */
		res = curl_easy_getinfo(handler->curl, CURLINFO_CONDITION_UNMET,
		    &unmet);
		if (res == CURLE_OK && unmet == 1)
			*cond_met = 0;
		return 0;
	}

	if (*response_code >= HTTP_BAD_REQUEST)
		return pr_err("Error requesting URL %s (received HTTP code %ld): %s",
		    uri, *response_code, curl_err_string(handler, res));

	/* FIXME (NOW) Always log to validation log */
	pr_err("[VALIDATION] Error requesting URL %s: %s", uri,
	    curl_err_string(handler, res));
	/* FIXME (NOW) and send to operation log when requested */
	if (log_operation)
		pr_err("[OPERATION] Error requesting URL %s: %s", uri,
		    curl_err_string(handler, res));

	return EREQFAILED;
}

static void
http_easy_cleanup(struct http_handler *handler)
{
	curl_easy_cleanup(handler->curl);
}

static int
__http_download_file(struct rpki_uri *uri, http_write_cb cb,
    long *response_code, long ims_value, long *cond_met, bool log_operation)
{
	struct http_handler handler;
	struct stat stat;
	FILE *out;
	int error;

	*cond_met = 1;
	if (config_get_work_offline()) {
		*response_code = 0; /* Not 200 code, but also not an error */
		return 0;
	}

	error = create_dir_recursive(uri_get_local(uri));
	if (error)
		return ENSURE_NEGATIVE(error);

	error = file_write(uri_get_local(uri), &out, &stat);
	if (error)
		goto delete_dir;

	error = http_easy_init(&handler);
	if (error)
		goto close_file;

	/* Set "If-Modified-Since" header only if a value is specified */
	if (ims_value > 0) {
		curl_easy_setopt(handler.curl, CURLOPT_TIMEVALUE, ims_value);
		curl_easy_setopt(handler.curl, CURLOPT_TIMECONDITION,
		    CURL_TIMECOND_IFMODSINCE);
	}

	error = http_fetch(&handler, uri_get_global(uri), response_code,
	    cond_met, log_operation, cb, out);
	http_easy_cleanup(&handler);
	file_close(out);

	if (error)
		goto delete_dir;

	return 0;
close_file:
	file_close(out);
delete_dir:
	delete_dir_recursive_bottom_up(uri_get_local(uri));
	return ENSURE_NEGATIVE(error);
}

/*
 * Try to download from global @uri into a local directory structure created
 * from local @uri. The @cb should be utilized to write into a file; the file
 * will be sent to @cb as the last argument (its a FILE reference).
 *
 * Return values: 0 on success, negative value on error, EREQFAILED if the
 * request to the server failed.
 */
int
http_download_file(struct rpki_uri *uri, http_write_cb cb, bool log_operation)
{
	long response;
	long cond_met;
	return __http_download_file(uri, cb, &response, 0, &cond_met,
	    log_operation);
}

/*
 * Fetch the file from @uri, write it using the @cb.
 *
 * The HTTP request is made using the header 'If-Modified-Since' with a value
 * of @value (if @value is 0, the header isn't set).
 *
 * Returns:
 *   EREQFAILED the request to the server has failed.
 *   > 0 file was requested but wasn't downloaded since the server didn't sent
 *       a response due to its policy using the header 'If-Modified-Since'.
 *   = 0 file successfully downloaded.
 *   < 0 an actual error happened.
 */
int
http_download_file_with_ims(struct rpki_uri *uri, http_write_cb cb, long value,
    bool log_operation)
{
	long response;
	long cond_met;
	int error;

	error = __http_download_file(uri, cb, &response, value, &cond_met,
	    log_operation);
	if (error)
		return error;

	/* rfc7232#section-3.3:
	 * "the origin server SHOULD generate a 304 (Not Modified) response"
	 */
	if (response == HTTP_NOT_MODIFIED)
		return 1;

	/*
	 * Got another HTTP response code (OK or error).
	 *
	 * Check if the time condition was met (in case of error is set as
	 * 'true'), if it wasn't, then do a regular request (no time condition).
	 */
	if (cond_met)
		return 0;

	return __http_download_file(uri, cb, &response, 0, &cond_met,
	    log_operation);

}
