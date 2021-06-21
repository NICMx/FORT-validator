#include "http.h"

#include <errno.h>
#include <stdio.h>
#include <unistd.h>
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
		return pr_op_err("Error initializing global curl (%s)",
		    curl_easy_strerror(res));

	return 0;
}

void
http_cleanup(void)
{
	curl_global_cleanup();
}

static void
setopt_str(CURL *curl, CURLoption opt, char const *value)
{
	CURLcode result;

	if (value == NULL)
		return;

	result = curl_easy_setopt(curl, opt, value);
	if (result != CURLE_OK) {
		fprintf(stderr, "curl_easy_setopt(%d, %s) returned %d: %s\n",
		    opt, value, result, curl_easy_strerror(result));
	}
}

static void
setopt_long(CURL *curl, CURLoption opt, long value)
{
	CURLcode result;

	result = curl_easy_setopt(curl, opt, value);
	if (result != CURLE_OK) {
		fprintf(stderr, "curl_easy_setopt(%d, %ld) returned %d: %s\n",
		    opt, value, result, curl_easy_strerror(result));
	}
}

static void
setopt_writedata(CURL *curl, FILE *file)
{
	CURLcode result;

	result = curl_easy_setopt(curl, CURLOPT_WRITEDATA, file);
	if (result != CURLE_OK) {
		fprintf(stderr, "curl_easy_setopt(%d) returned %d: %s\n",
		    CURLOPT_WRITEDATA, result, curl_easy_strerror(result));
	}
}

static int
http_easy_init(struct http_handler *handler)
{
	CURL *result;
	long timeout;

	result = curl_easy_init();
	if (result == NULL)
		return pr_enomem();

	setopt_str(result, CURLOPT_USERAGENT, config_get_http_user_agent());

	setopt_long(result, CURLOPT_CONNECTTIMEOUT,
	    config_get_http_connect_timeout());
	setopt_long(result, CURLOPT_TIMEOUT,
	    config_get_http_transfer_timeout());

	timeout = config_get_http_idle_timeout();
	setopt_long(result, CURLOPT_LOW_SPEED_TIME, timeout);
	setopt_long(result, CURLOPT_LOW_SPEED_LIMIT, !!timeout);

	/* Always expect HTTPS usage */
	setopt_long(result, CURLOPT_SSL_VERIFYHOST, 2L);
	setopt_long(result, CURLOPT_SSL_VERIFYPEER, 1L);
	setopt_str(result, CURLOPT_CAPATH, config_get_http_ca_path());

	/* Currently all requests use GET */
	setopt_long(result, CURLOPT_HTTPGET, 1L);

	/*
	 * Response codes >= 400 will be treated as errors
	 *
	 * "This method is not fail-safe and there are occasions where
	 * non-successful response codes will slip through, especially when
	 * authentication is involved (response codes 401 and 407)."
	 *
	 * Well, be ready for those scenarios when performing the requests.
	 */
	setopt_long(result, CURLOPT_FAILONERROR, 1L);

	/* Refer to its error buffer */
	setopt_str(result, CURLOPT_ERRORBUFFER, handler->errbuf);

	/* Prepare for multithreading, avoid signals */
	setopt_long(result, CURLOPT_NOSIGNAL, 1L);

	handler->curl = result;
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
    long *cond_met, bool log_operation, FILE *file, bool is_ta)
{
	CURLcode res, res2;
	long unmet = 0;

	handler->errbuf[0] = 0;
	setopt_str(handler->curl, CURLOPT_URL, uri);
	setopt_writedata(handler->curl, file);

	res = curl_easy_perform(handler->curl);

	res2 = curl_easy_getinfo(handler->curl, CURLINFO_RESPONSE_CODE,
	    response_code);
	if (res2 != CURLE_OK) {
		return pr_op_err("curl_easy_getinfo(CURLINFO_RESPONSE_CODE) returned %d (%s). I think this is supposed to be illegal, so I'll have to drop URI '%s'.",
		    res2, curl_err_string(handler, res2), uri);
	}

	if (res == CURLE_OK) {
		if (*response_code != HTTP_OK)
			return 0;

		/*
		 * Scenario: Received an OK code, but the time condition
		 * (if-modified-since) wasn't actually met (ie. the document
		 * has not been modified since we last requested it), so handle
		 * this as a "Not Modified" code.
 		 *
 		 * This check is due to old libcurl versions, where the impl
		 * doesn't let us get the response content since the library
		 * does the time validation, resulting in "The requested
		 * document is not new enough".
		 *
		 * Update 2021-05-25: I just tested libcurl in my old CentOS 7.7
		 * VM (which is from October 2019, ie. older than the comments
		 * above), and it behaves normally.
		 * Also, the changelog doesn't mention anything about
		 * If-Modified-Since.
		 * This glue code is suspicious to me.
		 *
		 * For the record, this is how it behaves in my today's Ubuntu,
		 * as well as my Centos 7.7.1908:
		 *
		 * 	if if-modified-since is included:
		 * 		if page was modified:
		 * 			HTTP 200
		 * 			unmet: 0
		 * 			writefunction called
		 * 		else:
		 * 			HTTP 304
		 * 			unmet: 1
		 * 			writefunction not called
		 * 	else:
		 * 		HTTP OK
		 * 		unmet: 0
		 * 		writefunction called
		 */
		res = curl_easy_getinfo(handler->curl, CURLINFO_CONDITION_UNMET,
		    &unmet);
		if (res == CURLE_OK && unmet == 1)
			*cond_met = 0;
		return 0;
	}

	if (*response_code >= HTTP_BAD_REQUEST) {
		return pr_val_err("Error requesting URL %s (received HTTP code %ld): %s",
		    uri, *response_code, curl_err_string(handler, res));
	}

	pr_val_err("Error requesting URL %s: %s", uri,
	    curl_err_string(handler, res));
	if (log_operation) {
		pr_op_err("Error requesting URL %s: %s", uri,
		    curl_err_string(handler, res));
	}

	return EREQFAILED;
}

static void
http_easy_cleanup(struct http_handler *handler)
{
	curl_easy_cleanup(handler->curl);
}

static int
__http_download_file(struct rpki_uri *uri, long *response_code, long ims_value,
    long *cond_met, bool log_operation, bool is_ta)
{
	char const *tmp_suffix = "_tmp";
	struct http_handler handler;
	struct stat stat;
	FILE *out;
	unsigned int retries;
	char const *original_file;
	char *tmp_file, *tmp;
	int error;

	retries = 0;
	*cond_met = 1;
	if (!config_get_http_enabled()) {
		*response_code = 0; /* Not 200 code, but also not an error */
		return 0;
	}

	original_file = uri_get_local(uri);
	tmp_file = strdup(original_file);
	if (tmp_file == NULL)
		return pr_enomem();

	tmp = realloc(tmp_file, strlen(tmp_file) + strlen(tmp_suffix) + 1);
	if (tmp == NULL) {
		error = pr_enomem();
		goto release_tmp;
	}

	tmp_file = tmp;
	strcat(tmp_file, tmp_suffix);

	error = create_dir_recursive(tmp_file);
	if (error)
		goto release_tmp;

	error = file_write(tmp_file, &out, &stat);
	if (error)
		goto delete_dir;

	do {
		error = http_easy_init(&handler);
		if (error)
			goto close_file;

		/* Set "If-Modified-Since" header only if a value is specified */
		if (ims_value > 0) {
			setopt_long(handler.curl, CURLOPT_TIMEVALUE, ims_value);
			setopt_long(handler.curl, CURLOPT_TIMECONDITION,
			    CURL_TIMECOND_IFMODSINCE);
		}
		error = http_fetch(&handler, uri_get_global(uri), response_code,
		    cond_met, log_operation, out, is_ta);
		if (error != EREQFAILED) {
			break; /* Note: Usually happy path */
		}

		if (retries == config_get_http_retry_count()) {
			pr_val_warn("Max HTTP retries (%u) reached requesting for '%s', won't retry again.",
			    retries, uri_get_global(uri));
			break;
		}
		pr_val_warn("Retrying HTTP request '%s' in %u seconds, %u attempts remaining.",
		    uri_get_global(uri),
		    config_get_http_retry_interval(),
		    config_get_http_retry_count() - retries);
		retries++;
		http_easy_cleanup(&handler);
		sleep(config_get_http_retry_interval());
	} while (true);

	http_easy_cleanup(&handler);
	file_close(out);

	if (error)
		goto delete_dir;

	/* Overwrite the original file */
	error = rename(tmp_file, original_file);
	if (error) {
		error = errno;
		pr_val_errno(error, "Renaming temporal file from '%s' to '%s'",
		    tmp_file, original_file);
		goto delete_dir;
	}

	free(tmp_file);
	return 0;
close_file:
	file_close(out);
delete_dir:
	delete_dir_recursive_bottom_up(tmp_file);
release_tmp:
	free(tmp_file);
	return ENSURE_NEGATIVE(error);
}

/*
 * Try to download from global @uri into a local directory structure created
 * from local @uri.
 *
 * Return values: 0 on success, negative value on error, EREQFAILED if the
 * request to the server failed.
 */
int
http_download_file(struct rpki_uri *uri, bool log_operation, bool is_ta)
{
	long response;
	long cond_met;
	return __http_download_file(uri, &response, 0, &cond_met,
	    log_operation, is_ta);
}

/*
 * Fetch the file from @uri.
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
http_download_file_with_ims(struct rpki_uri *uri, long value,
    bool log_operation)
{
	long response;
	long cond_met;
	int error;

	error = __http_download_file(uri, &response, value, &cond_met,
	    log_operation, false);
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

	/*
	 * Situation:
	 *
	 * - old libcurl (because libcurl returned HTTP 200 and cond_met == 0,
	 *   which is a contradiction)
	 * - the download was successful (error == 0)
	 * - the page WAS modified since the last update
	 *
	 * libcurl wrote an empty file, so we have to redownload.
	 */

	return __http_download_file(uri, &response, 0, &cond_met,
	    log_operation, false);

}

/*
 * Downloads @remote to the absolute path @dest (no workspace nor directory
 * structure is created).
 */
int
http_direct_download(char const *remote, char const *dest)
{
	char const *tmp_suffix = "_tmp";
	struct http_handler handler;
	struct stat stat;
	FILE *out;
	long response_code;
	long cond_met;
	char *tmp_file, *tmp;
	int error;

	tmp_file = strdup(dest);
	if (tmp_file == NULL)
		return pr_enomem();

	tmp = realloc(tmp_file, strlen(tmp_file) + strlen(tmp_suffix) + 1);
	if (tmp == NULL) {
		error = pr_enomem();
		goto release_tmp;
	}

	tmp_file = tmp;
	strcat(tmp_file, tmp_suffix);

	error = file_write(tmp_file, &out, &stat);
	if (error)
		goto release_tmp;

	error = http_easy_init(&handler);
	if (error)
		goto close_file;

	response_code = 0;
	cond_met = 0;
	error = http_fetch(&handler, remote, &response_code, &cond_met, true,
	    out, false);
	http_easy_cleanup(&handler);
	file_close(out);
	if (error)
		goto release_tmp;

	/* Overwrite the original file */
	error = rename(tmp_file, dest);
	if (error) {
		error = errno;
		pr_val_errno(error, "Renaming temporal file from '%s' to '%s'",
		    tmp_file, dest);
		goto release_tmp;
	}

	free(tmp_file);
	return 0;
close_file:
	file_close(out);
release_tmp:
	free(tmp_file);
	return error;
}
