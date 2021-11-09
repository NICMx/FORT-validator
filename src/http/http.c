#include "http.h"

#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <curl/curl.h>
#include "common.h"
#include "config.h"
#include "file.h"
#include "log.h"

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

struct write_callback_arg {
	size_t total_bytes;
	int error;
	FILE *dst;
};

static size_t
write_callback(void *data, size_t size, size_t nmemb, void *userp)
{
	struct write_callback_arg *arg = userp;

	arg->total_bytes += size * nmemb;
	if (arg->total_bytes > config_get_http_max_file_size()) {
		/*
		 * If the server doesn't provide the file size beforehand,
		 * CURLOPT_MAXFILESIZE doesn't prevent large file downloads.
		 *
		 * Therefore, we cover our asses by way of this reactive
		 * approach. We already reached the size limit, but we're going
		 * to reject the file anyway.
		 */
		arg->error = -EFBIG;
		return 0; /* Ugh. See fwrite(3) */
	}

	return fwrite(data, size, nmemb, arg->dst);
}

static void
setopt_writefunction(CURL *curl)
{
	CURLcode result;

	result = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
	if (result != CURLE_OK) {
		fprintf(stderr, "curl_easy_setopt(%d) returned %d: %s\n",
		    CURLOPT_WRITEFUNCTION, result, curl_easy_strerror(result));
	}
}

static void
setopt_writedata(CURL *curl, struct write_callback_arg *arg)
{
	CURLcode result;

	result = curl_easy_setopt(curl, CURLOPT_WRITEDATA, arg);
	if (result != CURLE_OK) {
		fprintf(stderr, "curl_easy_setopt(%d) returned %d: %s\n",
		    CURLOPT_WRITEDATA, result, curl_easy_strerror(result));
	}
}

static int
http_easy_init(struct http_handler *handler)
{
	CURL *result;

	result = curl_easy_init();
	if (result == NULL)
		return pr_enomem();

	setopt_str(result, CURLOPT_USERAGENT, config_get_http_user_agent());

	setopt_long(result, CURLOPT_CONNECTTIMEOUT,
	    config_get_http_connect_timeout());
	setopt_long(result, CURLOPT_TIMEOUT,
	    config_get_http_transfer_timeout());
	setopt_long(result, CURLOPT_LOW_SPEED_LIMIT,
	    config_get_http_low_speed_limit());
	setopt_long(result, CURLOPT_LOW_SPEED_TIME,
	    config_get_http_low_speed_time());
	setopt_long(result, CURLOPT_MAXFILESIZE,
	    config_get_http_max_file_size());
	setopt_writefunction(result);

	/* Always expect HTTPS usage */
	setopt_long(result, CURLOPT_SSL_VERIFYHOST, 2L);
	setopt_long(result, CURLOPT_SSL_VERIFYPEER, 1L);
	setopt_str(result, CURLOPT_CAPATH, config_get_http_ca_path());

	/* Currently all requests use GET */
	setopt_long(result, CURLOPT_HTTPGET, 1L);

	/*
	 * Treat response codes >= 400 as errors. (In theory, this saves a
	 * little time by failing early, preventing the pointless download.)
	 *
	 * "This method is not fail-safe and there are occasions where
	 * non-successful response codes will slip through, especially when
	 * authentication is involved (response codes 401 and 407)."
	 *
	 * In other words, the HTTP result code still needs to be checked, even
	 * if the result of curl_easy_perform() is CURLE_OK.
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

static int
validate_file_size(char const *uri, struct write_callback_arg *args)
{
	float ratio;

	if (args->error == -EFBIG) {
		pr_val_err("File too big (read: %zu bytes). Rejecting.",
		    args->total_bytes);
		return -EFBIG;
	}

	ratio = args->total_bytes / (float) config_get_http_max_file_size();
	if (ratio > 0.5f) {
		pr_op_warn("File size exceeds 50%% of the configured limit (%zu/%ld bytes).",
		    args->total_bytes, config_get_http_max_file_size());
	}

	return 0;
}

static int
get_http_response_code(struct http_handler *handler, long *http_code,
    char const *uri)
{
	CURLcode res;

	res = curl_easy_getinfo(handler->curl, CURLINFO_RESPONSE_CODE,
	    http_code);
	if (res != CURLE_OK) {
		return pr_op_err("curl_easy_getinfo(CURLINFO_RESPONSE_CODE) returned %d (%s). "
		    "I think this is supposed to be illegal, so I'll have to drop URI '%s'.",
		    res, curl_err_string(handler, res), uri);
	}

	return 0;
}

static int
handle_http_response_code(long http_code)
{
	/* This is the same logic from CURL, according to its documentation. */
	if (http_code == 408 || http_code == 429)
		return EREQFAILED; /* Retry */
	if (500 <= http_code && http_code < 600)
		return EREQFAILED; /* Retry */
	return -EINVAL; /* Do not retry */
}

/*
 * Fetch data from @uri and write result using @cb (which will receive @arg).
 */
static int
http_fetch(struct http_handler *handler, char const *uri, long *response_code,
    long *cond_met, bool log_operation, FILE *file)
{
	struct write_callback_arg args;
	CURLcode res;
	long http_code;
	long unmet = 0;

	handler->errbuf[0] = 0;
	setopt_str(handler->curl, CURLOPT_URL, uri);

	args.total_bytes = 0;
	args.error = 0;
	args.dst = file;
	setopt_writedata(handler->curl, &args);

	pr_val_debug("HTTP GET: %s", uri);
	res = curl_easy_perform(handler->curl);
	pr_val_debug("Done. Total bytes transferred: %zu", args.total_bytes);

	args.error = validate_file_size(uri, &args);
	if (args.error)
		return args.error;

	args.error = get_http_response_code(handler, &http_code, uri);
	if (args.error)
		return args.error;
	*response_code = http_code;

	if (res != CURLE_OK) {
		pr_val_err("Error requesting URL: %s. (HTTP code: %ld)",
		    curl_err_string(handler, res), http_code);
		if (log_operation)
			pr_op_err("Error requesting URL: %s. (HTTP code: %ld)",
			    curl_err_string(handler, res), http_code);

		switch (res) {
		case CURLE_FILESIZE_EXCEEDED:
			return -EFBIG; /* Do not retry */
		case CURLE_OPERATION_TIMEDOUT:
		case CURLE_COULDNT_RESOLVE_HOST:
		case CURLE_COULDNT_RESOLVE_PROXY:
		case CURLE_FTP_ACCEPT_TIMEOUT:
			return EREQFAILED; /* Retry */
		default:
			return handle_http_response_code(http_code);
		}
	}

	if (http_code >= 400) {
		pr_val_err("HTTP result code: %ld", http_code);
		return handle_http_response_code(http_code);
	}
	if (http_code >= 300) {
		/*
		 * If you're ever forced to implement this, please remember that
		 * a malicious server can send us on a wild chase with infinite
		 * redirects, so there needs to be a limit.
		 */
		pr_val_err("HTTP result code: %ld. I don't follow redirects; discarding file.",
		    http_code);
		return -EINVAL; /* Do not retry. */
	}

	pr_val_debug("HTTP result code: %ld", http_code);

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
	res = curl_easy_getinfo(handler->curl, CURLINFO_CONDITION_UNMET, &unmet);
	if (res == CURLE_OK && unmet == 1)
		*cond_met = 0;

	return 0;
}

static void
http_easy_cleanup(struct http_handler *handler)
{
	curl_easy_cleanup(handler->curl);
}

static int
__http_download_file(struct rpki_uri *uri, long *response_code, long ims_value,
    long *cond_met, bool log_operation)
{
	char const *tmp_suffix = "_tmp";
	struct http_handler handler;
	FILE *out;
	unsigned int retries;
	char const *original_file;
	char *tmp_file;
	int error;

	retries = 0;
	*cond_met = 1;
	if (!config_get_http_enabled()) {
		*response_code = 0; /* Not 200 code, but also not an error */
		return 0;
	}

	original_file = uri_get_local(uri);

	tmp_file = malloc(strlen(original_file) + strlen(tmp_suffix) + 1);
	if (tmp_file == NULL)
		return pr_enomem();
	strcpy(tmp_file, original_file);
	strcat(tmp_file, tmp_suffix);

	error = create_dir_recursive(tmp_file);
	if (error)
		goto release_tmp;

	error = file_write(tmp_file, &out);
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
		    cond_met, log_operation, out);
		if (error != EREQFAILED)
			break; /* Note: Usually happy path */

		if (retries == config_get_http_retry_count()) {
			if (retries > 0)
				pr_val_warn("Max HTTP retries (%u) reached. Won't retry again.",
				    retries);
			break;
		}
		pr_val_warn("Retrying HTTP request in %u seconds. %u attempts remaining.",
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
		pr_val_err("Renaming temporal file from '%s' to '%s': %s",
		    tmp_file, original_file, strerror(error));
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
http_download_file(struct rpki_uri *uri, bool log_operation)
{
	long response;
	long cond_met;
	return __http_download_file(uri, &response, 0, &cond_met,
	    log_operation);
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
	    log_operation);
	if (error)
		return error;

	/* rfc7232#section-3.3:
	 * "the origin server SHOULD generate a 304 (Not Modified) response"
	 */
	if (response == 304)
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
	    log_operation);

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

	error = file_write(tmp_file, &out);
	if (error)
		goto release_tmp;

	error = http_easy_init(&handler);
	if (error)
		goto close_file;

	error = http_fetch(&handler, remote, &response_code, &cond_met, true,
	    out);
	http_easy_cleanup(&handler);
	file_close(out);
	if (error)
		goto release_tmp;

	/* Overwrite the original file */
	error = rename(tmp_file, dest);
	if (error) {
		error = errno;
		pr_val_err("Renaming temporal file from '%s' to '%s': %s",
		    tmp_file, dest, strerror(error));
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
