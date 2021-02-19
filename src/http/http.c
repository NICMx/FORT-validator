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

typedef size_t (http_write_cb)(unsigned char *, size_t, size_t, void *);

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

	/* Prepare for multithreading, avoid signals */
	curl_easy_setopt(tmp, CURLOPT_NOSIGNAL, 1L);

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

	pr_val_debug("Doing HTTP GET to '%s'.", uri);
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
		return pr_val_err("Error requesting URL %s (received HTTP code %ld): %s",
		    uri, *response_code, curl_err_string(handler, res));

	pr_val_err("Error requesting URL %s: %s", uri,
	    curl_err_string(handler, res));
	if (log_operation)
		pr_op_err("Error requesting URL %s: %s", uri,
		    curl_err_string(handler, res));

	return EREQFAILED;
}

static void
http_easy_cleanup(struct http_handler *handler)
{
	curl_easy_cleanup(handler->curl);
}

static size_t
write_cb(unsigned char *content, size_t size, size_t nmemb, void *arg)
{
	FILE *fd = arg;
	size_t read = size * nmemb;
	size_t written;

	written = fwrite(content, size, nmemb, fd);
	if (written != nmemb)
		return -EINVAL;

	return read;
}

static int
__http_download_file(struct rpki_uri *uri, long *response_code, long ims_value,
    long *cond_met, bool log_operation)
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
			curl_easy_setopt(handler.curl, CURLOPT_TIMEVALUE, ims_value);
			curl_easy_setopt(handler.curl, CURLOPT_TIMECONDITION,
			    CURL_TIMECOND_IFMODSINCE);
		}
		error = http_fetch(&handler, uri_get_global(uri), response_code,
		    cond_met, log_operation, write_cb, out);
		if (error != EREQFAILED)
			break;

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
	    write_cb, out);
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
