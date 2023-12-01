#include "http/http.h"

#include <curl/curl.h>

#include "alloc.h"
#include "common.h"
#include "config.h"
#include "file.h"
#include "log.h"
#include "cache/tmp.h"
#include "data_structure/uthash.h"

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
get_ims(char const *file, time_t *ims)
{
	struct stat meta;
	int error;

	if (stat(file, &meta) != 0) {
		error = errno;
		*ims = 0;
		return (error == ENOENT) ? 0 : error;
	}

	*ims = meta.st_mtim.tv_sec;
	return 0;
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

	char const *file_name;
	FILE *file; /* Initialized lazily */
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

	if (arg->file == NULL) {
		arg->error = file_write(arg->file_name, &arg->file);
		if (arg->error)
			return 0;
	}

	return fwrite(data, size, nmemb, arg->file);
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
http_easy_init(struct http_handler *handler, curl_off_t ims)
{
	CURL *result;

	result = curl_easy_init();
	if (result == NULL)
		return pr_val_err(
		    "curl_easy_init() returned NULL; no error message given."
		);

	setopt_str(result, CURLOPT_USERAGENT, config_get_http_user_agent());

	setopt_long(result, CURLOPT_FOLLOWLOCATION, 1);
	setopt_long(result, CURLOPT_MAXREDIRS, config_get_max_redirs());

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

	if (ims > 0) {
		setopt_long(result, CURLOPT_TIMEVALUE_LARGE, ims);
		setopt_long(result, CURLOPT_TIMECONDITION,
		    CURL_TIMECOND_IFMODSINCE);
	}

	handler->curl = result;
	return 0;
}

static void
http_easy_cleanup(struct http_handler *handler)
{
	curl_easy_cleanup(handler->curl);
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
		return pr_op_err_st("curl_easy_getinfo(CURLINFO_RESPONSE_CODE) returned %d (%s). "
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
		return EAGAIN; /* Retry */
	if (500 <= http_code && http_code < 600)
		return EAGAIN; /* Retry */
	return -EINVAL; /* Do not retry */
}

/*
 * Fetch data from @src and write result on @dst.
 */
static int
http_fetch(char const *src, char const *dst, curl_off_t ims, bool *changed)
{
	struct http_handler handler;
	struct write_callback_arg args;
	CURLcode res;
	long http_code;
	int error;

	error = http_easy_init(&handler, ims);
	if (error)
		return error;

	handler.errbuf[0] = 0;
	setopt_str(handler.curl, CURLOPT_URL, src);

	args.total_bytes = 0;
	args.error = 0;
	args.file_name = dst;
	args.file = NULL;
	setopt_writedata(handler.curl, &args);

	pr_val_info("HTTP GET: %s -> %s", src, dst);
	res = curl_easy_perform(handler.curl); /* write_callback() */
	if (args.file != NULL)
		file_close(args.file);
	pr_val_debug("Done. Total bytes transferred: %zu", args.total_bytes);

	args.error = validate_file_size(src, &args);
	if (args.error) {
		error = args.error;
		goto end;
	}

	args.error = get_http_response_code(&handler, &http_code, src);
	if (args.error) {
		error = args.error;
		goto end;
	}

	if (res != CURLE_OK) {
		pr_val_err("Error requesting URL: %s. (HTTP code: %ld)",
		    curl_err_string(&handler, res), http_code);

		switch (res) {
		case CURLE_FILESIZE_EXCEEDED:
			error = -EFBIG; /* Do not retry */
			goto end;
		case CURLE_OPERATION_TIMEDOUT:
		case CURLE_COULDNT_RESOLVE_HOST:
		case CURLE_COULDNT_RESOLVE_PROXY:
		case CURLE_FTP_ACCEPT_TIMEOUT:
			error = EAGAIN; /* Retry */
			goto end;
		case CURLE_TOO_MANY_REDIRECTS:
			error = -EINVAL;
			goto end;
		default:
			error = handle_http_response_code(http_code);
			goto end;
		}
	}

	if (http_code >= 400 || http_code == 204) {
		pr_val_err("HTTP result code: %ld", http_code);
		error = handle_http_response_code(http_code);
		goto end;
	}
	if (http_code == 304) {
		/* Write callback not called, no file to remove. */
		pr_val_debug("Not modified.");
		error = 0;
		goto end;
	}

	pr_val_debug("HTTP result code: %ld", http_code);
	error = 0;
	*changed = true;

end:	http_easy_cleanup(&handler);
	if (error)
		remove(dst);
	return error;
}

/*
 * Assumes @dst's parent directory has already been created.
 */
static int
do_retries(char const *src, char const *dst, curl_off_t ims, bool *changed)
{
	unsigned int r;
	int error;

	pr_val_info("Downloading '%s'.", src);

	r = 0;
	do {
		pr_val_debug("Download attempt #%u...", r + 1);

		error = http_fetch(src, dst, ims, changed);
		switch (error) {
		case 0:
			pr_val_debug("Download successful.");
			return 0; /* Happy path */

		case EAGAIN:
			break;

		default:
			pr_val_debug("Download failed.");
			return error;
		}

		if (r >= config_get_http_retry_count()) {
			pr_val_debug("Download failed: Retries exhausted.");
			return EIO;
		}

		pr_val_warn("Download failed; retrying in %u seconds.",
		    config_get_http_retry_interval());
		/*
		 * TODO (fine) Wrong. This is slowing the entire tree traversal
		 * down; use a thread pool.
		 */
		sleep(config_get_http_retry_interval());
		r++;
	} while (true);
}

/*
 * Download @uri->global into @uri->local; HTTP assumed.
 *
 * If @changed returns true, the file was downloaded normally.
 * If @changed returns false, the file already existed and is already its latest
 * version.
 * @changed can be NULL.
 */
int
http_download(struct rpki_uri *uri, bool *changed)
{
	char *tmp_file_name;
	char const *final_file_name;
	time_t ims;
	bool __changed;
	int error;

	if (changed == NULL)
		changed = &__changed;
	*changed = false;

	error = cache_tmpfile(&tmp_file_name);
	if (error)
		return error;
	final_file_name = uri_get_local(uri);
	error = get_ims(final_file_name, &ims);
	if (error)
		goto end;

	error = do_retries(uri_get_global(uri), tmp_file_name, (curl_off_t)ims,
	    changed);
	if (error || !(*changed))
		goto end;

	error = mkdir_p(final_file_name, false);
	if (error) {
		remove(tmp_file_name);
		goto end;
	}

	error = rename(tmp_file_name, final_file_name);
	if (error) {
		error = errno;
		pr_val_err("Renaming temporal file from '%s' to '%s': %s",
		    tmp_file_name, final_file_name, strerror(error));
		remove(tmp_file_name);
		goto end;
	}

end:	free(tmp_file_name);
	return error;
}

/*
 * Downloads @remote to the absolute path @dest (no workspace nor directory
 * structure is created).
 */
int
http_direct_download(char const *remote, char const *dest)
{
	bool changed;
	return http_fetch(remote, dest, 0, &changed);
}
