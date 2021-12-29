#include "http/http.h"

#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <curl/curl.h>
#include "common.h"
#include "config.h"
#include "file.h"
#include "log.h"

struct curl_args {
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
		arg->error = EFBIG;
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
http_easy_init(struct curl_args *handler, long ims)
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

	if (ims > 0) {
		/* Set "If-Modified-Since" header */
		setopt_long(result, CURLOPT_TIMEVALUE, ims);
		setopt_long(result, CURLOPT_TIMECONDITION,
		    CURL_TIMECOND_IFMODSINCE);
	}

	handler->curl = result;
	return 0;
}

static char const *
curl_err_string(struct curl_args *handler, CURLcode res)
{
	return strlen(handler->errbuf) > 0 ?
	    handler->errbuf : curl_easy_strerror(res);
}

static int
get_http_response_code(struct curl_args *handler, long *http_code,
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
		return EAGAIN; /* Retry */
	if (500 <= http_code && http_code < 600)
		return EAGAIN; /* Retry */
	return -EINVAL; /* Do not retry */
}

/*
 * *Single* attempt to request URI @src, and store it in file @dst.
 *
 * If @dst already exists, it *will* be overwritten without warning. Basically
 * always. Even if IMS is enabled.
 *
 * Leaves a dirty file on error. I'm offloading the responsibility of cleaning
 * it, because parent directories should also probably be deleted if empty, but
 * only if we don't need to retry.
 */
static int
do_single_http_get(struct curl_args *handler, char const *src, char const *dst)
{
	struct write_callback_arg args;
	CURLcode res;
	long http_code;

	args.total_bytes = 0;
	handler->errbuf[0] = 0;
	setopt_str(handler->curl, CURLOPT_URL, src);
	setopt_writedata(handler->curl, &args);

	pr_val_debug("HTTP GET: %s", src);

	args.error = file_write(dst, &args.dst);
	if (args.error)
		return args.error;

	res = curl_easy_perform(handler->curl);

	file_close(args.dst);

	pr_val_debug("Done. Total bytes transferred: %zu", args.total_bytes);

	if (args.error == EFBIG) {
		pr_val_err("File too big (read: %zu bytes). Rejecting.",
		    args.total_bytes);
		return EFBIG;
	}

	args.error = get_http_response_code(handler, &http_code, src);
	if (args.error)
		return args.error;

	if (res != CURLE_OK) {
		pr_val_err("Error requesting URL %s: %s. (HTTP code: %ld)",
		    src, curl_err_string(handler, res), http_code);

		switch (res) {
		case CURLE_FILESIZE_EXCEEDED:
			return EFBIG; /* Do not retry */
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
	if (http_code == 304) {
		pr_val_debug("HTTP result code: %ld. No need to download.",
		    http_code);
		return ENOTCHANGED;
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
	return 0;
}

static void
http_easy_cleanup(struct curl_args *handler)
{
	curl_easy_cleanup(handler->curl);
}

/* Retries in accordance with configuration limits. */
static int
retry_until_done(char const *remote, char const *local,
    struct curl_args *handler)
{
	unsigned int attempt;
	unsigned int max_attempts;
	unsigned int retry_interval;
	int error;

	error = create_dir_recursive(local);
	if (error)
		return error;

	max_attempts = config_get_http_retry_count() + 1;
	retry_interval = config_get_http_retry_interval();

	for (attempt = 1; true; attempt++) {
		pr_val_debug("HTTP GET attempt %u (out of %u)...",
		    attempt, max_attempts);
		error = do_single_http_get(handler, remote, local);
		if (error == 0)
			return 0;
		if (error != EAGAIN)
			break;

		if (attempt == max_attempts) {
			pr_val_err("HTTP GET attempt %u (out of %u): Failure. Giving up.",
			    attempt, max_attempts);
			break;
		}

		pr_val_warn("HTTP GET attempt %u (out of %u): Failure. Retrying in %u seconds.",
		    attempt, max_attempts, retry_interval);
		sleep(retry_interval);
	}

	delete_dir_recursive_bottom_up(local);
	return error;
}

/*
 * Try to download from @remote into @local, full package.
 *
 * @ims is the The "If-Modified-Since" HTTP header.
 * -1 happens to be an invalid `time()` value, so use it if you don't want to
 * include the header.
 *
 * Return values:
 *
 * - 0: Download successful.
 * - ENOTCHANGED: File hasn't changed since `args->ims`.
 * - < 0: Something went wrong.
 */
int
http_get(struct rpki_uri *uri, long ims)
{
	static char const *TMP_SUFFIX = "_tmp";

	struct curl_args handler;
	char *tmp_file;
	int error;

	if (!config_get_http_enabled())
		return ENOTCHANGED;

	/* TODO (aaaa) this is reusable. Move to the thread. */
	error = http_easy_init(&handler, ims);
	if (error)
		return error;

	/*
	 * We will write the file into a temporal location first.
	 * This will prevent us from overriding the existing file, which is
	 * going to be a problem if the download turns out to fail.
	 */
	tmp_file = malloc(strlen(uri_get_local(uri)) + strlen(TMP_SUFFIX) + 1);
	if (tmp_file == NULL) {
		error = pr_enomem();
		goto free_handler;
	}
	strcpy(tmp_file, uri_get_local(uri));
	strcat(tmp_file, TMP_SUFFIX);

	error = retry_until_done(uri_get_global(uri), tmp_file, &handler);
	if (error)
		goto free_tmp;

	if (rename(tmp_file, uri_get_local(uri)) == -1) {
		error = errno;
		pr_val_errno(error, "Renaming temporal file from '%s' to '%s'",
		    tmp_file, uri_get_local(uri));
	}

free_tmp:
	free(tmp_file);
free_handler:
	http_easy_cleanup(&handler);
	return error;
}

/*
 * Downloads @remote to the absolute path @dest (no workspace nor directory
 * structure is created).
 *
 * TODO (aaaa) this function needs to shrink even more.
 */
int
http_direct_download(char const *remote, char const *dest)
{
	struct curl_args curl;
	int error;

	error = http_easy_init(&curl, 0L);
	if (error)
		return error;

	error = do_single_http_get(&curl, remote, dest);

	http_easy_cleanup(&curl);

	return error;
}
