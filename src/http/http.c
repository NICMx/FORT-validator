#include "http.h"

#include <curl/curl.h>
#include <sys/stat.h>
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
	curl_easy_setopt(tmp, CURLOPT_NOSIGNAL, 1);

	/* Always expect HTTPS usage */
	curl_easy_setopt(tmp, CURLOPT_SSL_VERIFYHOST, 2);
	curl_easy_setopt(tmp, CURLOPT_SSL_VERIFYPEER, 1);

	/* Currently all requests use GET */
	curl_easy_setopt(tmp, CURLOPT_HTTPGET, 1);

	/* Refer to its error buffer */
	curl_easy_setopt(tmp, CURLOPT_ERRORBUFFER, handler->errbuf);

	handler->curl = tmp;

	return 0;
}

/*
 * Fetch data from @uri and write result using @cb (which will receive @arg).
 */
static int
http_fetch(struct http_handler *handler, char const *uri, http_write_cb cb,
    void *arg)
{
	CURLcode res;

	handler->errbuf[0] = 0;
	curl_easy_setopt(handler->curl, CURLOPT_URL, uri);
	curl_easy_setopt(handler->curl, CURLOPT_WRITEFUNCTION, cb);
	curl_easy_setopt(handler->curl, CURLOPT_WRITEDATA, arg);

	pr_debug("HTTP GET from '%s'.", uri);
	res = curl_easy_perform(handler->curl);
	if (res != CURLE_OK)
		return pr_err("Error requesting URL %s: %s", uri,
		    strlen(handler->errbuf) > 0 ?
		    handler->errbuf : curl_easy_strerror(res));

	return 0;
}

static void
http_easy_cleanup(struct http_handler *handler)
{
	curl_easy_cleanup(handler->curl);
}

/*
 * Try to download from global @uri into a local directory structure created
 * from local @uri. The @cb should be utilized to write into a file; the file
 * will be sent to @cb as the last argument (its a FILE reference).
 */
int
http_download_file(struct rpki_uri *uri, http_write_cb cb)
{
	struct http_handler handler;
	struct stat stat;
	FILE *out;
	int error;

	error = create_dir_recursive(uri_get_local(uri));
	if (error)
		return error;

	error = file_write(uri_get_local(uri), &out, &stat);
	if (error)
		return error;

	error = http_easy_init(&handler);
	if (error)
		goto close_file;

	error = http_fetch(&handler, uri_get_global(uri), cb, out);
	http_easy_cleanup(&handler);
	file_close(out);

	/* Error 0 it's ok */
	return error;
close_file:
	file_close(out);
	return error;
}
