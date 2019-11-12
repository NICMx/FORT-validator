#include <check.h>
#include <errno.h>
#include <stdlib.h>

#include "common.c"
#include "file.c"
#include "impersonator.c"
#include "log.c"
#include "uri.c"
#include "http/http.c"

struct response {
	unsigned char *content;
	size_t size;
};

static void
init_response(struct response *resp)
{
	resp->size = 0;
	resp->content = malloc(sizeof(char));
}

static size_t
write_cb(unsigned char *content, size_t size, size_t nmemb, void *arg)
{
	struct response *resp = arg;
	unsigned char *tmp;
	size_t read = size * nmemb;

	tmp = realloc(resp->content, resp->size + read + 1);
	if (tmp == NULL)
		return -EINVAL;

	resp->content = tmp;
	memcpy(&resp->content[resp->size], content, read);
	resp->size += read;
	resp->content[resp->size] = 0;

	return read;
}

static int
local_download(char const *url, struct response *resp)
{
	struct http_handler handler;
	int error;

	error = http_easy_init(&handler);
	if (error)
		return error;

	error = http_fetch(&handler, url, write_cb, resp);
	http_easy_cleanup(&handler);
	return error;
}

START_TEST(http_fetch_normal)
{
	struct response resp;
	char const *url = "https://rrdp.ripe.net/notification.xml";

	init_response(&resp);

	ck_assert_int_eq(http_init(), 0);
	ck_assert_int_eq(local_download(url, &resp), 0);
	ck_assert_int_gt(resp.size, 0);

	http_cleanup();
	free(resp.content);
}
END_TEST

Suite *http_load_suite(void)
{
	Suite *suite;
	TCase *fetch;

	fetch = tcase_create("Fetch");
	tcase_add_test(fetch, http_fetch_normal);
	tcase_set_timeout(fetch, 60);

	suite = suite_create("http_test()");
	suite_add_tcase(suite, fetch);

	return suite;
}

int main(void)
{
	Suite *suite;
	SRunner *runner;
	int tests_failed;

	suite = http_load_suite();

	runner = srunner_create(suite);
	srunner_run_all(runner, CK_NORMAL);
	tests_failed = srunner_ntests_failed(runner);
	srunner_free(runner);

	return (tests_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
