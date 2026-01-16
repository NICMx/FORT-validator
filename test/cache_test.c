#include <check.h>
#include <sys/queue.h>

#include "alloc.c"
#include "common.c"
#include "cache.c"
#include "json_util.c"
#include "mock.c"
#include "types/map.c"
#include "types/uri.c"

MOCK(rrdp_ctx2json, json_t *, json_object(), struct rrdp_ctx const *ctx)
MOCK_INT(rrdp_json2ctx, 0, json_t *json, char *path, struct rrdp_ctx **ctx)
MOCK_VOID(rrdpctx_free, struct rrdp_ctx *ctx)
MOCK_ABORT_PTR(tactx_create, ta_context, char const *fallback)
MOCK_ABORT_VOID(tactx_free, struct ta_context *ctx)

/* Converts @src into JSON forth and back. Checks the result equals @src. */
static void
ck_json(struct cache_node const *src)
{
	struct cache_node *dst;
	json_t *json;

	json = node2json(src);
	json_dumpf(json, stdout, JSON_INDENT(2));
	printf("\n");
	ck_assert_ptr_ne(NULL, json);
	dst = json2node(json);
	json_decref(json);

	ck_assert_uri(uri_str(&src->map.url), &dst->map.url);
	ck_assert_str_eq(src->map.path, dst->map.path);
	ck_assert_int_eq(DLS_OUTDATED, dst->state);	/* Must be reset */
	ck_assert_pstr_eq(NULL, dst->verdict);		/* Must be reset */
	ck_assert_int_eq(src->attempt_ts, dst->attempt_ts);
	ck_assert_int_eq(src->success_ts, dst->success_ts);
	ck_assert_int_eq(src->ctx.type, dst->ctx.type);
	ck_assert_ptr_eq(NULL, dst->ctx.v.rrdp);	/* Different module */

	delete_node(NULL, dst, NULL);
}

START_TEST(test_json_min)
{
	struct cache_node node = { 0 };

	__URI_INIT(&node.map.url, "https://a.b.c/sample.cer");
	node.map.path = "rrdp/123";
	node.ctx.type = CT_RRDP;
	node.ctx.v.rrdp = (struct rrdp_ctx *) "dummy";

	ck_json(&node);
}

START_TEST(test_json_max)
{
	struct cache_node node = { 0 };

	__URI_INIT(&node.map.url, "https://a.b.c/sample.cer");
	node.map.path = "rrdp/123";
	node.state = DLS_FRESH;
	node.verdict = VV_FAIL;
	node.attempt_ts = 1234;
	node.success_ts = 4321;
	node.ctx.type = CT_RRDP;
	node.ctx.v.rrdp = (struct rrdp_ctx *) "dummy";

	ck_json(&node);
}

static Suite *
create_suite(void)
{
	Suite *suite;
	TCase *json;

	json = tcase_create("json");
	tcase_add_test(json, test_json_min);
	tcase_add_test(json, test_json_max);

	suite = suite_create("cache");
	suite_add_tcase(suite, json);

	return suite;
}

int
main(void)
{
	SRunner *runner;
	int failures;

	runner = srunner_create(create_suite());
	srunner_run_all(runner, CK_NORMAL);
	failures = srunner_ntests_failed(runner);
	srunner_free(runner);

	return (failures == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
