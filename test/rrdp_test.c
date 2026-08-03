#include <check.h>

#include "alloc.c"
#include "asn1/asn1c/INTEGER.c"
#include "asn1/asn1c/asn_codecs_prim.c"
#include "asn1/asn1c/asn_internal.c"
#include "asn1/asn1c/ber_decoder.c"
#include "asn1/asn1c/ber_tlv_length.c"
#include "asn1/asn1c/ber_tlv_tag.c"
#include "asn1/asn1c/constraints.c"
#include "asn1/asn1c/der_encoder.c"
#include "base64.c"
#include "cachefile.c"
#include "common.c"
#include "file.c"
#include "json_util.c"
#include "hash.c"
#include "mock.c"
#include "rrdp.c"
#include "rrdp_xml.c"
#include "types/uri.c"
#include "types/map.c"
#include "types/path.c"
#include "types/str.c"

__MOCK_ABORT(config_get_http_max_file_size, curl_off_t, 10000, void)
__MOCK_ABORT(config_get_asn1_decode_max_stack, unsigned int, 32, void)
__MOCK_ABORT(http_download, int, 0, struct uri const *u, curl_write_callback cb,
    void *a, curl_off_t i, bool *ch)

/* Converts @src into JSON forth and back. Checks the result equals @src. */
static void
ck_json(struct rrdp_ctx const *src)
{
	struct rrdp_ctx *dst;
	json_t *json;

	json = rrdp_ctx2json(src);
	json_dumpf(json, stdout, JSON_INDENT(2));
	printf("\n");
	ck_assert_ptr_ne(NULL, json);
	ck_assert_int_eq(0, rrdp_json2ctx(json, src->seq.pfx.str, &dst));
	json_decref(json);

	/* FIXME (test) not checking sessions */
	if (TAILQ_EMPTY(&src->sessions))
		ck_assert_int_eq(true, TAILQ_EMPTY(&dst->sessions));
	ck_assert_str_eq(src->seq.pfx.str, dst->seq.pfx.str);
	ck_assert_int_eq(src->seq.next_id, dst->seq.next_id);

	rrdpctx_free(dst);
}

struct cache_file *
_cachefile_create(char const *uri, char *path, int hashchr)
{
	struct uri _uri;
	unsigned char hash[SHA256_DIGEST_LENGTH];

	__URI_INIT(&_uri, uri);
	memset(hash, hashchr, SHA256_DIGEST_LENGTH);

	return cachefile_create(&_uri, path, strrchr(path, '/') + 1, hash);
}

static void
step_add_fileref(struct rrdp_step *step, struct cache_file *file)
{
	struct cache_file_ref *fileref;
	char const *urlstr;
	size_t urlen;

	fileref = fileref_create(file);
	urlstr = uri_str(&fileref->file->map.url);
	urlen = uri_len(&fileref->file->map.url);
	HASH_ADD_KEYPTR(hh, step->files.ht, urlstr, urlen, fileref);
}

static void
add_step(struct rrdp_session *session, char const *serial, int hashchr, ...)
{
	struct rrdp_step *step;
	va_list ap;
	struct cache_file *file;

	step = pzalloc(sizeof(struct rrdp_step));
	TAILQ_INSERT_TAIL(&session->steps, step, lh);

	ck_assert_int_eq(0, str2serial(serial, &step->serial));

	va_start(ap, hashchr);
	while ((file = va_arg(ap, struct cache_file *)) != NULL)
		step_add_fileref(step, file);
	va_end(ap);

	memset(step->delta_hash.bytes, hashchr, RRDP_HASH_LEN);
	step->delta_hash.set = true;
}

START_TEST(test_json)
{
	/* TODO (fine) no cleanup */

	struct rrdp_ctx ctx;
	struct rrdp_session se1, se2;
	struct cache_file *f1, *f2, *f3, *f4;

	f1 = _cachefile_create("https://n/a.cer", "https/22/0", 0x0a);
	f2 = _cachefile_create("https://n/b.cer", "https/22/1", 0x0b);
	f3 = _cachefile_create("https://n/c.cer", "https/22/2", 0x0c);
	f4 = _cachefile_create("https://n/d.cer", "https/22/3", 0x0d);

	TAILQ_INIT(&ctx.sessions);

	TAILQ_INSERT_TAIL(&ctx.sessions, &se1, lh);
	se1.id = "session1";
	TAILQ_INIT(&se1.steps);
	add_step(&se1, "3", 0x03, f1, f4, NULL);
	add_step(&se1, "2", 0x02, f2, f3, f4, NULL);
	add_step(&se1, "1", 0x01, f1, f2, f3, NULL);
	se1.fresh = false;
	se1.fbs.ht = NULL;
	ck_assert_int_eq(0, pthread_mutex_init(&se1.fbs.lock, NULL));

	TAILQ_INSERT_TAIL(&ctx.sessions, &se2, lh);
	se2.id = "session2";
	TAILQ_INIT(&se2.steps);
	add_step(&se2, "6", 0x06, f1, f4, NULL);
	add_step(&se2, "5", 0x05, f2, f3, f4, NULL);
	add_step(&se2, "4", 0x04, f1, f2, f3, NULL);
	se2.fresh = true;
	se2.fbs.ht = NULL;
	ck_assert_int_eq(0, pthread_mutex_init(&se2.fbs.lock, NULL));

	cseq_init(&ctx.seq, "http/22", 4, false);

	ck_json(&ctx);
}
END_TEST

static Suite *
create_suite(void)
{
	Suite *suite;
	TCase *json;

	json = tcase_create("json");
	tcase_add_test(json, test_json);

	suite = suite_create("RRDP");
	suite_add_tcase(suite, json);

	return suite;
}

int
main(void)
{
	Suite *suite;
	SRunner *runner;
	int tests_failed;

	suite = create_suite();

	runner = srunner_create(suite);
	srunner_run_all(runner, CK_NORMAL);
	tests_failed = srunner_ntests_failed(runner);
	srunner_free(runner);

	return (tests_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
