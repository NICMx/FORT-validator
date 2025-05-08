#include <check.h>
#include <stdlib.h>

#include "alloc.c"
#include "common.c"
#include "mock.c"
#include "types/path.c"
#include "types/uri.c"

#define TEST_REWIND(expected, test, limit)				\
	parser.dst = test;						\
	parser.d = strlen(test);					\
	rewind_buffer(&parser, limit);					\
	ck_assert_uint_eq(strlen(expected), parser.d)

START_TEST(test_rewind)
{
	struct uri_buffer parser;

	TEST_REWIND("/a/b", "/a/b/c", 0);
	TEST_REWIND("/a/b", "/a/b/cdefg", 0);

	TEST_REWIND("/a/b", "/a/b/c", 2);
	TEST_REWIND("/a/b", "/a/b/cdefg", 2);

	TEST_REWIND("/a/b", "/a/b/c", 4);
	TEST_REWIND("/a/b", "/a/b/cdefg", 4);

	TEST_REWIND("/a/b", "/a/b", 4);
}
END_TEST

#define TEST_NORMALIZE(dirty, clean)					\
	ck_assert_pstr_eq(NULL, url_normalize(				\
		(unsigned char *)dirty, 0, &normal			\
	));								\
	ck_assert_str_eq(clean, normal);				\
	free(normal)

#define TEST_NORMALIZE_AUS(dirty, clean)				\
	ck_assert_ptr_eq(NULL, url_normalize(				\
		(unsigned char *)dirty, URI_ALLOW_UNKNOWN_SCHEME, &normal \
	));								\
	ck_assert_str_eq(clean, normal);				\
	free(normal)

#define TEST_NORMALIZE_FAIL(dirty, error)				\
	ck_assert_str_eq(error, url_normalize(				\
		(unsigned char *)dirty, 0, &normal			\
	));

#define TEST_NORMALIZE_FAIL_AUS(dirty, error)				\
	ck_assert_str_eq(error, url_normalize(				\
		(unsigned char *)dirty, URI_ALLOW_UNKNOWN_SCHEME, &normal \
	));

START_TEST(awkward_dot_dotting)
{
	char *normal;

	/*
	 * Additional, tricky: RFC 3986 never states that `//` should be
	 * normalized as `/`, which is seemingly implying that `/d//..` equals
	 * `/d/`, not `/` (as Unix would lead one to believe).
	 */
	printf("Extra\n");

	TEST_NORMALIZE("rsync://a.b.c//////", "rsync://a.b.c//////");
	TEST_NORMALIZE_AUS("http://a.b.c/d//..", "http://a.b.c/d");
}
END_TEST

START_TEST(test_port)
{
	char *normal;

	printf("rfc3986#3.2.3: Port\n");

	TEST_NORMALIZE_FAIL("https://a:-1/", EM_PORT_BADCHR);
	TEST_NORMALIZE_FAIL("https://a:0/", EM_PORT_RANGE);
	TEST_NORMALIZE("https://a:1/", "https://a:1/");
	TEST_NORMALIZE("https://a:65535/", "https://a:65535/");
	TEST_NORMALIZE_FAIL("https://a:65536/", EM_PORT_RANGE);
}
END_TEST

START_TEST(pct_encoding)
{
	char *normal;

	printf("3986#2.1: Percent encoding\n");

	TEST_NORMALIZE("https://%61/", "https://a/");
	TEST_NORMALIZE("https://%6f/", "https://o/");
	TEST_NORMALIZE("https://%6F/", "https://o/");
	TEST_NORMALIZE("https://%7C/", "https://%7C/");
	TEST_NORMALIZE("https://%7c/", "https://%7C/");

	TEST_NORMALIZE("https://a%6fa/", "https://aoa/");
	TEST_NORMALIZE("https://a%7ca/", "https://a%7Ca/");

	TEST_NORMALIZE_FAIL("https://%6G", EM_PCT_NOTHEX);
	TEST_NORMALIZE_FAIL("https://%G6", EM_PCT_NOTHEX);

	/* Host */
	TEST_NORMALIZE_FAIL("https://%6", EM_PCT_NOT3);
	TEST_NORMALIZE_FAIL("https://%", EM_PCT_NOT3);
	TEST_NORMALIZE_FAIL("https://%6:", EM_PCT_NOT3);
	TEST_NORMALIZE_FAIL("https://%:", EM_PCT_NOT3);
	TEST_NORMALIZE_FAIL("https://%6/", EM_PCT_NOT3);
	TEST_NORMALIZE_FAIL("https://%/", EM_PCT_NOT3);
	TEST_NORMALIZE_FAIL("https://%6?", EM_PCT_NOT3);
	TEST_NORMALIZE_FAIL("https://%?", EM_PCT_NOT3);
	TEST_NORMALIZE_FAIL("https://%6#", EM_PCT_NOT3);
	TEST_NORMALIZE_FAIL("https://%#", EM_PCT_NOT3);

	/* Userinfo */
	TEST_NORMALIZE("rsync://%61@a/", "rsync://a@a/");
	TEST_NORMALIZE_FAIL("rsync://%6@a", EM_PCT_NOT3);
	TEST_NORMALIZE_FAIL("rsync://%@a", EM_PCT_NOT3);

	/* Port */
	TEST_NORMALIZE_FAIL("rsync://a:%31/", EM_PORT_BADCHR);
	TEST_NORMALIZE_FAIL("rsync://a:%3", EM_PORT_BADCHR);
	TEST_NORMALIZE_FAIL("rsync://a:%", EM_PORT_BADCHR);

	/* Path */
	TEST_NORMALIZE("https://a/%41", "https://a/A");
	TEST_NORMALIZE_FAIL("https://a/%4", EM_PCT_NOT3);
	TEST_NORMALIZE_FAIL("https://a/%", EM_PCT_NOT3);
	TEST_NORMALIZE_FAIL("https://a/%4/", EM_PCT_NOT3);
	TEST_NORMALIZE_FAIL("https://a/%/", EM_PCT_NOT3);
	TEST_NORMALIZE_FAIL("https://a/%4?", EM_PCT_NOT3);
	TEST_NORMALIZE_FAIL("https://a/%?", EM_PCT_NOT3);
	TEST_NORMALIZE_FAIL("https://a/%4#", EM_PCT_NOT3);
	TEST_NORMALIZE_FAIL("https://a/%#", EM_PCT_NOT3);

	/* Query */
	TEST_NORMALIZE("https://a/?%30", "https://a/?0");
	TEST_NORMALIZE_FAIL("https://a/?%3", EM_PCT_NOT3);
	TEST_NORMALIZE_FAIL("https://a/?%", EM_PCT_NOT3);
	TEST_NORMALIZE_FAIL("https://a/?%3#", EM_PCT_NOT3);
	TEST_NORMALIZE_FAIL("https://a/?%#", EM_PCT_NOT3);

	/* Fragment */
	TEST_NORMALIZE("https://a/#%30", "https://a/#0");
	TEST_NORMALIZE_FAIL("https://a/#%3", EM_PCT_NOT3);
	TEST_NORMALIZE_FAIL("https://a/#%", EM_PCT_NOT3);
}
END_TEST

#define ck_assert_origin(expected, s1, s2)				\
	do {								\
		__URI_INIT(&u1, s1);					\
		__URI_INIT(&u2, s2);					\
		ck_assert_int_eq(expected, uri_same_origin(&u1, &u2));	\
	} while (0)

START_TEST(test_same_origin)
{
	struct uri u1, u2;

	ck_assert_origin(true,	"https://a.b.c/d/e/f",	"https://a.b.c/g/h/i");
	ck_assert_origin(false,	"https://a.b.cc/d/e/f",	"https://a.b.c/g/h/i");
	ck_assert_origin(false,	"https://a.b.c/d/e/f",	"https://a.b.cc/g/h/i");
	ck_assert_origin(true,	"https://a.b.c",	"https://a.b.c");
	ck_assert_origin(true,	"https://a.b.c/",	"https://a.b.c");
	ck_assert_origin(true,	"https://a.b.c",	"https://a.b.c/");
	ck_assert_origin(true,	"https://",		"https://");
	ck_assert_origin(false,	"https://",		"https://a");
	ck_assert_origin(false,	"https://a",		"https://b");

	/* Undefined, but manhandle the code anyway */
	ck_assert_origin(false,	"",			"");
	ck_assert_origin(false,	"ht",			"ht");
	ck_assert_origin(false,	"https:",		"https:");
	ck_assert_origin(false,	"https:/",		"https:/");
	ck_assert_origin(false,	"https:/a",		"https:/a");
	ck_assert_origin(true,	"https:/a/",		"https:/a/");
}
END_TEST

static unsigned char const ASCI = 'a';	/* 0_______ */
static unsigned char const CONT = 0x80;	/* 10______ */
static unsigned char const DUO = 0xC0;	/* 110_____ */
static unsigned char const TRIO = 0xE0;	/* 1110____ */
static unsigned char const QUAD = 0xF0;	/* 11110___ */
static unsigned char const CHRS[] = { ASCI, CONT, DUO, TRIO, QUAD, 0 };

static void
test_utf8_fail(unsigned char chr1, unsigned char chr2,
    unsigned char chr3, unsigned char chr4)
{
	char *normal;
	char messy[32];

	if (chr1 == ASCI && chr2 == ASCI && chr3 == ASCI && chr4 == ASCI)
		return;
	if (chr1 == ASCI && chr2 == ASCI && chr3 == DUO && chr4 == CONT)
		return;
	if (chr1 == ASCI && chr2 == DUO && chr3 == CONT && chr4 == ASCI)
		return;
	if (chr1 == DUO && chr2 == CONT && chr3 == ASCI && chr4 == ASCI)
		return;
	if (chr1 == DUO && chr2 == CONT && chr3 == DUO && chr4 == CONT)
		return;
	if (chr1 == ASCI && chr2 == TRIO && chr3 == CONT && chr4 == CONT)
		return;
	if (chr1 == TRIO && chr2 == CONT && chr3 == CONT && chr4 == ASCI)
		return;
	if (chr1 == QUAD && chr2 == CONT && chr3 == CONT && chr4 == CONT)
		return;

	strcpy(messy, "https://----/");
	messy[8] = chr1;
	messy[9] = chr2;
	messy[10] = chr3;
	messy[11] = chr4;
	TEST_NORMALIZE_FAIL(messy, EM_UTF8);
}

START_TEST(test_utf8)
{
	char *normal;
	array_index c1, c2, c3, c4;

	TEST_NORMALIZE("https://a.β.c/", "https://a.%CE%B2.c/");
	TEST_NORMALIZE("https://a.砦.c/", "https://a.%E7%A0%A6.c/");
	TEST_NORMALIZE("https://a.𝆑.c/", "https://a.%F0%9D%86%91.c/");

	TEST_NORMALIZE_FAIL_AUS("βsync://a.b.c/", EM_SCHEME_1ST);
	TEST_NORMALIZE_FAIL_AUS("rsβnc://a.b.c/", EM_SCHEME_NTH);
	TEST_NORMALIZE("rsync://β@a.b.c/", "rsync://%CE%B2@a.b.c/");
	TEST_NORMALIZE_FAIL("rsync://a.b.c:β/", EM_PORT_BADCHR);
	TEST_NORMALIZE("https://a.b.c/β", "https://a.b.c/%CE%B2");
	TEST_NORMALIZE("https://a.b.c/?β", "https://a.b.c/?%CE%B2");
	TEST_NORMALIZE("https://a.b.c/#β", "https://a.b.c/#%CE%B2");

	for (c1 = 0; CHRS[c1]; c1++)
		for (c2 = 0; CHRS[c2]; c2++)
			for (c3 = 0; CHRS[c3]; c3++)
				for (c4 = 0; CHRS[c4]; c4++)
					test_utf8_fail(CHRS[c1], CHRS[c2],
					    CHRS[c3], CHRS[c4]);
}
END_TEST

START_TEST(test_unknown_protocols)
{
	char *normal;

	printf("Unknown protocols\n");

	TEST_NORMALIZE_AUS("https://a.b.c/d", "https://a.b.c/d");
	TEST_NORMALIZE("https://a.b.c/d", "https://a.b.c/d");
	TEST_NORMALIZE_AUS("http://a.b.c/d", "http://a.b.c/d");
	TEST_NORMALIZE_FAIL("http://a.b.c/d", EM_SCHEME_UNKNOWN);

	TEST_NORMALIZE_FAIL("httpz://a.b.c/d", EM_SCHEME_UNKNOWN);
	TEST_NORMALIZE_FAIL("abcde://a.b.c/d", EM_SCHEME_UNKNOWN);
	TEST_NORMALIZE_FAIL("://a.b.c/d", EM_SCHEME_EMPTY);
	TEST_NORMALIZE_FAIL("0abc://a.b.c/d", EM_SCHEME_UNKNOWN);
	TEST_NORMALIZE_FAIL("9abc://a.b.c/d", EM_SCHEME_UNKNOWN);
	TEST_NORMALIZE_FAIL("+abc://a.b.c/d", EM_SCHEME_UNKNOWN);
	TEST_NORMALIZE_FAIL(".abc://a.b.c/d", EM_SCHEME_UNKNOWN);
	TEST_NORMALIZE_FAIL("-abc://a.b.c/d", EM_SCHEME_UNKNOWN);
	TEST_NORMALIZE_FAIL("a_b://a.b.c/d", EM_SCHEME_UNKNOWN);
	TEST_NORMALIZE_FAIL("a~b://a.b.c/d", EM_SCHEME_UNKNOWN);

	TEST_NORMALIZE_AUS("httpz://a.b.c/d", "httpz://a.b.c/d");
	TEST_NORMALIZE_AUS("abcde://a.b.c/d", "abcde://a.b.c/d");
	TEST_NORMALIZE_FAIL_AUS("://a.b.c/d", EM_SCHEME_EMPTY);
	TEST_NORMALIZE_FAIL_AUS("0abc://a.b.c/d", EM_SCHEME_1ST);
	TEST_NORMALIZE_FAIL_AUS("9abc://a.b.c/d", EM_SCHEME_1ST);
	TEST_NORMALIZE_FAIL_AUS("+abc://a.b.c/d", EM_SCHEME_1ST);
	TEST_NORMALIZE_FAIL_AUS(".abc://a.b.c/d", EM_SCHEME_1ST);
	TEST_NORMALIZE_FAIL_AUS("-abc://a.b.c/d", EM_SCHEME_1ST);
	TEST_NORMALIZE_AUS("a0b://a.b.c/d", "a0b://a.b.c/d");
	TEST_NORMALIZE_AUS("a9b://a.b.c/d", "a9b://a.b.c/d");
	TEST_NORMALIZE_AUS("a+b://a.b.c/d", "a+b://a.b.c/d");
	TEST_NORMALIZE_AUS("a.b://a.b.c/d", "a.b://a.b.c/d");
	TEST_NORMALIZE_AUS("a-b://a.b.c/d", "a-b://a.b.c/d");
	TEST_NORMALIZE_FAIL_AUS("a_b://a.b.c/d", EM_SCHEME_NTH);
	TEST_NORMALIZE_FAIL_AUS("a~b://a.b.c/d", EM_SCHEME_NTH);
}
END_TEST

START_TEST(reserved_unchanged)
{
	char *normal;

	printf("3986#2.2: \"characters in the reserved set are protected from normalization\"\n");
	printf("3986#6.2.2.1: Percent-encoding should always be uppercase\n");

#define RESERVED_PCT "%3A%2F%3F%23%5B%5D%40%21%24%26%27%28%29%2A%2B%2C%3B%3D"
#define SUBDELIMS "!$&'()*+,;="

	TEST_NORMALIZE("https://" RESERVED_PCT ":1234/" RESERVED_PCT "?" RESERVED_PCT "#" RESERVED_PCT,
			"https://" RESERVED_PCT ":1234/" RESERVED_PCT "?" RESERVED_PCT "#" RESERVED_PCT);
	TEST_NORMALIZE("https://" SUBDELIMS ":1234/" SUBDELIMS "?" SUBDELIMS "#" SUBDELIMS,
			"https://" SUBDELIMS ":1234/" SUBDELIMS "?" SUBDELIMS "#" SUBDELIMS);

	TEST_NORMALIZE("rsync://" RESERVED_PCT "@" RESERVED_PCT ":1234/" RESERVED_PCT,
			"rsync://" RESERVED_PCT "@" RESERVED_PCT ":1234/" RESERVED_PCT);
	TEST_NORMALIZE("rsync://" SUBDELIMS "@" SUBDELIMS ":1234/" SUBDELIMS,
			"rsync://" SUBDELIMS "@" SUBDELIMS ":1234/" SUBDELIMS);
}
END_TEST

START_TEST(test_query)
{
	char *normal;

	printf("3986#3.4: Query\n");

	TEST_NORMALIZE("https://a/?azAZ09-._~%31!$&'()*+,;=:@/?", "https://a/?azAZ09-._~1!$&'()*+,;=:@/?");
	TEST_NORMALIZE("https://a/?azAZ09-._~%31!$&'()*+,;=:@/?#", "https://a/?azAZ09-._~1!$&'()*+,;=:@/?#");

	TEST_NORMALIZE_FAIL("https://a/?[", EM_QF_BADCHR);
	TEST_NORMALIZE_FAIL("https://a/?]", EM_QF_BADCHR);
	TEST_NORMALIZE_FAIL("https://a/? ", EM_QF_BADCHR);
	TEST_NORMALIZE_FAIL("https://a/?\"", EM_QF_BADCHR);
	TEST_NORMALIZE_FAIL("https://a/?<", EM_QF_BADCHR);
	TEST_NORMALIZE_FAIL("https://a/?>", EM_QF_BADCHR);
	TEST_NORMALIZE_FAIL("https://a/?\\", EM_QF_BADCHR);
	TEST_NORMALIZE_FAIL("https://a/?^", EM_QF_BADCHR);
	TEST_NORMALIZE_FAIL("https://a/?`", EM_QF_BADCHR);
	TEST_NORMALIZE_FAIL("https://a/?{", EM_QF_BADCHR);
	TEST_NORMALIZE_FAIL("https://a/?}", EM_QF_BADCHR);
	TEST_NORMALIZE_FAIL("https://a/?|", EM_QF_BADCHR);
}
END_TEST

START_TEST(test_fragment)
{
	char *normal;

	printf("3986#3.6: Fragment\n");

	TEST_NORMALIZE("https://a/#azAZ09-._~%31!$&'()*+,;=:@/?", "https://a/#azAZ09-._~1!$&'()*+,;=:@/?");
	TEST_NORMALIZE("https://a/#azAZ09-._~%31!$&'()*+,;=:@/?", "https://a/#azAZ09-._~1!$&'()*+,;=:@/?");

	TEST_NORMALIZE_FAIL("https://a/##", EM_QF_BADCHR);
	TEST_NORMALIZE_FAIL("https://a/#[", EM_QF_BADCHR);
	TEST_NORMALIZE_FAIL("https://a/#]", EM_QF_BADCHR);
	TEST_NORMALIZE_FAIL("https://a/# ", EM_QF_BADCHR);
	TEST_NORMALIZE_FAIL("https://a/#\"", EM_QF_BADCHR);
	TEST_NORMALIZE_FAIL("https://a/#<", EM_QF_BADCHR);
	TEST_NORMALIZE_FAIL("https://a/#>", EM_QF_BADCHR);
	TEST_NORMALIZE_FAIL("https://a/#\\", EM_QF_BADCHR);
	TEST_NORMALIZE_FAIL("https://a/#^", EM_QF_BADCHR);
	TEST_NORMALIZE_FAIL("https://a/#`", EM_QF_BADCHR);
	TEST_NORMALIZE_FAIL("https://a/#{", EM_QF_BADCHR);
	TEST_NORMALIZE_FAIL("https://a/#}", EM_QF_BADCHR);
	TEST_NORMALIZE_FAIL("https://a/#|", EM_QF_BADCHR);
}
END_TEST

START_TEST(lowercase_scheme_and_host)
{
	char *normal;

	printf("3986#6.2.2.1, 9110#4.2.3c: Lowercase scheme and host\n");

	TEST_NORMALIZE_AUS("http://a.b.c/d", "http://a.b.c/d");
	TEST_NORMALIZE_AUS("abcde://a.b.c/d", "abcde://a.b.c/d");
	TEST_NORMALIZE_AUS("HTTPS://a.b.c/d", "https://a.b.c/d");
	TEST_NORMALIZE_AUS("rSyNc://a.b.c/d", "rsync://a.b.c/d");
	TEST_NORMALIZE_AUS("HTTPS://A.B.C/d", "https://a.b.c/d");
	TEST_NORMALIZE_AUS("HTTP://WWW.EXAMPLE.COM/aBc/dEf", "http://www.example.com/aBc/dEf");
	TEST_NORMALIZE_AUS("HTTP://WWW.EXAMPLE.COM/aBc/dEf?gHi#jKl", "http://www.example.com/aBc/dEf?gHi#jKl");
}
END_TEST

START_TEST(decode_unreserved_characters)
{
	char *normal;

	printf("3986#6.2.2.2, 9110#4.2.3d: Decode unreserved characters\n");

	TEST_NORMALIZE_AUS("http://%61%7A.%41%5A.%30%39/%61%7A%41%5A%30%39", "http://az.AZ.09/azAZ09");
	TEST_NORMALIZE_AUS("http://%2D%2E%5F%7E/%2D%2E%5F%7E", "http://-._~/-._~");
}
END_TEST

START_TEST(path_segment_normalization)
{
	char *normal;

	printf("3986#6.2.2.3: Path segment normalization\n");

	TEST_NORMALIZE("rsync://a.b.c", "rsync://a.b.c/");
	TEST_NORMALIZE("rsync://a.b.c/", "rsync://a.b.c/");
	TEST_NORMALIZE("rsync://a.b.c/d", "rsync://a.b.c/d");
	TEST_NORMALIZE("rsync://a.b.c//////", "rsync://a.b.c//////");
	TEST_NORMALIZE("rsync://a.b.c/d/e", "rsync://a.b.c/d/e");
	TEST_NORMALIZE("rsync://a.b.c/d/e/.", "rsync://a.b.c/d/e");
	TEST_NORMALIZE("rsync://a.b.c/d/e/.", "rsync://a.b.c/d/e");
	TEST_NORMALIZE("rsync://a.b.c/././d/././e/./.", "rsync://a.b.c/d/e");
	TEST_NORMALIZE("rsync://a.b.c/d/..", "rsync://a.b.c/");
	TEST_NORMALIZE("rsync://a.b.c/x/../x/y/z", "rsync://a.b.c/x/y/z");
	TEST_NORMALIZE("rsync://a.b.c/d/../d/../d/e/", "rsync://a.b.c/d/e/");
	TEST_NORMALIZE("rsync://x//y/z/../../m/./n/o", "rsync://x//m/n/o");
	TEST_NORMALIZE("rsync://.", "rsync://./");
	TEST_NORMALIZE("https://./.", "https://./");
	TEST_NORMALIZE("https://./d", "https://./d");
	TEST_NORMALIZE("rsync://..", "rsync://../");
	TEST_NORMALIZE("rsync://../..", "rsync://../");
	TEST_NORMALIZE("rsync://../d", "rsync://../d");
	TEST_NORMALIZE("rsync://a.b.c/..", "rsync://a.b.c/");
	TEST_NORMALIZE("rsync://a.b.c/../..", "rsync://a.b.c/");
	TEST_NORMALIZE("rsync://a.b.c/../x", "rsync://a.b.c/x");
	TEST_NORMALIZE("rsync://a.b.c/../x/y/z", "rsync://a.b.c/x/y/z");
	TEST_NORMALIZE("rsync://a.b.c/d/e/../../..", "rsync://a.b.c/");
}
END_TEST

START_TEST(all_the_above_combined)
{
	char *normal;

	printf("3986#6.2.2: All the above, combined\n");

	TEST_NORMALIZE_AUS("example://a/b/c/%5Bfoo%5D", "example://a/b/c/%5Bfoo%5D");
	TEST_NORMALIZE_AUS("eXAMPLE://a/./b/../b/%63/%5bfoo%5d", "example://a/b/c/%5Bfoo%5D");
}
END_TEST

START_TEST(scheme_based_normalization)
{
	char *normal;

	printf("3986#6.2.3: Scheme-based normalization\n");

	TEST_NORMALIZE_AUS("http://example.com/?", "http://example.com/?");
	TEST_NORMALIZE_AUS("http://example.com/#", "http://example.com/#");
}
END_TEST

START_TEST(https_grammar)
{
	char *normal;

	printf("9110#4.2.2: https-URI     = \"https\" \"://\" authority path-abempty [ \"?\" query ]\n");
	printf("            authority     = host [ \":\" port ]\n");
	printf("            path-abempty  = *( \"/\" segment )\n");
	printf("            segment       = *pchar\n");

	TEST_NORMALIZE_FAIL("", EM_SCHEME_NOCOLON);
	TEST_NORMALIZE_FAIL("h", EM_SCHEME_NOCOLON);
	TEST_NORMALIZE_FAIL("http", EM_SCHEME_NOCOLON);
	TEST_NORMALIZE_FAIL("https", EM_SCHEME_NOCOLON);
	TEST_NORMALIZE_FAIL("https:", EM_SCHEME_NOTREMOTE);
	TEST_NORMALIZE_FAIL("https:/", EM_SCHEME_NOTREMOTE);
	TEST_NORMALIZE_FAIL("https://", EM_HOST_EMPTY);

	/* I think everything else is already tested elsewhere. */
}
END_TEST

START_TEST(https_default_port)
{
	char *normal;

	printf("9110#4.2.2: Default https port is 443\n");
	printf("(Also 9110#4.2.3: Omit default port)\n");

	TEST_NORMALIZE("https://a.b.c/", "https://a.b.c/");
	TEST_NORMALIZE("https://a.b.c:/", "https://a.b.c/");
	TEST_NORMALIZE("https://a.b.c:443/", "https://a.b.c/");
	TEST_NORMALIZE("https://a.b.c:873/", "https://a.b.c:873/");

	TEST_NORMALIZE("https://a.b.c", "https://a.b.c/");
	TEST_NORMALIZE("https://a.b.c:", "https://a.b.c/");
	TEST_NORMALIZE("https://a.b.c:443", "https://a.b.c/");
	TEST_NORMALIZE("https://a.b.c:873", "https://a.b.c:873/");
}
END_TEST

START_TEST(disallow_http_empty_host)
{
	char *normal;

	printf("9110#4.2.2: Disallow https empty host\n");
	printf("(Also 9110#4.2.3: Empty path normalizes to '/')\n");

	TEST_NORMALIZE("https://a", "https://a/");
	TEST_NORMALIZE_FAIL("https://", EM_HOST_EMPTY);
	TEST_NORMALIZE("https://a/f/g", "https://a/f/g");
	TEST_NORMALIZE_FAIL("https:///f/g", EM_HOST_EMPTY);
	TEST_NORMALIZE("https://a:1234/f/g", "https://a:1234/f/g");
	TEST_NORMALIZE_FAIL("https://:1234/f/g", EM_HOST_EMPTY);
	TEST_NORMALIZE("https://a?123", "https://a/?123");
	TEST_NORMALIZE_FAIL("https://?123", EM_HOST_EMPTY);
	TEST_NORMALIZE("https://a#123", "https://a/#123");
	TEST_NORMALIZE_FAIL("https://#123", EM_HOST_EMPTY);
}
END_TEST

START_TEST(provide_default_path)
{
	char *normal;

	printf("9110#4.2.3: Empty path normalizes to '/'\n");

	TEST_NORMALIZE("https://example.com/", "https://example.com/");
	TEST_NORMALIZE("https://example.com", "https://example.com/");
}
END_TEST

START_TEST(scheme_and_host_lowercase)
{
	char *normal;

	printf("9110#4.2.3: Scheme and host normalize to lowercase\n");

	TEST_NORMALIZE("https://c.d.e:123/FgHi/jKlM?NoPQ#rStU", "https://c.d.e:123/FgHi/jKlM?NoPQ#rStU");
	TEST_NORMALIZE("HTTPS://C.D.E:123/FgHi/jKlM?NoPQ#rStU", "https://c.d.e:123/FgHi/jKlM?NoPQ#rStU");
	TEST_NORMALIZE("hTtPs://C.d.E:123/FgHi/jKlM?NoPQ#rStU", "https://c.d.e:123/FgHi/jKlM?NoPQ#rStU");
}
END_TEST

START_TEST(not_reserved_not_pct_encoded)
{
	char *normal;

	/*
	 * Note: It seems "not in the reserved set" apparently means "unreserved
	 * characters," not "any character, except those in the reserved set."
	 *
	 * Otherwise there are too many exceptions: Non-printables, whitespace,
	 * quotes, percent, less/greater than, backslash, caret, backtick,
	 * curlies and pipe.
	 *
	 * That being said, we're going to cover all characters in the same
	 * test.
	 */
	printf("9110#4.2.3: \"Characters other than those in the 'reserved' set\" normalize to not percent-encoded\n");

/* "All Characters, Encoded Uppercase" */
#define ACEU "%00%01%02%03%04%05%06%07%08%09%0A%0B%0C%0D%0E%0F"	\
	"%10%11%12%13%14%15%16%17%18%19%1A%1B%1C%1D%1E%1F"	\
	"%20%21%22%23%24%25%26%27%28%29%2A%2B%2C%2D%2E%2F"	\
	"%30%31%32%33%34%35%36%37%38%39%3A%3B%3C%3D%3E%3F"	\
	"%40%41%42%43%44%45%46%47%48%49%4A%4B%4C%4D%4E%4F"	\
	"%50%51%52%53%54%55%56%57%58%59%5A%5B%5C%5D%5E%5F"	\
	"%60%61%62%63%64%65%66%67%68%69%6A%6B%6C%6D%6E%6F"	\
	"%70%71%72%73%74%75%76%77%78%79%7A%7B%7C%7D%7E%7F"
/* "All Characters, Encoded Lowercase" */
#define ACEL "%00%01%02%03%04%05%06%07%08%09%0a%0b%0c%0d%0e%0f"	\
	"%10%11%12%13%14%15%16%17%18%19%1a%1b%1c%1d%1e%1f"	\
	"%20%21%22%23%24%25%26%27%28%29%2a%2b%2c%2d%2e%2f"	\
	"%30%31%32%33%34%35%36%37%38%39%3a%3b%3c%3d%3e%3f"	\
	"%40%41%42%43%44%45%46%47%48%49%4a%4b%4c%4d%4e%4f"	\
	"%50%51%52%53%54%55%56%57%58%59%5a%5b%5c%5d%5e%5f"	\
	"%60%61%62%63%64%65%66%67%68%69%6a%6b%6c%6d%6e%6f"	\
	"%70%71%72%73%74%75%76%77%78%79%7a%7b%7c%7d%7e%7f"	\
/* "All Characters, Decoded" */
#define ACD "%00%01%02%03%04%05%06%07%08%09%0A%0B%0C%0D%0E%0F"	\
	"%10%11%12%13%14%15%16%17%18%19%1A%1B%1C%1D%1E%1F"	\
	"%20%21%22%23%24%25%26%27%28%29%2A%2B%2C-.%2F"		\
	"0123456789%3A%3B%3C%3D%3E%3F"				\
	"%40ABCDEFGHIJKLMNO"					\
	"PQRSTUVWXYZ%5B%5C%5D%5E_"				\
	"%60abcdefghijklmno"					\
	"pqrstuvwxyz%7B%7C%7D~%7F"

	TEST_NORMALIZE("https://" ACEU "/" ACEU "?" ACEU "#" ACEU,
			"https://" ACD "/" ACD "?" ACD "#" ACD);
	TEST_NORMALIZE("https://" ACEL "/" ACEL "?" ACEL "#" ACEL,
			"https://" ACD "/" ACD "?" ACD "#" ACD);
}
END_TEST

START_TEST(aggregated_423)
{
	char *normal;

	printf("9110#4.2.3: Aggregated example\n");

	TEST_NORMALIZE("https://example.com:443/~smith/home.html", "https://example.com/~smith/home.html");
	TEST_NORMALIZE("https://EXAMPLE.com/%7Esmith/home.html", "https://example.com/~smith/home.html");
	TEST_NORMALIZE("https://EXAMPLE.com:/%7esmith/home.html", "https://example.com/~smith/home.html");
}
END_TEST

START_TEST(disallow_https_userinfo)
{
	char *normal;

	printf("9110#4.2.4: Disallow https userinfo\n");

	TEST_NORMALIZE("https://c.d.e/f/g", "https://c.d.e/f/g");
	TEST_NORMALIZE_FAIL("https://a@c.d.e/f/g", EM_USERINFO_DISALLOWED);
	TEST_NORMALIZE_FAIL("https://a:b@c.d.e/f/g", EM_USERINFO_DISALLOWED);
}
END_TEST

START_TEST(rsync_grammar)
{
	char *normal;

	printf("5781#2: rsync://[user@]host[:PORT]/Source\n");
	printf("rsyncuri        = \"rsync:\" hier-part\n");

	TEST_NORMALIZE_FAIL("", EM_SCHEME_NOCOLON);
	TEST_NORMALIZE_FAIL("r", EM_SCHEME_NOCOLON);
	TEST_NORMALIZE_FAIL("rsyn", EM_SCHEME_NOCOLON);
	TEST_NORMALIZE_FAIL("rsync", EM_SCHEME_NOCOLON);
	TEST_NORMALIZE_FAIL("rsync:", EM_SCHEME_NOTREMOTE);
	TEST_NORMALIZE_FAIL("rsync:/", EM_SCHEME_NOTREMOTE);
	TEST_NORMALIZE_FAIL("rsync://", EM_HOST_EMPTY);

	TEST_NORMALIZE("rsync://a.b.c/m", "rsync://a.b.c/m");
	TEST_NORMALIZE("rsync://a.b.c/m/r", "rsync://a.b.c/m/r");
	TEST_NORMALIZE_FAIL("rsync://a.b.c/m/r?query", EM_QUERY_DISALLOWED);
	TEST_NORMALIZE_FAIL("rsync://a.b.c/m/r#fragment", EM_FRAGMENT_DISALLOWED);

	/* hier-part     = "//" authority path-abempty */
	TEST_NORMALIZE("rsync://user@a.b.c:1234/m/r", "rsync://user@a.b.c:1234/m/r");
	TEST_NORMALIZE("rsync://a.b.c/m/r", "rsync://a.b.c/m/r");
	TEST_NORMALIZE("rsync://user@a.b.c:1234", "rsync://user@a.b.c:1234/");
	TEST_NORMALIZE("rsync://a.b.c", "rsync://a.b.c/");
	TEST_NORMALIZE_FAIL("rsync://[@a.b.c", EM_USERINFO_BADCHR);

	/* hier-part     = path-absolute */
	/* ie. "rsync:/" [ pchar+ ( "/" pchar* )* ] */
	/* (These refer to local files. The RFC allows them, but Fort shouldn't.) */
	TEST_NORMALIZE_FAIL("rsync:/", EM_SCHEME_NOTREMOTE);
	TEST_NORMALIZE_FAIL("rsync:/a", EM_SCHEME_NOTREMOTE);
	TEST_NORMALIZE_FAIL("rsync:/a/", EM_SCHEME_NOTREMOTE);
	TEST_NORMALIZE_FAIL("rsync:/a/a", EM_SCHEME_NOTREMOTE);
	TEST_NORMALIZE_FAIL("rsync:/a/a/a", EM_SCHEME_NOTREMOTE);
	TEST_NORMALIZE_FAIL("rsync:/abc/def/xyz", EM_SCHEME_NOTREMOTE);
	TEST_NORMALIZE_FAIL("rsync:/abc////def//xyz", EM_SCHEME_NOTREMOTE);

	/* hier-part     = path-rootless */
	/* ie. "rsync:" pchar+ ( "/" pchar* )* */
	/* (Also local paths. Disallowed by Fort needs.) */
	TEST_NORMALIZE_FAIL("rsync:a", EM_SCHEME_NOTREMOTE);
	TEST_NORMALIZE_FAIL("rsync:aa", EM_SCHEME_NOTREMOTE);
	TEST_NORMALIZE_FAIL("rsync:aa/", EM_SCHEME_NOTREMOTE);
	TEST_NORMALIZE_FAIL("rsync:aa/a", EM_SCHEME_NOTREMOTE);
	TEST_NORMALIZE_FAIL("rsync:aa/aa", EM_SCHEME_NOTREMOTE);
	TEST_NORMALIZE_FAIL("rsync:aa///aa", EM_SCHEME_NOTREMOTE);

	/* hier-part     = path-empty */
	TEST_NORMALIZE_FAIL("rsync:", EM_SCHEME_NOTREMOTE);
}
END_TEST

START_TEST(rsync_default_port)
{
	char *normal;

	printf("5781#2: Default rsync port is 873\n");
	TEST_NORMALIZE("rsync://a.b.c/", "rsync://a.b.c/");
	TEST_NORMALIZE("rsync://a.b.c:/", "rsync://a.b.c/");
	TEST_NORMALIZE("rsync://a.b.c:873/", "rsync://a.b.c/");
	TEST_NORMALIZE("rsync://a.b.c:443/", "rsync://a.b.c:443/");
}
END_TEST

static Suite *create_suite(void)
{
	Suite *suite;
	TCase *misc, *generic, *https, *rsync;

	misc = tcase_create("Miscellaneous");
	tcase_add_test(misc, test_rewind);
	tcase_add_test(misc, test_unknown_protocols);
	tcase_add_test(misc, awkward_dot_dotting);
	tcase_add_test(misc, test_same_origin);
	tcase_add_test(misc, test_utf8);

	generic = tcase_create("RFC 3986 (generic URI)");
	tcase_add_test(generic, pct_encoding);
	tcase_add_test(generic, reserved_unchanged);
	tcase_add_test(generic, test_port);
	tcase_add_test(generic, test_query);
	tcase_add_test(generic, test_fragment);
	tcase_add_test(generic, lowercase_scheme_and_host);
	tcase_add_test(generic, decode_unreserved_characters);
	tcase_add_test(generic, path_segment_normalization);
	tcase_add_test(generic, all_the_above_combined);
	tcase_add_test(generic, scheme_based_normalization);

	https = tcase_create("RFC 9110 (https)");
	tcase_add_test(https, https_grammar);
	tcase_add_test(https, https_default_port);
	tcase_add_test(https, disallow_http_empty_host);
	tcase_add_test(https, provide_default_path);
	tcase_add_test(https, scheme_and_host_lowercase);
	tcase_add_test(https, not_reserved_not_pct_encoded);
	tcase_add_test(https, aggregated_423);
	tcase_add_test(https, disallow_https_userinfo);

	rsync = tcase_create("RFC 5781 (rsync)");
	tcase_add_test(rsync, rsync_grammar);
	tcase_add_test(rsync, rsync_default_port);

	suite = suite_create("url");
	suite_add_tcase(suite, misc);
	suite_add_tcase(suite, generic);
	suite_add_tcase(suite, https);
	suite_add_tcase(suite, rsync);

	return suite;
}

int main(void)
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
