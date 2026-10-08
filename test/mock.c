#include "mock.h"

#include <errno.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <openssl/err.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "common/common.h"
#include "common/log.h"
#include "common/types/map.h"
#include "validator/config.h"

/* Some core functions, as linked from unit tests. */

bool
pr_trc_enabled(void)
{
	return true;
}

#if 0

static void
print_monotime(void)
{
	struct timespec now;
	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
		pr_panic("clock_gettime() returned '%s'", strerror(errno));
	printf("%ld.%.3ld ", now.tv_sec, now.tv_nsec / 1000000);
}

#define MOCK_PRINT(color)						\
	do {								\
		va_list args;						\
		printf(color);						\
		print_monotime();					\
		va_start(args, format);					\
		vfprintf(stdout, format, args);				\
		va_end(args);						\
		printf(CLR_RST "\n");					\
	} while (0)

#else
#define MOCK_PRINT(color)
#endif

#define MOCK_VOID_PRINT(name, color)					\
	void								\
	name(const char *format, ...)					\
	{								\
		MOCK_PRINT(color);					\
	}

#define MOCK_INT_PRINT(name, color, result)				\
	int								\
	name(const char *format, ...)					\
	{								\
		MOCK_PRINT(color);					\
		return result;						\
	}

MOCK_VOID_PRINT(pr_trc, CLR_DBG)
MOCK_VOID_PRINT(pr_inf, CRL_INF)
MOCK_INT_PRINT(pr_wrn, CLR_WRN, 0)
MOCK_INT_PRINT(pr_crit, CLR_ERR, EINVAL)

#define ERRMSG_MAXSIZE 256
static char last_errmsg[ERRMSG_MAXSIZE];

int
pr_err(char const *format, ...)
{
	va_list args2;

	MOCK_PRINT(CLR_ERR);

	if (last_errmsg[0] != 0)
		pr_wrn("The test printed more than one error message: '%s'",
		    last_errmsg);

	va_start(args2, format);
	vsnprintf(last_errmsg, ERRMSG_MAXSIZE, format, args2);
	va_end(args2);

	return EINVAL;
}

struct crypto_cb_arg {
	unsigned int stack_size;
	int (*error_fn)(const char *, ...);
};

static int
log_crypto_error(const char *str, size_t len, void *_arg)
{
	struct crypto_cb_arg *arg = _arg;
	arg->error_fn("-> %s", str);
	arg->stack_size++;
	return 1;
}

int
pr_crypto_err(const char *format, ...)
{
	struct crypto_cb_arg arg;

	MOCK_PRINT(CLR_ERR);

	pr_err("libcrypto error stack:");
	arg.stack_size = 0;
	arg.error_fn = pr_err;
	ERR_print_errors_cb(log_crypto_error, &arg);
	if (arg.stack_size == 0)
		pr_err("   <Empty>");
	else
		pr_err("End of libcrypto stack.");

	return EINVAL;
}

void
enomem_panic(void)
{
	ck_abort_msg("Out of memory.");
}

void
pr_panic(const char *format, ...)
{
	va_list args;
	fprintf(stderr, "pr_panic() called! ");
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
	fprintf(stderr, "\n");
	ck_abort();
}

MOCK_VOID(log_teardown, void)

static char addr_buffer1[INET6_ADDRSTRLEN];
static char addr_buffer2[INET6_ADDRSTRLEN];

char const *
v4addr2str(struct in_addr const *addr)
{
	return inet_ntop(AF_INET, addr, addr_buffer1, sizeof(addr_buffer1));
}

char const *
v4addr2str2(struct in_addr const *addr)
{
	return inet_ntop(AF_INET, addr, addr_buffer2, sizeof(addr_buffer2));
}

char const *
v6addr2str(struct in6_addr const *addr)
{
	return inet_ntop(AF_INET6, addr, addr_buffer1, sizeof(addr_buffer1));
}

char const *
v6addr2str2(struct in6_addr const *addr)
{
	return inet_ntop(AF_INET6, addr, addr_buffer2, sizeof(addr_buffer2));
}

struct fort_config fortcfg = {
	.tal = "tal/",
	.rrdp.delta_threshold = 5,
	.rsync.enabled = true,
	.http.enabled = true,
};

MOCK_VOID(free_rpki_config, void *cfg)

MOCK_VOID(fnstack_init, void)
MOCK_VOID(fnstack_push, char const *file)
MOCK_VOID(fnstack_pop, void)
MOCK_VOID(fnstack_cleanup, void)

void
ck_assert_pstr_eq_free(char const *expected, char *actual)
{
	ck_assert_pstr_eq(expected, actual);
	free(actual);
}

void
ck_assert_uri(char const *expected, struct uri const *actual)
{
	ck_assert_str_eq(expected, uri_str(actual));
	ck_assert_uint_eq(strlen(expected), uri_len(actual));
}

void
touch_dir(char const *dir)
{
	ck_assert(mkdir(dir, CACHE_FILEMODE) == 0 || errno == EEXIST);
}

void
touch_file(char const *file)
{
	int fd;
	int error;

	pr_trc("touch %s", file);

	fd = open(file, O_WRONLY | O_CREAT, CACHE_FILEMODE);
	if (fd < 0) {
		error = errno;
		if (error == EEXIST)
			return;
		ck_abort_msg("open(%s): %s", file, strerror(error));
	}

	close(fd);
}
