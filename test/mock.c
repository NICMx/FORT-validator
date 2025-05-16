#include "mock.h"

#include <errno.h>
#include <arpa/inet.h>
#include <time.h>
#include "config.h"
#include "log.h"
#include "thread_var.h"

/* Some core functions, as linked from unit tests. */

#if 0

static void
print_monotime(void)
{
	struct timespec now;
	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
		pr_crit("clock_gettime() returned '%s'", strerror(errno));
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
		printf(PR_COLOR_RST "\n");				\
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

MOCK_VOID_PRINT(pr_op_debug, PR_COLOR_DBG)
MOCK_VOID_PRINT(pr_op_info, PR_COLOR_INF)
MOCK_INT_PRINT(pr_op_warn, PR_COLOR_WRN, 0)
MOCK_INT_PRINT(pr_op_err, PR_COLOR_ERR, EINVAL)
MOCK_INT_PRINT(pr_op_err_st, PR_COLOR_ERR, EINVAL)
MOCK_INT_PRINT(op_crypto_err, PR_COLOR_ERR, EINVAL)

MOCK_VOID_PRINT(pr_val_debug, PR_COLOR_DBG)
MOCK_VOID_PRINT(pr_val_info, PR_COLOR_INF)
MOCK_INT_PRINT(pr_val_warn, PR_COLOR_WRN, 0)
MOCK_INT_PRINT(pr_val_err, PR_COLOR_ERR, EINVAL)
MOCK_INT_PRINT(val_crypto_err, PR_COLOR_ERR, EINVAL)

void
enomem_panic(void)
{
	ck_abort_msg("Out of memory.");
}

void
pr_crit(const char *format, ...)
{
	va_list args;
	fprintf(stderr, "pr_crit() called! ");
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

MOCK_NULL(config_get_slurm, char const *, void)
MOCK(config_get_tal, char const *, "tal/", void)
MOCK(cfg_cache_threshold, time_t, 2, void)
MOCK(config_get_mode, enum mode, STANDALONE, void)
MOCK_UINT(config_get_rrdp_delta_threshold, 5, void)
MOCK_TRUE(config_get_rsync_enabled, void)
MOCK_UINT(config_get_rsync_priority, 50, void)
MOCK_TRUE(config_get_http_enabled, void)
MOCK_UINT(config_get_http_priority, 60, void)
MOCK_NULL(config_get_output_roa, char const *, void)
MOCK_NULL(config_get_output_bgpsec, char const *, void)
MOCK(config_get_op_log_file_format, enum filename_format, FNF_NAME, void)
MOCK(config_get_val_log_file_format, enum filename_format, FNF_NAME, void)
MOCK(logv_filename, char const *, path, char const *path)
MOCK_VOID(free_rpki_config, void)

MOCK_VOID(fnstack_init, void)
MOCK_VOID(fnstack_push, char const *file)
MOCK_VOID(fnstack_push_map, struct cache_mapping const *map)
MOCK_VOID(fnstack_pop, void)
MOCK_VOID(fnstack_cleanup, void)

void
ck_assert_uri(char const *expected, struct uri const *actual)
{
	ck_assert_str_eq(expected, uri_str(actual));
	ck_assert_uint_eq(strlen(expected), uri_len(actual));
}

void
touch_dir(char const *dir)
{
	ck_assert_int_eq(0, file_mkdir(dir, true));
}

void
touch_file(char const *file)
{
	int fd;
	int error;

	pr_op_debug("touch %s", file);

	fd = open(file, O_WRONLY | O_CREAT, CACHE_FILEMODE);
	if (fd < 0) {
		error = errno;
		if (error == EEXIST)
			return;
		ck_abort_msg("open(%s): %s", file, strerror(error));
	}

	close(fd);
}
