#include "mock.h"

#include <errno.h>
#include <arpa/inet.h>
#include "config.h"
#include "config/filename_format.h"
#include "config/mode.h"
#include "incidence.h"
#include "state.h"
#include "thread_var.h"

/**
 * Some core functions, as linked from unit tests.
 */

MOCK_TRUE(log_val_enabled, unsigned int l)
MOCK_TRUE(log_op_enabled, unsigned int l)

///* CFLAGS=-DPRINT_PRS make check */
//#ifdef PRINT_PRS
#define MOCK_PRINT							\
	do {								\
		va_list args;						\
		va_start(args, format);					\
		vfprintf(stdout, format, args);				\
		va_end(args);						\
		printf("\n");						\
	} while (0)
//#else
//#define MOCK_PRINT
//#endif

#define MOCK_VOID_PRINT(name)						\
	void								\
	name(const char *format, ...)					\
	{								\
		MOCK_PRINT;						\
	}

#define MOCK_INT_PRINT(name, result)					\
	int								\
	name(const char *format, ...)					\
	{								\
		MOCK_PRINT;						\
		return result;						\
	}

MOCK_VOID_PRINT(pr_op_debug)
MOCK_VOID_PRINT(pr_op_info)
MOCK_INT_PRINT(pr_op_warn, 0)
MOCK_INT_PRINT(pr_op_err, -EINVAL)
MOCK_INT_PRINT(pr_op_err_st, -EINVAL)
MOCK_INT_PRINT(op_crypto_err, -EINVAL)

MOCK_VOID_PRINT(pr_val_debug)
MOCK_VOID_PRINT(pr_val_info)
MOCK_INT_PRINT(pr_val_warn, 0)
MOCK_INT_PRINT(pr_val_err, -EINVAL)
MOCK_INT_PRINT(val_crypto_err, -EINVAL)

int
incidence(enum incidence_id id, const char *format, ...)
{
	MOCK_PRINT;
	return -EINVAL;
}

void
enomem_panic(void)
{
	ck_abort_msg("Out of memory.");
}

void
pr_crit(const char *format, ...)
{
	va_list args;
	fprintf(stderr, "pr_crit() called!\n");
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
	fprintf(stderr, "\n");
	ck_abort();
}

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
MOCK(config_get_local_repository, char const *, "tmp", void)
MOCK(config_get_mode, enum mode, STANDALONE, void)
MOCK_TRUE(config_get_rsync_enabled, void)
MOCK_UINT(config_get_rsync_priority, 50, void)
MOCK_TRUE(config_get_http_enabled, void)
MOCK_UINT(config_get_http_priority, 60, void)
MOCK_NULL(config_get_output_roa, char const *, void)
MOCK_NULL(config_get_output_bgpsec, char const *, void)
MOCK(config_get_op_log_filename_format, enum filename_format, FNF_NAME, void)
MOCK(config_get_val_log_filename_format, enum filename_format, FNF_NAME, void)
