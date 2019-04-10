#include "console_handler.h"

#include "thread_var.h"
#include "validation_handler.h"
#include "object/tal.h"

static int
print_v4_roa(uint32_t as, struct ipv4_prefix const *prefix, uint8_t max_length,
    void *arg)
{
	printf("AS%u,%s/%u,%u\n", as, v4addr2str(&prefix->addr), prefix->len,
	    max_length);
	return 0;
}

static int
print_v6_roa(uint32_t as, struct ipv6_prefix const *prefix, uint8_t max_length,
    void *arg)
{
	printf("AS%u,%s/%u,%u\n", as, v6addr2str(&prefix->addr), prefix->len,
	    max_length);
	return 0;
}

int
validate_into_console(void)
{
	struct validation_handler handler;

	handler.reset = NULL;
	handler.traverse_down = NULL;
	handler.traverse_up = NULL;
	handler.handle_roa_v4 = print_v4_roa;
	handler.handle_roa_v6 = print_v6_roa;
	handler.arg = NULL;

	return perform_standalone_validation(&handler);
}
