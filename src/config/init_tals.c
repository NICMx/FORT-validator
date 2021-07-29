#include "config/init_tals.h"

static int
init_tals_parse_json(struct option_field const *opt, json_t *json, void *result)
{
	/* This is deprecated. Please delete it in the future. */
	return 0;
}

const struct global_type gt_init_tals_locations = {
	.print = NULL,
	.parse.json = init_tals_parse_json,
};
