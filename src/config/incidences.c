#include "config/incidences.h"

#include "log.h"

static void
incidences_print(struct option_field const *field, void *_value)
{
	/* Empty */
}

static int
incidences_parse_json(struct option_field const *opt, json_t *json,
    void *_result)
{
	pr_op_warn("Incidences are deprecated; please delete them from your configuration.");
	return 0;
}

const struct global_type gt_incidences = {
	.print = incidences_print,
	.parse.json = incidences_parse_json,
};
