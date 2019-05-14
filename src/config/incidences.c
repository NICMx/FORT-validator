#include "config/incidences.h"

#include <getopt.h>
#include "incidence/incidence.h"

static void
incidences_print(struct option_field const *field, void *_value)
{
	incidence_print();
}

static int
incidences_parse_json(struct option_field const *opt, json_t *json,
    void *_result)
{
	return incidence_update(json);
}

const struct global_type gt_incidences = {
	.print = incidences_print,
	.parse.json = incidences_parse_json,
};
