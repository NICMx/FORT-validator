#include "rtr/db/vrps.h"

#include <errno.h>
#include <sys/stat.h>

#include "config.h"
#include "log.h"
#include "object/tal.h"
#include "output_printer.h"
#include "slurm/slurm_loader.h"

/*
 * High level validator function.
 *
 * - Downloads tree
 * - Validates tree
 * - Updates RTR state
 */
static struct vp_table *
__vrps_update(void)
{
	struct vp_table *vpt;

	vpt = perform_standalone_validation();
	if (!vpt)
		return NULL;

	// XXX The RTR save should happen before the cache cleanup

	if (slurm_apply(vpt) != 0)
		goto fail;

	vpt_sort(vpt);

	if (vpt_cache(vpt) != 0)
		goto fail;

	output_print_data(vpt);

	return vpt;

fail:	vpt_destroy(vpt);
	return NULL;
}

/*
 * Highest level validator function.
 *
 * - Downloads tree
 * - Validates tree
 * - Updates RTR state
 * - Logs status
 *
 * TODO (#50) remove this wrapper once Prometheus is implemented
 */
int
vrps_update(struct rtr_metadata *rtr)
{
	struct vp_table *vpt;
	time_t start, finish;

	start = time(NULL);
	vpt = __vrps_update();
	finish = time(NULL);

	pr_inf("Validation finished:");
	pr_inf("- Valid VRPs: %u", vpt_vrp_count(vpt));
	pr_inf("- Valid Router Keys: %u", vpt_rk_count(vpt));
	pr_inf("- Valid ASPAs: %u", vpt_aspa_count(vpt));
	if (fortcfg.mode == SERVER)
		pr_inf("- Serial: %u", vpt_serial(vpt));
	if (start != ((time_t) -1) && finish != ((time_t) -1))
		pr_inf("- Real execution time: %.0lfs", difftime(finish, start));

	if (rtr) {
		rtr->session = vpt_session(vpt);
		rtr->serial = vpt_serial(vpt);
	}

	vpt_destroy(vpt);
	return vpt ? 0 : EINVAL;
}
