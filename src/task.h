#ifndef SRC_TASK_H_
#define SRC_TASK_H_

#include <sys/queue.h>

#include "types/map.h"
#include "object/certificate.h"

struct validation_task {
	struct rpki_certificate *ca;
	STAILQ_ENTRY(validation_task) lh;
};

void task_setup(void);
void task_start(void);
void task_stop(void);
void task_teardown(void);

unsigned int task_enqueue(struct cache_mapping *, struct rpki_certificate *);
void task_requeue_busy(struct validation_task *);
void task_wakeup(void);
void task_wakeup_busy(void);
struct validation_task *task_dequeue(struct validation_task *);

#endif /* SRC_TASK_H_ */
