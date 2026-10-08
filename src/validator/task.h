#ifndef VALIDATOR_TASK_H_
#define VALIDATOR_TASK_H_

#include "validator/object/certificate.h"

enum validation_task_type {
	VTT_RPP,
	VTT_TAL,
};

struct validation_task {
	enum validation_task_type type;
	union {
		char *tal;
		struct rpki_certificate *ca;
	} u;
	STAILQ_ENTRY(validation_task) lh;
};

void task_setup(void);
void task_start(void);
void task_cancel(void);
void task_stop(void);
void task_teardown(void);

char const *task_name(struct validation_task *);
bool task_stopped(void);
unsigned int task_enqueue_tal(char const *);
unsigned int task_enqueue_rpp(struct cache_mapping const *, struct rpki_certificate *);
void task_requeue_dormant(struct validation_task *);
void task_wakeup(void);
void task_wakeup_dormants(void);
struct validation_task *task_dequeue(struct validation_task *);

#endif /* VALIDATOR_TASK_H_ */
