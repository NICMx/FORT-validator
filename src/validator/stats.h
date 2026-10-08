#ifndef SRC_STATS_H_
#define SRC_STATS_H_

struct stats_gauge;
extern struct stats_gauge *stat_rtr_ready;
extern struct stats_gauge *stat_rtr_connections;

int stats_setup(void);
void stats_teardown(void);

void stats_gauge_set(struct stats_gauge *, unsigned int);
void stats_set_tal_vrps(char const *, char const *, unsigned int);

char *stats_export(void);

#endif /* SRC_STATS_H_ */
