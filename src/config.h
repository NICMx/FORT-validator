#ifndef SRC_CONFIG_H_
#define SRC_CONFIG_H_

#include <curl/curl.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "common.h"
#include "config/file_type.h"
#include "config/log_conf.h"
#include "config/mode.h"
#include "config/output_format.h"
#include "config/string_array.h"

/*
 * To add a member to this structure,
 *
 * 1. Add it.
 * 2. Add its metadata somewhere in @options.
 * 3. Add default value to set_default_values().
 *
 * Assuming you don't need to create a data type, that should be all.
 */
struct fort_config {
	/* */
	enum mode mode;
	/* Number of seconds to wait between cycles ("serve" mode only) */
	unsigned int interval;

	/* TAL file name or directory. */
	char *tal;
	/* Local cache path */
	char *cache;
	/* File or directory where the .slurm file(s) is(are) located */
	char *slurm;

	/* Run fort as a daemon? */
	bool daemon;

	struct {
		/* The bound listening address of the RTR server. */
		struct string_array address;
		/* The bound listening port of the RTR server. */
		char *port;
		/* Outstanding connections in the socket's listen queue */
		unsigned int backlog;
		/*
		 * Seconds the clients should retain data.
		 * Advertised through RTR EoD.
		 */
		unsigned int expire;
		/* Number of iterations the deltas will be stored. */
		unsigned int deltas_lifetime;

		unsigned int max_rtr_version;
	} rtr;

	struct {
		unsigned int port;
	} prometheus;

	struct {
		/* Enables the protocol */
		bool enabled;
		/* Maximum simultaneous rsyncs */
		unsigned int max;
		unsigned int timeout;
		char *program;
	} rsync;

	struct {
		/* Enables the protocol */
		bool enabled;
		/* HTTP User-Agent request header */
		char *user_agent;
		/* Allowed redirects per request XXX hardcode? */
		unsigned int max_redirs;
		/* CURLOPT_CONNECTTIMEOUT */
		unsigned int connect_timeout;
		/* CURLOPT_TIMEOUT */
		unsigned int transfer_timeout;
		/* CURLOPT_LOW_SPEED_LIMIT */
		unsigned int low_speed_limit;
		/* CURLOPT_LOW_SPEED_TIME */
		unsigned int low_speed_time;
		/* CURLOPT_MAXFILESIZE_LARGE */
		curl_off_t max_file_size;
		/* CURLOPT_CAPATH */
		char *ca_path;
		/* CURLOPT_PROXY */
		char *proxy;
	} http;

	struct {
		/*
		 * Maximum deltas to explode per RRDP session, per iteration.
		 *
		 * (If the RRDP notification lists more than this amount of
		 * unprocessed deltas, Fort will reset the session, exploding
		 * the snapshot instead.)
		 *
		 * Per draft-spaghetti-sidrops-rrdp-desynchronization's
		 * recommendation, this is also the maximum number of delta
		 * hashes Fort will remember per RRDP session, to detect session
		 * desynchronization.
		 *
		 * XXX hardcode?
		 */
		unsigned int delta_threshold;
	} rrdp;

	struct {
		/* Enables operation logs **/
		bool enabled;
		bool print_times;
		/* String tag to identify operation logs **/
		char *tag;
		/* Print ANSI color codes? */
		bool color;
		/* Log level */
		uint8_t level;
		/* Log output */
		enum log_output output;
		/* facility for syslog if output is syslog **/
		uint32_t facility;
	} log;

	struct {
		char *path;
	} report;

	struct {
		unsigned int max_providers; /* per customer */
	} aspa;

	struct {
		char *vrp_filepath;
		enum output_format vrp_format;

		char *bgpsec_filepath;
		enum output_format bgpsec_format;

		char *aspa_filepath;
	} output;

	/* Thread pools for specific tasks */
	struct {
		/* Threads related to RTR server */
		struct {
			unsigned int max;
		} server;
		/* Threads related to validation cycles */
		struct {
			unsigned int max;
		} validation;
	} thread_pool;

	enum file_type ft;
	char const *payload;

	struct {
		/*
		 * If nonzero, all RPKI object expiration dates are compared to
		 * this number instead of the current time.
		 * Meant for testing of repositories we don't want to have to
		 * keep regenerating.
		 */
		time_t validation_time;
	} debug;
};

extern struct fort_config fortcfg;

/* Init/destroy */
init_verdict handle_flags_config(int , char **);
void free_rpki_config(void);

#define MAX_ASPA_PROVIDERS 16380u /* Absolute maximum */

/* Needed public by the JSON module */
void *get_rpki_config_field(struct option_field const *);
struct option_field const *get_option_metadatas(void);

#endif /* SRC_CONFIG_H_ */
