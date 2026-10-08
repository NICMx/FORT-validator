#ifndef VALIDATOR_CONFIG_H_
#define VALIDATOR_CONFIG_H_

#include <curl/curl.h>

#include "common/common.h"
#include "common/config/file_type.h"
#include "common/config/log_conf.h"
#include "common/config/output_format.h"
#include "common/report.h"
#include "validator/object/tal.h"

/*
 * To add a member to this structure,
 *
 * 1. Add it.
 * 2. Add its metadata somewhere in @options.
 * 3. Add default value to set_default_values().
 * 4. Create the getter.
 *
 * Assuming you don't need to create a data type, that should be all.
 */
struct fort_config {
	/* TAL file name or directory. */
	char *tal;
	/* Local cache path */
	char *cache;
	/* File or directory where the .slurm file(s) is(are) located */
	char *slurm;

	/* Run as a daemon? */
	bool daemon;

	/* Number of iterations the deltas will be stored. */
	unsigned int deltas_lifetime;

	/*
	 * Number of seconds to wait between validation cycles
	 * 0 = disabled
	 */
	unsigned int validation_interval;

	unsigned int prometheus_port;

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
	unsigned int validation_threads;

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

init_verdict handle_flags_config(int, char **);

/* Needed public by the JSON module */
struct option_field const *get_option_metadatas(void);

#endif /* VALIDATOR_CONFIG_H_ */
