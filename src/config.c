#include "config.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <sys/socket.h>
#include <syslog.h>

#include "common.h"
#include "configure_ac.h"
#include "daemon.h"
#include "file.h"
#include "init.h"
#include "json_handler.h"
#include "log.h"
#include "config/boolean.h"
#include "config/incidences.h"
#include "config/init_tals.h"
#include "config/rrdp_conf.h"
#include "config/str.h"
#include "config/sync_strategy.h"
#include "config/uint.h"
#include "config/uint32.h"
#include "config/work_offline.h"

/**
 * To add a member to this structure,
 *
 * 1. Add it.
 * 2. Add its metadata somewhere in @groups.
 * 3. Add default value to set_default_values().
 * 4. Create the getter.
 *
 * Assuming you don't need to create a data type, that should be all.
 */
struct rpki_config {
	/** TAL file name or directory. */
	char *tal;
	/** Path of our local clone of the repository */
	char *local_repository;
	/** TODO (later) Deprecated, remove it. RSYNC download strategy. */
	enum rsync_strategy sync_strategy;
	/**
	 * Handle TAL URIs in random order?
	 * (https://tools.ietf.org/html/rfc8630#section-3, last
	 * paragraphs)
	 */
	bool shuffle_tal_uris;
	/**
	 * rfc6487#section-7.2, last paragraph.
	 * Prevents arbitrarily long paths and loops.
	 */
	unsigned int maximum_certificate_depth;
	/** File or directory where the .slurm file(s) is(are) located */
	char *slurm;
	/* Run as RTR server or standalone validation */
	enum mode mode;
	/*
	 * Disable outgoing requests (currently rsync and http supported), if
	 * 'true' uses only local files located at local-repository.
	 */
	bool work_offline;
	/*
	 * Run fort as a daemon.
	 */
	bool daemon;

	struct {
		/** The bound listening address of the RTR server. */
		struct string_array address;
		/** The bound listening port of the RTR server. */
		char *port;
		/** Outstanding connections in the socket's listen queue */
		unsigned int backlog;
		struct {
			/** Interval used to look for updates at VRPs location */
			unsigned int validation;
			unsigned int refresh;
			unsigned int retry;
			unsigned int expire;
		} interval;
		/** Number of iterations the deltas will be stored. */
		unsigned int deltas_lifetime;
	} server;

	struct {
		/* Enables the protocol */
		bool enabled;
		/*
		 * Priority, this will override the order set at the CAs in
		 * their accessMethod extension.
		 */
		unsigned int priority;
		/* Synchronization download strategy. */
		enum rsync_strategy strategy;
		/* Retry conf, utilized on errors */
		struct {
			/* Maximum number of retries on error */
			unsigned int count;
			/* Interval (in seconds) between each retry */
			unsigned int interval;
		} retry;
		char *program;
		struct {
			struct string_array flat;
			struct string_array recursive;
		} args;
	} rsync;

	struct {
		/* Enables the protocol */
		bool enabled;
		/*
		 * Priority, this will override the order set at the CAs in
		 * their accessMethod extension.
		 */
		unsigned int priority;
		/* Retry conf, utilized on errors */
		struct {
			/* Maximum number of retries on error */
			unsigned int count;
			/* Interval (in seconds) between each retry */
			unsigned int interval;
		} retry;
	} rrdp;

	struct {
		/* Enables the protocol */
		bool enabled;
		/*
		 * Priority, whenever there's an option to sync something via
		 * http or rsync, use this priority. When working with CAs, this
		 * will override the order set at the CAs in their accessMethod
		 * extension.
		 */
		unsigned int priority;
		/* Retry conf, utilized on errors */
		struct {
			/* Maximum number of retries on error */
			unsigned int count;
			/* Interval (in seconds) between each retry */
			unsigned int interval;
		} retry;
		/* User-Agent header set at requests */
		char *user_agent;
		/* CURLOPT_CONNECTTIMEOUT for our HTTP transfers. */
		unsigned int connect_timeout;
		/* CURLOPT_TIMEOUT for our HTTP transfers. */
		unsigned int transfer_timeout;
		/* CURLOPT_LOW_SPEED_LIMIT for our HTTP transfers. */
		unsigned int low_speed_limit;
		/* CURLOPT_LOW_SPEED_TIME for our HTTP transfers. */
		unsigned int low_speed_time;
		/*
		 * CURLOPT_MAXFILESIZE, except it also works for unknown size
		 * files. (Though this is reactive, not preventive.)
		 */
		unsigned int max_file_size;
		/* Directory where CA certs to verify peers are found */
		char *ca_path;
	} http;

	struct {
		/** Enables operation logs **/
		bool enabled;
		/** String tag to identify operation logs **/
		char *tag;
		/** Print ANSI color codes? */
		bool color;
		/** Format in which file names will be printed. */
		enum filename_format filename_format;
		/* Log level */
		uint8_t level;
		/* Log output */
		enum log_output output;
		/** facility for syslog if output is syslog **/
		uint32_t facility;
	} log;

	struct {
		/** Enables validation Logs **/
		bool enabled;
		/** String tag to identify validation logs **/
		char *tag;
		/** Print ANSI color codes? */
		bool color;
		/** Format in which file names will be printed. */
		enum filename_format filename_format;
		/* Log level */
		uint8_t level;
		/* Log output */
		enum log_output output;
		/** facilities for syslog if output is syslog **/
		uint32_t facility;
	} validation_log;

	struct {
		/** File where the validated ROAs will be stored */
		char *roa;
		/** File where the validated BGPsec certs will be stored */
		char *bgpsec;
		/** Format for the output */
		enum output_format format;
	} output;

	/* ASN1 decoder max stack size allowed */
	unsigned int asn1_decode_max_stack;

	/* Time period that must lapse to warn about a stale repository */
	unsigned int stale_repository_period;

	/* Download the normal TALs into --tal? */
	bool init_tals;
	/* Download AS0 TALs into --tal? */
	bool init_tal0s;
	/* Deprecated; currently does nothing. */
	unsigned int init_tal_locations;

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
};

static void print_usage(FILE *, bool);

#define DECLARE_HANDLE_FN(name)						\
	static int name(						\
	    struct option_field const *,				\
	    char *							\
	)
DECLARE_HANDLE_FN(handle_help);
DECLARE_HANDLE_FN(handle_usage);
DECLARE_HANDLE_FN(handle_version);
DECLARE_HANDLE_FN(handle_json);

static char const *program_name;
static struct rpki_config rpki_config;

/**
 * An ARGP option that takes no arguments, is not correlated to any rpki_config
 * fields, and is entirely managed by its handler function.
 */
static const struct global_type gt_callback = {
	.has_arg = no_argument,
};

static const struct option_field options[] = {

	/* ARGP-only, non-fields */
	{
		.id = 'h',
		.name = "help",
		.type = &gt_callback,
		.handler = handle_help,
		.doc = "Give this help list",
		.availability = AVAILABILITY_GETOPT,
	}, {
		.id = 1000,
		.name = "usage",
		.type = &gt_callback,
		.handler = handle_usage,
		.doc = "Give a short usage message",
		.availability = AVAILABILITY_GETOPT,
	}, {
		.id = 'V',
		.name = "version",
		.type = &gt_callback,
		.handler = handle_version,
		.doc = "Print program version",
		.availability = AVAILABILITY_GETOPT,
	}, {
		.id = 'f',
		.name = "configuration-file",
		.type = &gt_string,
		.handler = handle_json,
		.doc = "JSON file additional configuration will be read from",
		.arg_doc = "<file>",
		.availability = AVAILABILITY_GETOPT,
	},

	/* Root fields */
	{
		.id = 't',
		.name = "tal",
		.type = &gt_string,
		.offset = offsetof(struct rpki_config, tal),
		.doc = "Path to the TAL file or TALs directory",
		.arg_doc = "<file>|<directory>",
	}, {
		.id = 'r',
		.name = "local-repository",
		.type = &gt_string,
		.offset = offsetof(struct rpki_config, local_repository),
		.doc = "Directory where the repository local cache will be stored/read",
		.arg_doc = "<directory>",
	}, {
		.id = 1001,
		.name = "sync-strategy",
		.type = &gt_sync_strategy,
		.offset = offsetof(struct rpki_config, sync_strategy),
		.doc = "RSYNC download strategy. Will be deprecated, use 'rsync.strategy' instead.",
	}, {
		.id = 2001,
		.name = "shuffle-uris",
		.type = &gt_bool,
		.offset = offsetof(struct rpki_config, shuffle_tal_uris),
		.doc = "Shuffle URIs in the TAL before accessing them",
	}, {
		.id = 1002,
		.name = "maximum-certificate-depth",
		.type = &gt_uint,
		.offset = offsetof(struct rpki_config,
		    maximum_certificate_depth),
		.doc = "Maximum allowable certificate chain length",
		.min = 5,
		/**
		 * It cannot be UINT_MAX, because then the actual number will
		 * overflow and will never be bigger than this.
		 */
		.max = UINT_MAX - 1,
	}, {
		.id = 1003,
		.name = "slurm",
		.type = &gt_string,
		.offset = offsetof(struct rpki_config, slurm),
		.doc = "Path to the SLURM file or SLURMs directory (files must have the extension .slurm)",
		.arg_doc = "<file>|<directory>"
	}, {
		.id = 1004,
		.name = "mode",
		.type = &gt_mode,
		.offset = offsetof(struct rpki_config, mode),
		.doc = "Run mode: 'server' (run as RTR server), 'standalone' (run validation once and exit)",
	}, {
		.id = 1005,
		.name = "work-offline",
		.type = &gt_work_offline,
		.offset = offsetof(struct rpki_config, work_offline),
		.doc = "Disable all outgoing requests (rsync, http (implies RRDP)) and work only with local repository files.",
	}, {
		.id = 1006,
		.name = "daemon",
		.type = &gt_bool,
		.offset = offsetof(struct rpki_config, daemon),
		.doc = "Run fort as a daemon.",
	},

	/* Server fields */
	{
		.id = 5000,
		.name = "server.address",
		.type = &gt_string_array,
		.offset = offsetof(struct rpki_config, server.address),
		.doc = "List of addresses (comma separated) to which RTR server will bind itself to. Can be a name, in which case an address will be resolved. The format for each address is '<address>[#<port/service>]'.",
		.min = 0,
		.max = 50,
	}, {
		.id = 5001,
		.name = "server.port",
		.type = &gt_string,
		.offset = offsetof(struct rpki_config, server.port),
		.doc = "Default port to which RTR server addresses will bind itself to. Can be a string, in which case a number will be resolved. If all of the addresses have a port, this value isn't utilized.",
	}, {
		.id = 5002,
		.name = "server.backlog",
		.type = &gt_uint,
		.offset = offsetof(struct rpki_config, server.backlog),
		.doc = "Maximum connections in the socket's listen queue",
		.min = 1,
		.max = SOMAXCONN,
	}, {
		.id = 5003,
		.name = "server.interval.validation",
		.type = &gt_uint,
		.offset = offsetof(struct rpki_config,
		    server.interval.validation),
		.doc = "Interval used to look for updates at VRPs location",
		/*
		 * RFC 6810 and 8210:
		 * "The cache MUST rate-limit Serial Notifies to no more
		 * frequently than one per minute."
		 * We do this by not getting new information more than once per
		 * minute.
		 */
		.min = 60,
		.max = UINT_MAX,
	}, {
		.id = 5004,
		.name = "server.interval.refresh",
		.type = &gt_uint,
		.offset = offsetof(struct rpki_config,
		    server.interval.refresh),
		.doc = "Interval between normal cache polls",
		/*
		 * RFC 8210: "Interval between normal cache polls".
		 * Min, max, and default values taken from RFC 8210 section 6.
		 *
		 * RFC mentions "router SHOULD NOT poll the cache sooner than
		 * indicated by this parameter", but what if this is ignored by
		 * the router? There's no proper error message to notice the
		 * client about its error without dropping the connection (I
		 * don't think that 'No Data Available' is the right option).
		 *
		 * So, let the operator configure this option hoping that
		 * clients honor the interval.
		 */
		.min = 1,
		.max = 86400,
	}, {
		.id = 5005,
		.name = "server.interval.retry",
		.type = &gt_uint,
		.offset = offsetof(struct rpki_config,
		    server.interval.retry),
		.doc = "Interval between cache poll retries after a failed cache poll",
		/*
		 * RFC 8210: "Interval between cache poll retries after a
		 * failed cache poll"
		 * Min, max, and default values taken from RFC 8210 section 6.
		 */
		.min = 1,
		.max = 7200,
	}, {
		.id = 5006,
		.name = "server.interval.expire",
		.type = &gt_uint,
		.offset = offsetof(struct rpki_config,
		    server.interval.expire),
		.doc = "Interval during which data fetched from a cache remains valid in the absence of a successful subsequent cache poll",
		/*
		 * RFC 8210: "Interval during which data fetched from a cache
		 * remains valid in the absence of a successful subsequent
		 * cache poll"
		 * Min, max, and default values taken from RFC 8210 section 6.
		 */
		.min = 600,
		.max = 172800,
	}, {
		.id = 5007,
		.name = "server.deltas.lifetime",
		.type = &gt_uint,
		.offset = offsetof(struct rpki_config, server.deltas_lifetime),
		.doc = "Number of iterations the deltas will be stored.",
		.min = 0,
		.max = UINT_MAX,
	},

	/* RSYNC fields */
	{
		.id = 3000,
		.name = "rsync.enabled",
		.type = &gt_bool,
		.offset = offsetof(struct rpki_config, rsync.enabled),
		.doc = "Enables RSYNC execution",
	}, {
		.id = 3001,
		.name = "rsync.priority",
		.type = &gt_uint32,
		.offset = offsetof(struct rpki_config, rsync.priority),
		.doc = "Priority of execution to fetch repositories files, a higher value means higher priority",
		.min = 0,
		.max = 100,
	},{
		.id = 3002,
		.name = "rsync.strategy",
		.type = &gt_rsync_strategy,
		.offset = offsetof(struct rpki_config, rsync.strategy),
		.doc = "RSYNC download strategy",
	}, {
		.id = 3003,
		.name = "rsync.retry.count",
		.type = &gt_uint,
		.offset = offsetof(struct rpki_config, rsync.retry.count),
		.doc = "Maximum amount of retries whenever there's an RSYNC error",
		.min = 0,
		.max = UINT_MAX,
	}, {
		.id = 3004,
		.name = "rsync.retry.interval",
		.type = &gt_uint,
		.offset = offsetof(struct rpki_config, rsync.retry.interval),
		.doc = "Period (in seconds) to wait between retries after an RSYNC error ocurred",
		.min = 0,
		.max = UINT_MAX,
	},{
		.id = 3005,
		.name = "rsync.program",
		.type = &gt_string,
		.offset = offsetof(struct rpki_config, rsync.program),
		.doc = "Name of the program needed to execute an RSYNC",
		.arg_doc = "<path to program>",
		.availability = AVAILABILITY_JSON,
	}, {
		.id = 3006,
		.name = "rsync.arguments-recursive",
		.type = &gt_string_array,
		.offset = offsetof(struct rpki_config, rsync.args.recursive),
		.doc = "RSYNC program arguments that will trigger a recursive RSYNC",
		.availability = AVAILABILITY_JSON,
		/* Unlimited */
		.max = 0,
	}, {
		.id = 3007,
		.name = "rsync.arguments-flat",
		.type = &gt_string_array,
		.offset = offsetof(struct rpki_config, rsync.args.flat),
		.doc = "RSYNC program arguments that will trigger a non-recursive RSYNC",
		.availability = AVAILABILITY_JSON,
		/* Unlimited */
		.max = 0,
	},

	/* RRDP fields */
	{
		.id = 10000,
		.name = "rrdp.enabled",
		.type = &gt_rrdp_enabled,
		.offset = offsetof(struct rpki_config, rrdp.enabled),
		.doc = "Enables RRDP execution. Will be deprecated, use 'http.enabled' instead.",
	}, {
		.id = 10001,
		.name = "rrdp.priority",
		.type = &gt_rrdp_priority,
		.offset = offsetof(struct rpki_config, rrdp.priority),
		.doc = "Priority of execution to fetch repositories files, a higher value means higher priority. Will be deprecated, use 'http.priority' instead.",
		.min = 0,
		.max = 100,
	}, {
		.id = 10002,
		.name = "rrdp.retry.count",
		.type = &gt_rrdp_retry_count,
		.offset = offsetof(struct rpki_config, rrdp.retry.count),
		.doc = "Maximum amount of retries whenever there's an error fetching RRDP files. Will be deprecated, use 'http.retry.count' instead.",
		.min = 0,
		.max = UINT_MAX,
	}, {
		.id = 10003,
		.name = "rrdp.retry.interval",
		.type = &gt_rrdp_retry_interval,
		.offset = offsetof(struct rpki_config, rrdp.retry.interval),
		.doc = "Period (in seconds) to wait between retries after an error ocurred fetching RRDP files. Will be deprecated, use 'http.retry.interval' instead.",
		.min = 0,
		.max = UINT_MAX,
	},

	/* HTTP requests parameters */
	{
		.id = 9000,
		.name = "http.enabled",
		.type = &gt_rrdp_enabled,
		.offset = offsetof(struct rpki_config, http.enabled),
		.doc = "Enables outgoing HTTP requests",
	},
	{
		.id = 9001,
		.name = "http.priority",
		.type = &gt_rrdp_priority,
		.offset = offsetof(struct rpki_config, http.priority),
		.doc = "Priority of execution to fetch repositories files, a higher value means higher priority",
		.min = 0,
		.max = 100,
	},
	{
		.id = 9002,
		.name = "http.retry.count",
		.type = &gt_rrdp_retry_count,
		.offset = offsetof(struct rpki_config, http.retry.count),
		.doc = "Maximum amount of retries whenever there's an error requesting HTTP URIs",
		.min = 0,
		.max = UINT_MAX,
	},
	{
		.id = 9003,
		.name = "http.retry.interval",
		.type = &gt_rrdp_retry_interval,
		.offset = offsetof(struct rpki_config, http.retry.interval),
		.doc = "Period (in seconds) to wait between retries after an error ocurred doing HTTP requests",
		.min = 0,
		.max = UINT_MAX,
	},
	{
		.id = 9004,
		.name = "http.user-agent",
		.type = &gt_string,
		.offset = offsetof(struct rpki_config, http.user_agent),
		.doc = "User-Agent to use at HTTP requests, eg. Fort Validator Local/1.0",
	},
	{
		.id = 9005,
		.name = "http.connect-timeout",
		.type = &gt_uint,
		.offset = offsetof(struct rpki_config, http.connect_timeout),
		.doc = "Timeout for the connect phase",
		.min = 1,
		.max = UINT_MAX,
	},
	{
		.id = 9006,
		.name = "http.transfer-timeout",
		.type = &gt_uint,
		.offset = offsetof(struct rpki_config, http.transfer_timeout),
		.doc = "Maximum transfer time (once the connection is established) before dropping the connection",
		.min = 0,
		.max = UINT_MAX,
	},
	{
		.id = 9007,
		.name = "http.idle-timeout", /* TODO DEPRECATED. */
		.type = &gt_uint,
		.offset = offsetof(struct rpki_config, http.low_speed_time),
		.doc = "Deprecated; currently an alias for --http.low-speed-time. Use --http.low-speed-time instead.",
		.min = 0,
		.max = UINT_MAX,
	},
	{
		.id = 9009,
		.name = "http.low-speed-limit",
		.type = &gt_uint,
		.offset = offsetof(struct rpki_config, http.low_speed_limit),
		.doc = "Average transfer speed (in bytes per second) that the transfer should be below during --http.low-speed-time seconds for Fort to consider it to be too slow. (Slow connections are dropped.)",
		.min = 0,
		.max = UINT_MAX,
	},
	{
		.id = 9010,
		.name = "http.low-speed-time",
		.type = &gt_uint,
		.offset = offsetof(struct rpki_config, http.low_speed_time),
		.doc = "Seconds that the transfer speed should be below --http.low-speed-limit for the Fort to consider it too slow. (Slow connections are dropped.)",
		.min = 0,
		.max = UINT_MAX,
	},
	{
		.id = 9011,
		.name = "http.max-file-size",
		.type = &gt_uint,
		.offset = offsetof(struct rpki_config, http.max_file_size),
		.doc = "Fort will refuse to download files larger than this number of bytes.",
		.min = 0,
		.max = 2000000000,
	},
	{
		.id = 9008,
		.name = "http.ca-path",
		.type = &gt_string,
		.offset = offsetof(struct rpki_config, http.ca_path),
		.doc = "Directory where CA certificates are found, used to verify the peer",
		.arg_doc = "<directory>",
	},

	/* Logging fields */
	{
		.id = 4000,
		.name = "log.enabled",
		.type = &gt_bool,
		.offset = offsetof(struct rpki_config, log.enabled),
		.doc = "Enables operation logs",
	}, {
		.id = 4001,
		.name = "log.output",
		.type = &gt_log_output,
		.offset = offsetof(struct rpki_config, log.output),
		.doc = "Output where operation log messages will be printed",
	}, {
		.id = 4002,
		.name = "log.level",
		.type = &gt_log_level,
		.offset = offsetof(struct rpki_config, log.level),
		.doc = "Log level to print message of equal or higher importance",
	}, {
		.id = 4003,
		.name = "log.tag",
		.type = &gt_string,
		.offset = offsetof(struct rpki_config, log.tag),
		.doc = "Text tag to identify operation logs",
		.arg_doc = "<string>",
	}, {
		.id = 4004,
		.name = "log.facility",
		.type = &gt_log_facility,
		.offset = offsetof(struct rpki_config, log.facility),
		.doc = "Facility for syslog if output is syslog",
	}, {
		.id = 4005,
		.name = "log.file-name-format",
		.type = &gt_filename_format,
		.offset = offsetof(struct rpki_config, log.filename_format),
		.doc = "File name variant to print during debug/error messages",
	}, {
		.id = 'c',
		.name = "log.color-output",
		.type = &gt_bool,
		.offset = offsetof(struct rpki_config, log.color),
		.doc = "Print ANSI color codes",
	},

	{
		.id = 4010,
		.name = "validation-log.enabled",
		.type = &gt_bool,
		.offset = offsetof(struct rpki_config, validation_log.enabled),
		.doc = "Enables validation logs",
	}, {
		.id = 4011,
		.name = "validation-log.output",
		.type = &gt_log_output,
		.offset = offsetof(struct rpki_config, validation_log.output),
		.doc = "Output where validation log messages will be printed",
	}, {
		.id = 4012,
		.name = "validation-log.level",
		.type = &gt_log_level,
		.offset = offsetof(struct rpki_config, validation_log.level),
		.doc = "Log level to print message of equal or higher importance",
	}, {
		.id = 4013,
		.name = "validation-log.tag",
		.type = &gt_string,
		.offset = offsetof(struct rpki_config, validation_log.tag),
		.doc = "Text tag to identify validation logs",
		.arg_doc = "<string>",
	}, {
		.id = 4014,
		.name = "validation-log.facility",
		.type = &gt_log_facility,
		.offset = offsetof(struct rpki_config, validation_log.facility),
		.doc = "Facility for syslog if output is syslog",
	}, {
		.id = 4015,
		.name = "validation-log.file-name-format",
		.type = &gt_filename_format,
		.offset = offsetof(struct rpki_config,
		    validation_log.filename_format),
		.doc = "File name variant to print during debug/error messages",
	}, {
		.id = 4016,
		.name = "validation-log.color-output",
		.type = &gt_bool,
		.offset = offsetof(struct rpki_config, validation_log.color),
		.doc = "Print ANSI color codes",
	},

	/* Incidences */
	{
		.id = 7001,
		.name = "incidences",
		.type = &gt_incidences,
		.doc = "Override actions on validation errors",
		.availability = AVAILABILITY_JSON,
	},

	/* Output files */
	{
		.id = 6000,
		.name = "output.roa",
		.type = &gt_string,
		.offset = offsetof(struct rpki_config, output.roa),
		.doc = "File where ROAs will be stored, use '-' to print at console",
		.arg_doc = "<file>",
	}, {
		.id = 6001,
		.name = "output.bgpsec",
		.type = &gt_string,
		.offset = offsetof(struct rpki_config, output.bgpsec),
		.doc = "File where BGPsec Router Keys will be stored, use '-' to print at console",
		.arg_doc = "<file>",
	}, {
		.id = 6002,
		.name = "output.format",
		.type = &gt_output_format,
		.offset = offsetof(struct rpki_config, output.format),
		.doc = "Format to print ROAs and BGPsec Router Keys",
	},

	{
		.id = 8000,
		.name = "asn1-decode-max-stack",
		.type = &gt_uint,
		.offset = offsetof(struct rpki_config, asn1_decode_max_stack),
		.doc = "ASN1 decoder max stack size, utilized to avoid a stack overflow on large nested ASN1 objects",
		.min = 1,
		.max = UINT_MAX,
	},
	{
		.id = 8001,
		.name = "stale-repository-period",
		.type = &gt_uint,
		.offset = offsetof(struct rpki_config, stale_repository_period),
		.doc = "Time period that must lapse to warn about stale repositories",
		.min = 0,
		.max = UINT_MAX,
	},

	{
		.id = 11000,
		.name = "init-tals",
		.type = &gt_bool,
		.offset = offsetof(struct rpki_config, init_tals),
		.doc = "Fetch the currently-known TAL files into --tal",
		.availability = AVAILABILITY_GETOPT,
	}, {
		.id = 11002,
		.name = "init-as0-tals",
		.type = &gt_bool,
		.offset = offsetof(struct rpki_config, init_tal0s),
		.doc = "Fetch the currently-known AS0 TAL files into --tal",
		.availability = AVAILABILITY_GETOPT,
	}, {
		.id = 11001,
		.name = "init-locations",
		.type = &gt_init_tals_locations,
		.offset = offsetof(struct rpki_config, init_tal_locations),
		.doc = "Deprecated. Does nothing as of Fort 1.5.1.",
		.availability = AVAILABILITY_JSON,
	},

	{
		.id = 12000,
		.name = "thread-pool.server.max",
		.type = &gt_uint,
		.offset = offsetof(struct rpki_config, thread_pool.server.max),
		.doc = "Number of threads in the RTR client request thread pool. Also known as the maximum number of client requests the RTR server will be able to handle at the same time.",
		.min = 1,
		.max = UINT_MAX,
	},
	{
		.id = 12001,
		.name = "thread-pool.validation.max",
		.type = &gt_uint,
		.offset = offsetof(struct rpki_config,
		    thread_pool.validation.max),
		.doc = "Number of threads in the validation thread pool. (Each thread handles one TAL tree.)",
		.min = 0,
		.max = 100,
	},

	{ 0 },
};

/**
 * Returns true if @field is the descriptor of one of the members of the
 * struct rpki_config structure, false otherwise.
 * (Alternatively: Returns true if @field->offset is valid, false otherwise.)
 */
static bool
is_rpki_config_field(struct option_field const *field)
{
	return field->handler == NULL;
}

void *
get_rpki_config_field(struct option_field const *field)
{
	return ((unsigned char *) &rpki_config) + field->offset;
}

static int
handle_help(struct option_field const *field, char *arg)
{
	print_usage(stdout, true);
	exit(0);
}

static int
handle_usage(struct option_field const *field, char *arg)
{
	print_usage(stdout, false);
	exit(0);
}

static int
handle_version(struct option_field const *field, char *arg)
{
	printf(PACKAGE_STRING "\n");
	exit(0);
}

static int
handle_json(struct option_field const *field, char *file_name)
{
	return set_config_from_file(file_name);
}

static bool
is_alphanumeric(int chara)
{
	return ('a' <= chara && chara <= 'z')
	    || ('A' <= chara && chara <= 'Z')
	    || ('0' <= chara && chara <= '9');
}

/**
 * "struct option" is the array that getopt expects.
 * "struct args_flag" is our option metadata.
 */
static int
construct_getopt_options(struct option **_long_opts, char **_short_opts)
{
	struct option_field const *opt;
	struct option *long_opts;
	char *short_opts;
	unsigned int total_long_options;
	unsigned int total_short_options;

	total_long_options = 0;
	total_short_options = 0;
	FOREACH_OPTION(options, opt, AVAILABILITY_GETOPT) {
		total_long_options++;
		if (is_alphanumeric(opt->id)) {
			total_short_options++;
			if (opt->type->has_arg != no_argument)
				total_short_options++; /* ":" */
		}
	}

	/* +1 NULL end, means end of array. */
	long_opts = calloc(total_long_options + 1, sizeof(struct option));
	if (long_opts == NULL)
		return pr_enomem();
	short_opts = malloc(total_short_options + 1);
	if (short_opts == NULL) {
		free(long_opts);
		return pr_enomem();
	}

	*_long_opts = long_opts;
	*_short_opts = short_opts;

	FOREACH_OPTION(options, opt, AVAILABILITY_GETOPT) {
		long_opts->name = opt->name;
		long_opts->has_arg = opt->type->has_arg;
		long_opts->flag = NULL;
		long_opts->val = opt->id;
		long_opts++;

		if (is_alphanumeric(opt->id)) {
			*short_opts = opt->id;
			short_opts++;
			if (opt->type->has_arg != no_argument) {
				*short_opts = ':';
				short_opts++;
			}
		}
	}

	*short_opts = '\0';
	return 0;
}

static void
print_config(void)
{
	struct option_field const *opt;

	pr_op_info(PACKAGE_STRING);
	pr_op_info("Configuration {");

	FOREACH_OPTION(options, opt, 0xFFFF)
		if (is_rpki_config_field(opt) && opt->type->print != NULL)
			opt->type->print(opt, get_rpki_config_field(opt));

	pr_op_info("}");
}

static int
set_default_values(void)
{
	static char const *recursive_rsync_args[] = {
		"--recursive",
		"--delete",
		"--times",
		"--contimeout=20",
		"--timeout=15",
		"$REMOTE",
		"$LOCAL",
	};

	static char const *flat_rsync_args[] = {
		"--times",
		"--contimeout=20",
		"--timeout=15",
		"--dirs",
		"$REMOTE",
		"$LOCAL",
	};

	int error;

	/*
	 * Values that might need to be freed WILL be freed, so use heap
	 * duplicates.
	 */

	error = string_array_init(&rpki_config.server.address, NULL, 0);
	if (error)
		return error;

	rpki_config.server.port = strdup("323");
	if (rpki_config.server.port == NULL) {
		error = pr_enomem();
		goto revert_address;
	}

	rpki_config.server.backlog = SOMAXCONN;
	rpki_config.server.interval.validation = 3600;
	rpki_config.server.interval.refresh = 3600;
	rpki_config.server.interval.retry = 600;
	rpki_config.server.interval.expire = 7200;
	rpki_config.server.deltas_lifetime = 2;

	rpki_config.tal = NULL;
	rpki_config.slurm = NULL;

	rpki_config.local_repository = strdup("/tmp/fort/repository");
	if (rpki_config.local_repository == NULL) {
		error = pr_enomem();
		goto revert_port;
	}

	rpki_config.sync_strategy = RSYNC_ROOT_EXCEPT_TA;
	rpki_config.shuffle_tal_uris = false;
	rpki_config.maximum_certificate_depth = 32;
	rpki_config.mode = SERVER;
	rpki_config.work_offline = false;
	rpki_config.daemon = false;

	rpki_config.rsync.enabled = true;
	rpki_config.rsync.priority = 50;
	rpki_config.rsync.strategy = RSYNC_ROOT_EXCEPT_TA;
	rpki_config.rsync.retry.count = 2;
	rpki_config.rsync.retry.interval = 5;
	rpki_config.rsync.program = strdup("rsync");
	if (rpki_config.rsync.program == NULL) {
		error = pr_enomem();
		goto revert_repository;
	}

	error = string_array_init(&rpki_config.rsync.args.recursive,
	    recursive_rsync_args, ARRAY_LEN(recursive_rsync_args));
	if (error)
		goto revert_rsync_program;

	error = string_array_init(&rpki_config.rsync.args.flat,
	    flat_rsync_args, ARRAY_LEN(flat_rsync_args));
	if (error)
		goto revert_recursive_array;

	/* By default, has a higher priority than rsync */
	rpki_config.http.enabled = true;
	rpki_config.http.priority = 60;
	rpki_config.http.retry.count = 2;
	rpki_config.http.retry.interval = 5;
	rpki_config.http.user_agent = strdup(PACKAGE_NAME "/" PACKAGE_VERSION);
	if (rpki_config.http.user_agent == NULL) {
		error = pr_enomem();
		goto revert_flat_array;
	}
	rpki_config.http.connect_timeout = 30;
	rpki_config.http.transfer_timeout = 0;
	rpki_config.http.low_speed_limit = 30;
	rpki_config.http.low_speed_time = 10;
	rpki_config.http.max_file_size = 10000000;
	rpki_config.http.ca_path = NULL; /* Use system default */

	/*
	 * TODO (later) Same values as http.*, delete when rrdp.* is fully
	 * deprecated
	 */
	rpki_config.rrdp.enabled = rpki_config.http.enabled;
	rpki_config.rrdp.priority = rpki_config.http.priority;
	rpki_config.rrdp.retry.count = rpki_config.http.retry.count;
	rpki_config.rrdp.retry.interval = rpki_config.http.retry.interval;

	rpki_config.log.color = false;
	rpki_config.log.filename_format = FNF_GLOBAL;
	rpki_config.log.level = LOG_WARNING;
	rpki_config.log.output = CONSOLE;

	rpki_config.log.enabled = true;
	rpki_config.log.output = CONSOLE;
	rpki_config.log.level = LOG_WARNING;
	rpki_config.log.color = false;
	rpki_config.log.filename_format = FNF_GLOBAL;
	rpki_config.log.facility = LOG_DAEMON;
	rpki_config.log.tag = NULL;

	rpki_config.validation_log.enabled = false;
	rpki_config.validation_log.output = CONSOLE;
	rpki_config.validation_log.level = LOG_WARNING;
	rpki_config.validation_log.color = false;
	rpki_config.validation_log.filename_format = FNF_GLOBAL;
	rpki_config.validation_log.facility = LOG_DAEMON;
	rpki_config.validation_log.tag = strdup("Validation");
	if (rpki_config.validation_log.tag == NULL) {
		error = pr_enomem();
		goto revert_validation_log_tag;
	}

	rpki_config.output.roa = NULL;
	rpki_config.output.bgpsec = NULL;
	rpki_config.output.format = OFM_CSV;

	rpki_config.asn1_decode_max_stack = 4096; /* 4kB */
	rpki_config.stale_repository_period = 43200; /* 12 hours */

	rpki_config.init_tals = false;
	rpki_config.init_tal_locations = 0;

	/* Common scenario is to connect 1 router or a couple of them */
	rpki_config.thread_pool.server.max = 20;
	/* Usually 5 TALs, let a few more available */
	rpki_config.thread_pool.validation.max = 5;

	return 0;

revert_validation_log_tag:
	free(rpki_config.http.user_agent);
revert_flat_array:
	string_array_cleanup(&rpki_config.rsync.args.flat);
revert_recursive_array:
	string_array_cleanup(&rpki_config.rsync.args.recursive);
revert_rsync_program:
	free(rpki_config.rsync.program);
revert_repository:
	free(rpki_config.local_repository);
revert_port:
	free(rpki_config.server.port);
revert_address:
	string_array_cleanup(&rpki_config.server.address);
	return error;
}

static bool
valid_output_file(char const *path)
{
	return strcmp(path, "-") == 0 || file_valid(path);
}

static int
validate_config(void)
{
	if (rpki_config.tal == NULL)
		return pr_op_err("The TAL(s) location (--tal) is mandatory.");

	/* A file location at --tal isn't valid when --init-tals is set */
	if (!valid_file_or_dir(rpki_config.tal, !rpki_config.init_tals, true,
	    __pr_op_err))
		return pr_op_err("Invalid TAL(s) location.");

	/* Ignore the other checks */
	if (rpki_config.init_tals)
		return 0;

	if (rpki_config.server.interval.expire <
	    rpki_config.server.interval.refresh ||
	    rpki_config.server.interval.expire <
	    rpki_config.server.interval.retry)
		return pr_op_err("Expire interval must be greater than refresh and retry intervals");

	if (rpki_config.output.roa != NULL &&
	    !valid_output_file(rpki_config.output.roa))
		return pr_op_err("Invalid output.roa file.");

	if (rpki_config.output.bgpsec != NULL &&
	    !valid_output_file(rpki_config.output.bgpsec))
		return pr_op_err("Invalid output.bgpsec file.");

	if (rpki_config.slurm != NULL &&
	    !valid_file_or_dir(rpki_config.slurm, true, true, __pr_op_err))
		return pr_op_err("Invalid slurm location.");

	/* TODO (later) Remove when sync-strategy is fully deprecated */
	if (!rpki_config.rsync.enabled)
		config_set_sync_strategy(RSYNC_OFF);

	return 0;
}

static void
print_usage(FILE *stream, bool print_doc)
{
	struct option_field const *option;
	char const *arg_doc;

	fprintf(stream, "Usage: %s\n", program_name);
	FOREACH_OPTION(options, option, AVAILABILITY_GETOPT) {
		fprintf(stream, "\t[");
		fprintf(stream, "--%s", option->name);

		if (option->arg_doc != NULL)
			arg_doc = option->arg_doc;
		else if (option->type->arg_doc != NULL)
			arg_doc = option->type->arg_doc;
		else
			arg_doc = NULL;

		switch (option->type->has_arg) {
		case no_argument:
			break;
		case optional_argument:
		case required_argument:
			if (arg_doc != NULL)
				fprintf(stream, "=%s", arg_doc);
			break;
		}

		fprintf(stream, "]\n");

		if (print_doc)
			fprintf(stream, "\t    (%s)\n", option->doc);
	}
}


static int
handle_opt(int opt)
{
	struct option_field const *option;

	FOREACH_OPTION(options, option, AVAILABILITY_GETOPT) {
		if (option->id == opt) {
			return is_rpki_config_field(option)
			    ? option->type->parse.argv(option, optarg,
			          get_rpki_config_field(option))
			    : option->handler(option, optarg);
		}
	}

	pr_op_err("Unrecognized option: %d", opt);
	return -ESRCH;
}

int
handle_flags_config(int argc, char **argv)
{
	struct option *long_opts;
	char *short_opts;
	int opt;
	int error;

	program_name = argv[0];
	error = set_default_values();
	if (error)
		return error;

	long_opts = NULL;
	short_opts = NULL;
	error = construct_getopt_options(&long_opts, &short_opts);
	if (error)
		goto end; /* Error msg already printed. */

	while ((opt = getopt_long(argc, argv, short_opts, long_opts, NULL))
	    != -1) {
		error = handle_opt(opt);
		if (error)
			goto end;
	}

	/*
	 * This triggers when the user runs something like
	 * `rpki-validator disable-rsync` instead of
	 * `rpki-validator --disable-rsync`.
	 * This program does not have unflagged payload.
	 */
	if (optind < argc) {
		error = pr_op_err("I don't know what '%s' is.", argv[optind]);
		goto end;
	}

	error = validate_config();
	if (error)
		goto end;

	/* If present, nothing else is done */
	if (rpki_config.init_tals || rpki_config.init_tal0s) {
		if (rpki_config.init_tals)
			error = download_tals();
		if (!error && rpki_config.init_tal0s)
			error = download_tal0s();
		free(long_opts);
		free(short_opts);
		exit(error);
	}

	if (rpki_config.daemon) {
		pr_op_warn("Executing as daemon, all logs will be sent to syslog.");
		/* Send all logs to syslog */
		rpki_config.log.output = SYSLOG;
		rpki_config.validation_log.output = SYSLOG;
		error = daemonize(log_start);
		goto end;
	}

	log_start();
end:
	if (error) {
		free_rpki_config();
		pr_op_err("Try '%s --usage' or '%s --help' for more information.",
		    program_name, program_name);
	} else
		print_config();

	free(long_opts);
	free(short_opts);
	return error;

}

struct option_field const *
get_option_metadatas(void)
{
	return options;
}

enum mode
config_get_mode(void)
{
	return rpki_config.mode;
}

struct string_array const *
config_get_server_address(void)
{
	return &rpki_config.server.address;
}

char const *
config_get_server_port(void)
{
	return rpki_config.server.port;
}

int
config_get_server_queue(void)
{
	/* The range of this is 1-<small number>, so adding sign is safe. */
	return rpki_config.server.backlog;
}

unsigned int
config_get_validation_interval(void)
{
	return rpki_config.server.interval.validation;
}

unsigned int
config_get_interval_refresh(void)
{
	return rpki_config.server.interval.refresh;
}

unsigned int
config_get_interval_retry(void)
{
	return rpki_config.server.interval.retry;
}

unsigned int
config_get_interval_expire(void)
{
	return rpki_config.server.interval.expire;
}

unsigned int
config_get_deltas_lifetime(void)
{
	return rpki_config.server.deltas_lifetime;
}

char const *
config_get_slurm(void)
{
	return rpki_config.slurm;
}

char const *
config_get_tal(void)
{
	return rpki_config.tal;
}

char const *
config_get_local_repository(void)
{
	return rpki_config.local_repository;
}

bool
config_get_shuffle_tal_uris(void)
{
	return rpki_config.shuffle_tal_uris;
}

unsigned int
config_get_max_cert_depth(void)
{
	return rpki_config.maximum_certificate_depth;
}

bool
config_get_op_log_enabled(void)
{
	return rpki_config.log.enabled;
}

char const *
config_get_op_log_tag(void)
{
	return rpki_config.log.tag;
}

bool
config_get_op_log_color_output(void)
{
	return rpki_config.log.color;
}

enum filename_format
config_get_op_log_filename_format(void)
{
	return rpki_config.log.filename_format;
}

uint8_t
config_get_op_log_level(void)
{
	return rpki_config.log.level;
}

enum log_output
config_get_op_log_output(void)
{
	return rpki_config.log.output;
}

uint32_t
config_get_op_log_facility(void)
{
	return rpki_config.log.facility;
}

bool
config_get_val_log_enabled(void)
{
	return rpki_config.validation_log.enabled;
}

char const *
config_get_val_log_tag(void)
{
	return rpki_config.validation_log.tag;
}

bool
config_get_val_log_color_output(void)
{
	return rpki_config.validation_log.color;
}

enum filename_format
config_get_val_log_filename_format(void)
{
	return rpki_config.validation_log.filename_format;
}

uint8_t
config_get_val_log_level(void)
{
	return rpki_config.validation_log.level;
}

enum log_output
config_get_val_log_output(void)
{
	return rpki_config.validation_log.output;
}

uint32_t
config_get_val_log_facility(void)
{
	return rpki_config.validation_log.facility;
}

bool
config_get_rsync_enabled(void)
{
	return !rpki_config.work_offline && rpki_config.rsync.enabled;
}

unsigned int
config_get_rsync_priority(void)
{
	return rpki_config.rsync.priority;
}

enum rsync_strategy
config_get_rsync_strategy(void)
{
	return rpki_config.rsync.strategy;
}

unsigned int
config_get_rsync_retry_count(void)
{
	return rpki_config.rsync.retry.count;
}

unsigned int
config_get_rsync_retry_interval(void)
{
	return rpki_config.rsync.retry.interval;
}

char *
config_get_rsync_program(void)
{
	return rpki_config.rsync.program;
}

struct string_array const *
config_get_rsync_args(bool is_ta)
{
	switch (rpki_config.rsync.strategy) {
	case RSYNC_ROOT:
		return &rpki_config.rsync.args.recursive;
	case RSYNC_ROOT_EXCEPT_TA:
		return is_ta
		    ? &rpki_config.rsync.args.flat
		    : &rpki_config.rsync.args.recursive;
	case RSYNC_STRICT:
		return &rpki_config.rsync.args.flat;
	default:
		break;
	}

	pr_crit("Invalid rsync strategy: '%u'", rpki_config.rsync.strategy);
}

bool
config_get_http_enabled(void)
{
	return !rpki_config.work_offline && rpki_config.http.enabled;
}

unsigned int
config_get_http_priority(void)
{
	return rpki_config.http.priority;
}

unsigned int
config_get_http_retry_count(void)
{
	return rpki_config.http.retry.count;
}

unsigned int
config_get_http_retry_interval(void)
{
	return rpki_config.http.retry.interval;
}

char const *
config_get_http_user_agent(void)
{
	return rpki_config.http.user_agent;
}

long
config_get_http_connect_timeout(void)
{
	return rpki_config.http.connect_timeout;
}

long
config_get_http_transfer_timeout(void)
{
	return rpki_config.http.transfer_timeout;
}

long
config_get_http_low_speed_limit(void)
{
	return rpki_config.http.low_speed_limit;
}

long
config_get_http_low_speed_time(void)
{
	return rpki_config.http.low_speed_time;
}

long
config_get_http_max_file_size(void)
{
	return rpki_config.http.max_file_size;
}

char const *
config_get_http_ca_path(void)
{
	return rpki_config.http.ca_path;
}

char const *
config_get_output_roa(void)
{
	return rpki_config.output.roa;
}

char const *
config_get_output_bgpsec(void)
{
	return rpki_config.output.bgpsec;
}

enum output_format
config_get_output_format(void)
{
	return rpki_config.output.format;
}

unsigned int
config_get_asn1_decode_max_stack(void)
{
	return rpki_config.asn1_decode_max_stack;
}

unsigned int
config_get_stale_repository_period(void)
{
	return rpki_config.stale_repository_period;
}

unsigned int
config_get_thread_pool_server_max(void)
{
	return rpki_config.thread_pool.server.max;
}

unsigned int
config_get_thread_pool_validation_max(void)
{
	return rpki_config.thread_pool.validation.max;
}

void
config_set_rsync_enabled(bool value)
{
	rpki_config.rsync.enabled = value;
}

void
config_set_http_enabled(bool value)
{
	rpki_config.http.enabled = value;
}

void
free_rpki_config(void)
{
	struct option_field const *option;

	FOREACH_OPTION(options, option, 0xFFFF)
		if (is_rpki_config_field(option) && option->type->free != NULL)
			option->type->free(get_rpki_config_field(option));
}

/*
 * "To be deprecated" section
 */
void
config_set_rrdp_enabled(bool value)
{
	rpki_config.rrdp.enabled = value;
}

void
config_set_sync_strategy(enum rsync_strategy value)
{
	rpki_config.sync_strategy = value;
}

void
config_set_rsync_strategy(enum rsync_strategy value)
{
	rpki_config.rsync.strategy = value;
}

void
config_set_rrdp_priority(unsigned int value)
{
	rpki_config.rrdp.priority = value;
}

void
config_set_http_priority(unsigned int value)
{
	rpki_config.http.priority = value;
}

void
config_set_rrdp_retry_count(unsigned int value)
{
	rpki_config.rrdp.retry.count = value;
}

void
config_set_http_retry_count(unsigned int value)
{
	rpki_config.http.retry.count = value;
}

void
config_set_rrdp_retry_interval(unsigned int value)
{
	rpki_config.rrdp.retry.interval = value;
}

void
config_set_http_retry_interval(unsigned int value)
{
	rpki_config.http.retry.interval = value;
}
