#include "config.h"

#include <getopt.h>
#include <limits.h>
#include <microhttpd.h>
#include <openssl/opensslv.h>
#include <sys/socket.h>
#include <syslog.h>

#include "alloc.h"
#include "config/boolean.h"
#include "config/curl_offset.h"
#include "config/incidences.h"
#include "config/str.h"
#include "config/time.h"
#include "config/uint.h"
#include "configure_ac.h"
#include "daemon.h"
#include "file.h"
#include "json_handler.h"
#include "log.h"
#include "object/tal.h"
#include "types/array.h"
#include "types/path.h"

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
struct rpki_config {
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

/*
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
		.json_null_allowed = false,
	}, {
		.id = 'c',
		.name = "cache",
		.type = &gt_string,
		.offset = offsetof(struct rpki_config, cache),
		.doc = "Local cache directory",
		.arg_doc = "<directory>",
		.json_null_allowed = false,
	}, {
		.id = 1003,
		.name = "slurm",
		.type = &gt_string,
		.offset = offsetof(struct rpki_config, slurm),
		.doc = "Path to the SLURM file or SLURMs directory (files must have the extension .slurm)",
		.arg_doc = "<file>|<directory>",
		.json_null_allowed = true,
	}, {
		.id = 1004,
		.name = "mode",
		.type = &gt_mode,
		.offset = offsetof(struct rpki_config, mode),
		.doc = "Run mode: 'server' (run as RTR server), 'standalone' (run validation once and exit)",
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
		.offset = offsetof(struct rpki_config, rtr.address),
		.doc = "List of addresses (comma separated) to which RTR server will bind itself to. Can be a name, in which case an address will be resolved. The format for each address is '<address>[#<port/service>]'.",
		.min = 0,
		.max = 50,
	}, {
		.id = 5001,
		.name = "server.port",
		.type = &gt_service,
		.offset = offsetof(struct rpki_config, rtr.port),
		.doc = "Default port to which RTR server addresses will bind itself to. Can be a string, in which case a number will be resolved. If all of the addresses have a port, this value isn't utilized.",
		.json_null_allowed = false,
	}, {
		.id = 5002,
		.name = "server.backlog",
		.type = &gt_uint,
		.offset = offsetof(struct rpki_config, rtr.backlog),
		.doc = "Maximum connections in the socket's listen queue",
		.min = 1,
		.max = SOMAXCONN,
	}, {
		.id = 5003,
		.name = "server.interval.validation",
		.type = &gt_uint,
		.offset = offsetof(struct rpki_config, interval),
		.doc = "Interval used to look for updates at VRPs location",
		/*
		 * RFC 6810 and 8210:
		 * "The cache MUST rate-limit Serial Notifies to no more
		 * frequently than one per minute."
		 * We do this by not getting new information more than once per
		 * minute.
		 */
		.min = 60,
		/*
		 * 7 days.
		 * Must not overflow when multiplied by deltas.lifetime.
		 */
		.max = 604800,
	}, {
		.id = 5006,
		.name = "server.interval.expire",
		.type = &gt_uint,
		.offset = offsetof(struct rpki_config, rtr.expire),
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
		.offset = offsetof(struct rpki_config, rtr.deltas_lifetime),
		.doc = "Number of iterations the RTR deltas will be stored.",
		.min = 1,
		/*
		 * It's a serial, which means the technical maximum is about
		 * 2^31 - 1. But that's too much.
		 * Must not overflow when multiplied by interval.validation.
		 */
		.max = 1000,
	}, {
		.id = 5008,
		.name = "server.max-rtr-version",
		.type = &gt_uint,
		.offset = offsetof(struct rpki_config, rtr.max_rtr_version),
		.doc = "Maximum RTR version the server will be willing to negotiate with RTR clients",
		.min = 0,
		.max = 2,
	},

	/* Prometheus fields */
	{
		.id = 14000,
		.name = "prometheus.port",
		.type = &gt_uint,
		.offset = offsetof(struct rpki_config, prometheus.port),
		.doc = "Port to bind the Prometheus server to. "
		    "Prometheus requires this value and 'server' mode to start. "
		    "Unlike server.port, prometheus.port will not be resolved.",
		.min = 0,
		.max = 0xFFFF,
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
		.name = "rsync.max",
		.type = &gt_uint,
		.offset = offsetof(struct rpki_config, rsync.max),
		.doc = "Maximum simultaneous rsyncs.",
		.min = 0,
		.max = UINT_MAX,
	}, {
		.id = 3005,
		.name = "rsync.program",
		.type = &gt_string,
		.offset = offsetof(struct rpki_config, rsync.program),
		.doc = "Name of the program needed to execute an RSYNC",
		.arg_doc = "<path to program>",
		.json_null_allowed = false,
	}, {
		.id = 3008,
		.name = "rsync.transfer-timeout",
		.type = &gt_uint,
		.offset = offsetof(struct rpki_config, rsync.timeout),
		.doc = "Maximum transfer time before killing the rsync process",
		.min = 0,
		.max = UINT_MAX,
	},

	/* HTTP requests parameters */
	{
		.id = 9000,
		.name = "http.enabled",
		.type = &gt_bool,
		.offset = offsetof(struct rpki_config, http.enabled),
		.doc = "Enables outgoing HTTP requests",
	}, {
		.id = 9004,
		.name = "http.user-agent",
		.type = &gt_string,
		.offset = offsetof(struct rpki_config, http.user_agent),
		.doc = "User-Agent to use at HTTP requests, eg. Fort Validator Local/1.0",
		.json_null_allowed = false,
	}, {
		.id = 9012,
		.name = "http.max-redirs",
		.type = &gt_uint,
		.offset = offsetof(struct rpki_config, http.max_redirs),
		.doc = "Maximum number of redirections to follow, per HTTP request.",
		.min = 0,
		.max = UINT_MAX,
	}, {
		.id = 9005,
		.name = "http.connect-timeout",
		.type = &gt_uint,
		.offset = offsetof(struct rpki_config, http.connect_timeout),
		.doc = "Timeout for the connect phase",
		.min = 1,
		.max = UINT_MAX,
	}, {
		.id = 9006,
		.name = "http.transfer-timeout",
		.type = &gt_uint,
		.offset = offsetof(struct rpki_config, http.transfer_timeout),
		.doc = "Maximum transfer time (once the connection is established) before dropping the connection",
		.min = 0,
		.max = UINT_MAX,
	}, {
		.id = 9009,
		.name = "http.low-speed-limit",
		.type = &gt_uint,
		.offset = offsetof(struct rpki_config, http.low_speed_limit),
		.doc = "Average transfer speed (in bytes per second) that the transfer should be below during --http.low-speed-time seconds for Fort to consider it to be too slow. (Slow connections are dropped.)",
		.min = 0,
		.max = UINT_MAX,
	}, {
		.id = 9010,
		.name = "http.low-speed-time",
		.type = &gt_uint,
		.offset = offsetof(struct rpki_config, http.low_speed_time),
		.doc = "Seconds that the transfer speed should be below --http.low-speed-limit for the Fort to consider it too slow. (Slow connections are dropped.)",
		.min = 0,
		.max = UINT_MAX,
	}, {
		.id = 9011,
		.name = "http.max-file-size",
		.type = &gt_curl_offset,
		.offset = offsetof(struct rpki_config, http.max_file_size),
		.doc = "Fort will refuse to download files larger than this number of bytes.",
		.min = 0,
		.max = 2000000000,
	}, {
		.id = 9008,
		.name = "http.ca-path",
		.type = &gt_string,
		.offset = offsetof(struct rpki_config, http.ca_path),
		.doc = "Directory where CA certificates are found, used to verify the peer",
		.arg_doc = "<directory>",
		.json_null_allowed = true,
	}, {
		.id = 9013,
		.name = "http.proxy",
		.type = &gt_string,
		.offset = offsetof(struct rpki_config, http.proxy),
		.doc = "Name of proxy to use",
		.arg_doc = "<URI>",
		.json_null_allowed = true,
	},

	/* RRDP */
	{
		.id = 10000,
		.name = "rrdp.delta-threshold",
		.type = &gt_uint,
		.offset = offsetof(struct rpki_config, rrdp.delta_threshold),
		.doc = "Maximum deltas to explode per RRDP session, per iteration. "
		       "(Fall back to snapshot if threshold exceeded.)",
		.min = 1,	/* Must be > 0! */
		.max = 128,
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
		.id = 4006,
		.name = "log.print-times",
		.type = &gt_bool,
		.offset = offsetof(struct rpki_config, log.print_times),
		.doc = "(Console output only)",
	}, {
		.id = 4003,
		.name = "log.tag",
		.type = &gt_string,
		.offset = offsetof(struct rpki_config, log.tag),
		.doc = "Text tag to identify operation logs",
		.arg_doc = "<string>",
		.json_null_allowed = true,
	}, {
		.id = 4004,
		.name = "log.facility",
		.type = &gt_log_facility,
		.offset = offsetof(struct rpki_config, log.facility),
		.doc = "Facility for syslog if output is syslog",
	}, {
		.id = 'c',
		.name = "log.color-output",
		.type = &gt_bool,
		.offset = offsetof(struct rpki_config, log.color),
		.doc = "Print ANSI color codes",
	},

	{
		.id = 4010,
		.name = "report.path",
		.type = &gt_string,
		.offset = offsetof(struct rpki_config, report.path),
	},

	/* ASPA */
	{
		.id = 15000,
		.name = "aspa.max-providers",
		.type = &gt_uint,
		.offset = offsetof(struct rpki_config, aspa.max_providers),
		.doc = "Maximum number of providers each customerASID is allowed to declare across all RPKI trees during each validation cycle",
		.min = 0,
		.max = MAX_ASPA_PROVIDERS,
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
		.name = "output.vrp",
		.type = &gt_string,
		.offset = offsetof(struct rpki_config, output.vrp_filepath),
		.doc = "File where VRPs will be stored. ('-' for stdout)",
		.arg_doc = "<file>",
		.json_null_allowed = true,
	}, {
		.id = 6002,
		.name = "output.vrp-format",
		.type = &gt_output_format,
		.offset = offsetof(struct rpki_config, output.vrp_format),
		.doc = "VRP output file format",
	}, {
		.id = 6001,
		.name = "output.bgpsec",
		.type = &gt_string,
		.offset = offsetof(struct rpki_config, output.bgpsec_filepath),
		.doc = "File where BGPsec Router Keys will be stored. ('-' for stdout)",
		.arg_doc = "<file>",
		.json_null_allowed = true,
	}, {
		.id = 6004,
		.name = "output.bgpsec-format",
		.type = &gt_output_format,
		.offset = offsetof(struct rpki_config, output.bgpsec_format),
		.doc = "BGPsec Router Key output file format",
	}, {
		.id = 6003,
		.name = "output.aspa",
		.type = &gt_string,
		.offset = offsetof(struct rpki_config, output.aspa_filepath),
		.doc = "File where ASPAs will be stored. ('-' for stdout)",
		.arg_doc = "<file>",
		.json_null_allowed = true,
	},

	{
		.id = 12000,
		.name = "thread-pool.server.max",
		.type = &gt_uint,
		.offset = offsetof(struct rpki_config, thread_pool.server.max),
		.doc = "Number of threads in the RTR client request thread pool. Also known as the maximum number of client requests the RTR server will be able to handle at the same time.",
		.min = 1,
		.max = UINT_MAX,
	}, {
		.id = 12001,
		.name = "validation-threads",
		.type = &gt_uint,
		.offset = offsetof(struct rpki_config, thread_pool.validation.max),
		.doc = "Number of validation threads to allocate.",
		.min = 1,
		.max = 100,
	},

	{
		.id = 13000,
		.name = "debug.validation-time",
		.type = &gt_time,
		.offset = offsetof(struct rpki_config, debug.validation_time),
	},

	{
		.id = 13001,
		.name = "file-type",
		.type = &gt_file_type,
		.offset = offsetof(struct rpki_config, ft),
		.doc = "Parser for --mode=print",
	},
	{ 0 },
};

/*
 * Returns true if @field is the descriptor of one of the members of the
 * struct rpki_config structure, false otherwise.
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

/*
 * "struct option" is the array that getopt expects.
 * "struct option_field" is our option metadata.
 */
static void
build_opts(struct option **_long_opts, char **_short_opts)
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
	long_opts = pcalloc(total_long_options + 1, sizeof(struct option));
	short_opts = pmalloc(total_short_options + 1);

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
}

static void
print_config(void)
{
	struct option_field const *opt;

	pr_inf(PACKAGE_STRING);
	pr_inf("  libcrypto:     " OPENSSL_VERSION_TEXT);
	pr_inf("  jansson:       " JANSSON_VERSION);
	pr_inf("  libcurl:       " LIBCURL_VERSION);
	pr_inf("  libmicrohttpd: %x.%x.%x-%x",
	    MHD_VERSION >> 24, (MHD_VERSION >> 16) & 0xFF,
	    (MHD_VERSION >> 8) & 0xFF, MHD_VERSION & 0xFF);

	pr_inf("Configuration {");

	FOREACH_OPTION(options, opt, 0xFFFF)
		if (is_rpki_config_field(opt) && opt->type->print != NULL)
			opt->type->print(opt, get_rpki_config_field(opt));

	pr_inf("}");
}

static void
set_default_values(void)
{
	static char const *addrs[] = {
#ifdef __linux__
		"::"
#else
		"0.0.0.0", "::"
#endif
	};

	/*
	 * Values that might need to be freed WILL be freed, so use heap
	 * duplicates.
	 */

	rpki_config.tal = NULL;
	rpki_config.cache = pstrdup("/tmp/fort/repository");
	rpki_config.slurm = NULL;
	rpki_config.mode = SERVER;
	rpki_config.interval = 3600;
	rpki_config.daemon = false;

	string_array_init(&rpki_config.rtr.address, addrs, ARRAY_LEN(addrs));
	rpki_config.rtr.port = pstrdup("323");
	rpki_config.rtr.backlog = SOMAXCONN;
	rpki_config.rtr.expire = 7200;
	rpki_config.rtr.deltas_lifetime = 6;
	rpki_config.rtr.max_rtr_version = 0;

	rpki_config.prometheus.port = 0;

	rpki_config.rsync.enabled = true;
	rpki_config.rsync.max = 1;
	rpki_config.rsync.timeout = 900;
	rpki_config.rsync.program = pstrdup("rsync");

	rpki_config.http.enabled = true;
	rpki_config.http.user_agent = pstrdup(PACKAGE_NAME "/" PACKAGE_VERSION);
	rpki_config.http.max_redirs = 10;
	rpki_config.http.connect_timeout = 30;
	rpki_config.http.transfer_timeout = 900;
	rpki_config.http.low_speed_limit = 100000;
	rpki_config.http.low_speed_time = 10;
	rpki_config.http.max_file_size = 2000000000;
	rpki_config.http.ca_path = NULL; /* Use system default */
	rpki_config.http.proxy = NULL;

	/* TODO (fine) 64 may be too little; optimize. */
	rpki_config.rrdp.delta_threshold = 64;

	rpki_config.log.enabled = true;
	rpki_config.log.tag = NULL;
	rpki_config.log.color = false;
	rpki_config.log.level = LOG_WARNING;
	rpki_config.log.output = CONSOLE;
	rpki_config.log.facility = LOG_DAEMON;

	rpki_config.report.path = NULL;

	rpki_config.aspa.max_providers = 4000;

	rpki_config.output.vrp_filepath = NULL;
	rpki_config.output.vrp_format = OFM_CSV;
	rpki_config.output.bgpsec_filepath = NULL;
	rpki_config.output.bgpsec_format = OFM_CSV;
	rpki_config.output.aspa_filepath = NULL;

	rpki_config.thread_pool.server.max = 20;
	rpki_config.thread_pool.validation.max = 5;
}

static int
validate_config(void)
{
	char const *proxy;

	if (rpki_config.mode == PRINT_FILE)
		return 0;

	if (rpki_config.payload != NULL)
		return pr_err("I don't know what '%s' is.",
		    rpki_config.payload);

	if (rpki_config.tal == NULL)
		return pr_err("The TAL(s) location (--tal) is mandatory.");

	if (rpki_config.slurm != NULL && !file_is_valid(rpki_config.slurm, true))
		return pr_err("Invalid slurm location.");

	if (rpki_config.http.proxy == NULL) {
		proxy = curl_getenv("https_proxy");
		if (proxy == NULL)
			proxy = curl_getenv("HTTPS_PROXY");
		if (proxy != NULL && proxy[0] != '\0')
			rpki_config.http.proxy = pstrdup(proxy);
	}

	return 0;
}

static void
print_usage(FILE *stream, bool print_doc)
{
	struct option_field const *option;
	char const *arg_doc;

	fprintf(stream, "Usage: %s\n", program_name);
	FOREACH_OPTION(options, option, AVAILABILITY_GETOPT) {
		if (option->deprecated)
			continue;

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
			if (option->deprecated)
				pr_wrn("'%s' is deprecated.", option->name);

			return is_rpki_config_field(option)
			    ? option->type->parse.argv(option, optarg,
			          get_rpki_config_field(option))
			    : option->handler(option, optarg);
		}
	}

	pr_err("Unrecognized option: %d", opt);
	return ESRCH;
}

static int
parse_cfg(int argc, char **argv)
{
	struct option *lopts; /* long opts */
	char *sopts; /* short opts */
	int opt;
	int error;

	set_default_values();

	build_opts(&lopts, &sopts);

	while ((opt = getopt_long(argc, argv, sopts, lopts, NULL)) != -1) {
		error = handle_opt(opt);
		if (error)
			goto fail;
	}

	if (optind < argc)
		rpki_config.payload = argv[optind];

	error = validate_config();
	if (error)
		goto fail;

	free(lopts);
	free(sopts);
	return 0;

fail:	free(lopts);
	free(sopts);
	free_rpki_config();
	return error;
}

static void
become_absolute_path(char *cwd, char **_path)
{
	char *relative, *absolute;

	relative = *_path;
	if (relative != NULL) {
		absolute = path_join(cwd, relative);
		free(relative);
		*_path = absolute;
	}
}

static int
become_absolute_paths(void)
{
	char *buf, *cwd;
	int error;

	buf = pmalloc(1024);

	cwd = getcwd(buf, 1024);
	if (!cwd) {
		error = errno;
		pr_err("Cannot get the current directory: %s", strerror(error));
		free(buf);
		return error;
	}

	become_absolute_path(cwd, &rpki_config.tal);
	become_absolute_path(cwd, &rpki_config.report.path);
	become_absolute_path(cwd, &rpki_config.slurm);
	become_absolute_path(cwd, &rpki_config.http.ca_path);
	become_absolute_path(cwd, &rpki_config.output.vrp_filepath);
	become_absolute_path(cwd, &rpki_config.output.aspa_filepath);
	become_absolute_path(cwd, &rpki_config.output.bgpsec_filepath);

	free(buf);
	return 0;
}

static void
set_logger_syslog(void)
{
	struct log_listeners list = TAILQ_HEAD_INITIALIZER(list);
	struct log_listener node = { 0 };

	node.type = "syslog";
	node.level = "info";
	node.facility = LOG_DAEMON;

	TAILQ_INSERT_TAIL(&list, &node, lh);
	log_init(&list);
}

static void
set_logger_console(void)
{
	struct log_listeners list = TAILQ_HEAD_INITIALIZER(list);
	struct log_listener node = { 0 };

	node.type = "console";
	node.level = "trace";
	node.color = true;

	TAILQ_INSERT_TAIL(&list, &node, lh);
	log_init(&list);
}

init_verdict
handle_flags_config(int argc, char **argv)
{
	init_verdict verdict;

	if (parse_cfg(argc, argv) != 0) {
		pr_err("Try '%s --help' for more information.", argv[0]);
		return IV_FAIL;
	}

	if (become_absolute_paths() != 0) {
		free_rpki_config();
		return IV_FAIL;
	}

	if (rpki_config.daemon) {
		set_logger_syslog(); /* XXX hardcoded */
		verdict = daemonize();
		if (verdict != IV_CONTINUE) {
			free_rpki_config();
			return verdict;
		}
	} else {
		set_logger_console(); /* XXX hardcoded */
	}

	print_config();
	return IV_CONTINUE;
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
	return &rpki_config.rtr.address;
}

char const *
config_get_server_port(void)
{
	return rpki_config.rtr.port;
}

int
config_get_server_queue(void)
{
	/* The range of this is 1-<small number>, so adding sign is safe. */
	return rpki_config.rtr.backlog;
}

unsigned int
config_get_validation_interval(void)
{
	return rpki_config.interval;
}

unsigned int
config_get_interval_expire(void)
{
	return rpki_config.rtr.expire;
}

unsigned int
config_get_deltas_lifetime(void)
{
	return rpki_config.rtr.deltas_lifetime;
}

unsigned int
max_rtr_version(void)
{
	return rpki_config.rtr.max_rtr_version;
}

unsigned int
config_get_prometheus_port(void)
{
	return rpki_config.prometheus.port;
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
	return rpki_config.cache;
}

bool
config_get_op_log_enabled(void)
{
	return rpki_config.log.enabled;
}

bool
config_get_op_print_times(void)
{
	return rpki_config.log.print_times;
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

char *
config_get_report(void)
{
	return rpki_config.report.path;
}

bool
config_get_rsync_enabled(void)
{
	return rpki_config.rsync.enabled;
}

unsigned int
config_rsync_max(void)
{
	return rpki_config.rsync.max;
}

long
config_rsync_timeout(void)
{
	return rpki_config.rsync.timeout;
}

char const *
config_get_rsync_program(void)
{
	return rpki_config.rsync.program;
}

bool
config_get_http_enabled(void)
{
	return rpki_config.http.enabled;
}

char const *
config_get_http_proxy(void)
{
	return rpki_config.http.proxy;
}

char const *
config_get_http_user_agent(void)
{
	return rpki_config.http.user_agent;
}

unsigned int
config_get_max_redirs(void)
{
	return rpki_config.http.max_redirs;
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

curl_off_t
config_get_http_max_file_size(void)
{
	return rpki_config.http.max_file_size;
}

char const *
config_get_http_ca_path(void)
{
	return rpki_config.http.ca_path;
}

unsigned int
config_get_rrdp_delta_threshold(void)
{
	return rpki_config.rrdp.delta_threshold;
}

char const *
config_get_output_roa(void)
{
	return rpki_config.output.vrp_filepath;
}

enum output_format
config_get_vrp_output_format(void)
{
	return rpki_config.output.vrp_format;
}

char const *
config_get_output_bgpsec(void)
{
	return rpki_config.output.bgpsec_filepath;
}

enum output_format
config_get_bgpsec_output_format(void)
{
	return rpki_config.output.bgpsec_format;
}

char const *
config_get_output_aspa(void)
{
	return rpki_config.output.aspa_filepath;
}

unsigned int
config_get_thread_pool_server_max(void)
{
	return rpki_config.thread_pool.server.max;
}

unsigned int
config_get_validation_thread_count(void)
{
	return rpki_config.thread_pool.validation.max;
}

enum file_type
config_get_file_type(void)
{
	return rpki_config.ft;
}

char const *
config_get_payload(void)
{
	return rpki_config.payload;
}

time_t
config_get_validation_time(void)
{
	return rpki_config.debug.validation_time;
}

void
free_rpki_config(void)
{
	struct option_field const *option;

	FOREACH_OPTION(options, option, 0xFFFF)
		if (is_rpki_config_field(option) && option->type->free != NULL)
			option->type->free(get_rpki_config_field(option));
}

unsigned int
config_get_max_aspa_providers(void)
{
	return rpki_config.aspa.max_providers;
}
