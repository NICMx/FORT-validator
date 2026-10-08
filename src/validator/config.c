#include "validator/config.h"

#include <limits.h>
#include <microhttpd.h>
#include <openssl/opensslv.h>
#include <syslog.h>

#include "common/config.h"
#include "common/config/boolean.h"
#include "common/config/curl_offset.h"
#include "common/config/incidences.h"
#include "common/config/str.h"
#include "common/config/time.h"
#include "common/config/uint.h"
#include "common/daemon.h"
#include "common/file.h"
#include "common/log.h"
#include "common/types/path.h"
#include "configure_ac.h"
#include "validator/json_handler.h"

static int handle_json(struct option_field const *, char *);

/* This remains constant after inits */
struct fort_config fortcfg;

struct option_field const options[] = {

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
		.offset = offsetof(struct fort_config, tal),
		.doc = "Path to the TAL file or TALs directory",
		.arg_doc = "<file>|<directory>",
		.json_null_allowed = false,
	}, {
		.id = 'c',
		.name = "cache",
		.type = &gt_string,
		.offset = offsetof(struct fort_config, cache),
		.doc = "Local cache directory",
		.arg_doc = "<directory>",
		.json_null_allowed = false,
	}, {
		.id = 1003,
		.name = "slurm",
		.type = &gt_string,
		.offset = offsetof(struct fort_config, slurm),
		.doc = "Path to the SLURM file or SLURMs directory (files must have the extension .slurm)",
		.arg_doc = "<file>|<directory>",
		.json_null_allowed = true,
	}, {
		.id = 1006,
		.name = "daemon",
		.type = &gt_bool,
		.offset = offsetof(struct fort_config, daemon),
		.doc = "Run fort as a daemon.",
	},

	/* Server fields */
	{
		.id = 5003,
		.name = "server.interval.validation",
		.type = &gt_uint,
		.offset = offsetof(struct fort_config, validation_interval),
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
		.id = 5007,
		.name = "server.deltas.lifetime",
		.type = &gt_uint,
		.offset = offsetof(struct fort_config, deltas_lifetime),
		.doc = "Number of iterations the RTR deltas will be stored.",
		.min = 1,
		/*
		 * It's a serial, which means the technical maximum is about
		 * 2^31 - 1. But that's too much.
		 * Must not overflow when multiplied by interval.validation.
		 */
		.max = 1000,
	},

	/* RSYNC fields */
	{
		.id = 3000,
		.name = "rsync.enabled",
		.type = &gt_bool,
		.offset = offsetof(struct fort_config, rsync.enabled),
		.doc = "Enables RSYNC execution",
	}, {
		.id = 3001,
		.name = "rsync.max",
		.type = &gt_uint,
		.offset = offsetof(struct fort_config, rsync.max),
		.doc = "Maximum simultaneous rsyncs.",
		.min = 0,
		.max = UINT_MAX,
	}, {
		.id = 3005,
		.name = "rsync.program",
		.type = &gt_string,
		.offset = offsetof(struct fort_config, rsync.program),
		.doc = "Name of the program needed to execute an RSYNC",
		.arg_doc = "<path to program>",
		.json_null_allowed = false,
	}, {
		.id = 3008,
		.name = "rsync.transfer-timeout",
		.type = &gt_uint,
		.offset = offsetof(struct fort_config, rsync.timeout),
		.doc = "Maximum transfer time before killing the rsync process",
		.min = 0,
		.max = UINT_MAX,
	},

	/* HTTP requests parameters */
	{
		.id = 9000,
		.name = "http.enabled",
		.type = &gt_bool,
		.offset = offsetof(struct fort_config, http.enabled),
		.doc = "Enables outgoing HTTP requests",
	}, {
		.id = 9004,
		.name = "http.user-agent",
		.type = &gt_string,
		.offset = offsetof(struct fort_config, http.user_agent),
		.doc = "User-Agent to use at HTTP requests, eg. Fort Validator Local/1.0",
		.json_null_allowed = false,
	}, {
		.id = 9012,
		.name = "http.max-redirs",
		.type = &gt_uint,
		.offset = offsetof(struct fort_config, http.max_redirs),
		.doc = "Maximum number of redirections to follow, per HTTP request.",
		.min = 0,
		.max = UINT_MAX,
	}, {
		.id = 9005,
		.name = "http.connect-timeout",
		.type = &gt_uint,
		.offset = offsetof(struct fort_config, http.connect_timeout),
		.doc = "Timeout for the connect phase",
		.min = 1,
		.max = UINT_MAX,
	}, {
		.id = 9006,
		.name = "http.transfer-timeout",
		.type = &gt_uint,
		.offset = offsetof(struct fort_config, http.transfer_timeout),
		.doc = "Maximum transfer time (once the connection is established) before dropping the connection",
		.min = 0,
		.max = UINT_MAX,
	}, {
		.id = 9009,
		.name = "http.low-speed-limit",
		.type = &gt_uint,
		.offset = offsetof(struct fort_config, http.low_speed_limit),
		.doc = "Average transfer speed (in bytes per second) that the transfer should be below during --http.low-speed-time seconds for Fort to consider it to be too slow. (Slow connections are dropped.)",
		.min = 0,
		.max = UINT_MAX,
	}, {
		.id = 9010,
		.name = "http.low-speed-time",
		.type = &gt_uint,
		.offset = offsetof(struct fort_config, http.low_speed_time),
		.doc = "Seconds that the transfer speed should be below --http.low-speed-limit for the Fort to consider it too slow. (Slow connections are dropped.)",
		.min = 0,
		.max = UINT_MAX,
	}, {
		.id = 9011,
		.name = "http.max-file-size",
		.type = &gt_curl_offset,
		.offset = offsetof(struct fort_config, http.max_file_size),
		.doc = "Fort will refuse to download files larger than this number of bytes.",
		.min = 1,
		.max = 2000000000,
	}, {
		.id = 9008,
		.name = "http.ca-path",
		.type = &gt_string,
		.offset = offsetof(struct fort_config, http.ca_path),
		.doc = "Directory where CA certificates are found, used to verify the peer",
		.arg_doc = "<directory>",
		.json_null_allowed = true,
	}, {
		.id = 9013,
		.name = "http.proxy",
		.type = &gt_string,
		.offset = offsetof(struct fort_config, http.proxy),
		.doc = "Name of proxy to use",
		.arg_doc = "<URI>",
		.json_null_allowed = true,
	},

	/* RRDP */
	{
		.id = 10000,
		.name = "rrdp.delta-threshold",
		.type = &gt_uint,
		.offset = offsetof(struct fort_config, rrdp.delta_threshold),
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
		.offset = offsetof(struct fort_config, log.enabled),
		.doc = "Enables operation logs",
	}, {
		.id = 4001,
		.name = "log.output",
		.type = &gt_log_output,
		.offset = offsetof(struct fort_config, log.output),
		.doc = "Output where operation log messages will be printed",
	}, {
		.id = 4002,
		.name = "log.level",
		.type = &gt_log_level,
		.offset = offsetof(struct fort_config, log.level),
		.doc = "Log level to print message of equal or higher importance",
	}, {
		.id = 4006,
		.name = "log.print-times",
		.type = &gt_bool,
		.offset = offsetof(struct fort_config, log.print_times),
		.doc = "(Console output only)",
	}, {
		.id = 4003,
		.name = "log.tag",
		.type = &gt_string,
		.offset = offsetof(struct fort_config, log.tag),
		.doc = "Text tag to identify operation logs",
		.arg_doc = "<string>",
		.json_null_allowed = true,
	}, {
		.id = 4004,
		.name = "log.facility",
		.type = &gt_log_facility,
		.offset = offsetof(struct fort_config, log.facility),
		.doc = "Facility for syslog if output is syslog",
	}, {
		.id = 4005,
		.name = "log.color-output",
		.type = &gt_bool,
		.offset = offsetof(struct fort_config, log.color),
		.doc = "Print ANSI color codes",
	},

	{
		.id = 4010,
		.name = "report.path",
		.type = &gt_string,
		.offset = offsetof(struct fort_config, report.path),
	},

	/* ASPA */
	{
		.id = 15000,
		.name = "aspa.max-providers",
		.type = &gt_uint,
		.offset = offsetof(struct fort_config, aspa.max_providers),
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
		.offset = offsetof(struct fort_config, output.vrp_filepath),
		.doc = "File where VRPs will be stored. ('-' for stdout)",
		.arg_doc = "<file>",
		.json_null_allowed = true,
	}, {
		.id = 6002,
		.name = "output.vrp-format",
		.type = &gt_output_format,
		.offset = offsetof(struct fort_config, output.vrp_format),
		.doc = "VRP output file format",
	}, {
		.id = 6001,
		.name = "output.bgpsec",
		.type = &gt_string,
		.offset = offsetof(struct fort_config, output.bgpsec_filepath),
		.doc = "File where BGPsec Router Keys will be stored. ('-' for stdout)",
		.arg_doc = "<file>",
		.json_null_allowed = true,
	}, {
		.id = 6004,
		.name = "output.bgpsec-format",
		.type = &gt_output_format,
		.offset = offsetof(struct fort_config, output.bgpsec_format),
		.doc = "BGPsec Router Key output file format",
	}, {
		.id = 6003,
		.name = "output.aspa",
		.type = &gt_string,
		.offset = offsetof(struct fort_config, output.aspa_filepath),
		.doc = "File where ASPAs will be stored. ('-' for stdout)",
		.arg_doc = "<file>",
		.json_null_allowed = true,
	},

	{
		.id = 12001,
		.name = "validation-threads",
		.type = &gt_uint,
		.offset = offsetof(struct fort_config, validation_threads),
		.doc = "Number of validation threads to allocate.",
		.min = 1,
		.max = 100,
	},

	{
		.id = 13000,
		.name = "debug.validation-time",
		.type = &gt_time,
		.offset = offsetof(struct fort_config, debug.validation_time),
	},

	{
		.id = 13001,
		.name = "file-type",
		.type = &gt_file_type,
		.offset = offsetof(struct fort_config, ft),
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

static int
handle_json(struct option_field const *field, char *file_name)
{
	return set_config_from_file(file_name);
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
			opt->type->print(opt, get_rpki_config_field(opt, &fortcfg));

	pr_inf("}");
}

static void
set_default_values(void)
{
	/*
	 * Values that might need to be freed WILL be freed, so use heap
	 * duplicates.
	 */

	fortcfg.tal = NULL;
	fortcfg.cache = pstrdup("/tmp/fort/repository");
	fortcfg.slurm = NULL;
	fortcfg.validation_interval = 0;
	fortcfg.daemon = false;
	fortcfg.deltas_lifetime = 6;

	fortcfg.rsync.enabled = true;
	fortcfg.rsync.max = 1;
	fortcfg.rsync.timeout = 900;
	fortcfg.rsync.program = pstrdup("rsync");

	fortcfg.http.enabled = true;
	fortcfg.http.user_agent = pstrdup(PACKAGE_NAME "/" PACKAGE_VERSION);
	fortcfg.http.max_redirs = 10;
	fortcfg.http.connect_timeout = 30;
	fortcfg.http.transfer_timeout = 900;
	fortcfg.http.low_speed_limit = 100000;
	fortcfg.http.low_speed_time = 10;
	fortcfg.http.max_file_size = 2000000000;
	fortcfg.http.ca_path = NULL; /* Use system default */
	fortcfg.http.proxy = NULL;

	/* TODO (fine) 64 may be too little; optimize. */
	fortcfg.rrdp.delta_threshold = 64;

	fortcfg.log.enabled = true;
	fortcfg.log.tag = NULL;
	fortcfg.log.color = false;
	fortcfg.log.level = LOG_WARNING;
	fortcfg.log.output = CONSOLE;
	fortcfg.log.facility = LOG_DAEMON;

	fortcfg.report.path = NULL;

	fortcfg.aspa.max_providers = 4000;

	fortcfg.output.vrp_filepath = NULL;
	fortcfg.output.vrp_format = OFM_CSV;
	fortcfg.output.bgpsec_filepath = NULL;
	fortcfg.output.bgpsec_format = OFM_CSV;
	fortcfg.output.aspa_filepath = NULL;

	fortcfg.validation_threads = 5;
}

static int
validate_config(void)
{
	char const *proxy;

	if (fortcfg.payload != NULL && strlen(fortcfg.payload) != 0)
		return pr_err("I don't know what '%s' is.", fortcfg.payload);

	if (fortcfg.tal == NULL)
		return pr_err("The TAL(s) location (--tal) is mandatory.");

	if (fortcfg.slurm != NULL && !file_is_valid(fortcfg.slurm, true))
		return pr_err("Invalid slurm location.");

	if (fortcfg.http.proxy == NULL) {
		proxy = curl_getenv("https_proxy");
		if (proxy == NULL)
			proxy = curl_getenv("HTTPS_PROXY");
		if (proxy != NULL && proxy[0] != '\0')
			fortcfg.http.proxy = pstrdup(proxy);
	}

	return 0;
}

static int
parse_cfg(int argc, char **argv)
{
	int error;

	set_default_values();

	error = parse_args(argc, argv, &fortcfg);
	if (error)
		goto fail;

	if (optind < argc)
		fortcfg.payload = argv[optind];

	error = validate_config();
	if (error)
		goto fail;

	return 0;

fail:	free_rpki_config(&fortcfg);
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

	become_absolute_path(cwd, &fortcfg.tal);
	become_absolute_path(cwd, &fortcfg.report.path);
	become_absolute_path(cwd, &fortcfg.slurm);
	become_absolute_path(cwd, &fortcfg.http.ca_path);
	become_absolute_path(cwd, &fortcfg.output.vrp_filepath);
	become_absolute_path(cwd, &fortcfg.output.aspa_filepath);
	become_absolute_path(cwd, &fortcfg.output.bgpsec_filepath);

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
		free_rpki_config(&fortcfg);
		return IV_FAIL;
	}

	if (fortcfg.daemon) {
		set_logger_syslog(); /* XXX hardcoded */
		verdict = daemonize();
		if (verdict != IV_CONTINUE) {
			free_rpki_config(&fortcfg);
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
