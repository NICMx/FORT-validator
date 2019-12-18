---
title: Logging
url-log-level: "[`--log.level`](usage.html#--loglevel)"
url-log-output: "[`--log.output`](usage.html#--logoutput)"
url-log-color-output: "[`--log.color-output`](usage.html#--logcolor-output)"
url-log-file-name-format: "[`--log.file-name-format`](usage.html#--logfile-name-format)"
---

# {{ page.title }}

FORT validator logging can be configured using the arguments:
- {{ page.url-log-level }}
- {{ page.url-log-output }}
- {{ page.url-log-color-output }}
- {{ page.url-log-file-name-format }}

## Log output

During the brief period in which configuration has not been completely parsed yet (and therefore, the validator is not yet aware of the desired log output), the standard streams and syslog are used simultaneously.

Once the configuration has been loaded, all the log messages will be printed at the configured {{ page.url-log-output }}, which can have two values:
- `syslog`: all logging is sent to syslog, using **LOG_DAEMON** facility.
- `console`: informational and debug messages are printed in standard output, error and critical messages are thrown to standard error.

> Syslog configuration and usage is out of this docs scope, here's a brief introduction from [Wikipedia](https://en.wikipedia.org/wiki/Syslog). You can do some research according to your prefered OS distro to familiarize with syslog, since distinct implementations exists (the most common are: syslog, rsyslog, and syslog-ng).

## Log level

The {{ page.url-log-level }} argument defines which messages will be logged according to its priority. Any log message of equal or higher importance to the one configured, will be logged, e.g. a value of `info` will log messages of equal or higher level (`info`, `warning`, and `error`).

The validator uses exactly five levels of priority (they're just some of all the syslog priority levels), but only four of them can be utilized in {{ page.url-log-output }}. These are their meanings and priority from highest to lowest:
- `crit`: Programming errors. (These lead to program termination.)
	- **This level can't be indicated at {{ page.url-log-level }}**, since `error` and `crit` messages are relevant for an adequate operation.
- `error`: Validation failures. (RPKI object rejected.)
- `warning`: Suspicious validation outcome. (RPKI object not rejected.)
- `info`: Information deemed useful to the user:
	- Configuration echo at the beginning.
	- Server binding status.
	- Start and end of a validation cycle, including: number of valid Prefixes and Router Keys, current RTR serial number (only when [`--mode=server`](usage.html#--mode), and real execution time.
	- SLURM version applied in case of a syntax error or invalid data at the newest loaded SLURM configured at [`--slurm`](usage.html#--slurm).
	- RTR client connection accepted, closed or terminated.
- `debug`: Information deemed useful to the developer. Expect a lot of messages when utilized.

## Log color output

The flag {{ page.url-log-color-output }} is only meaningful when {{ page.url-log-output }} is `console` (it doesn't affect to `syslog`). When the flag is enabled, the log messages will have the following colors according to its priority:
- `crit`: <span style="color:magenta">CYAN</span>
- `error`: <span style="color:red">RED</span>
- `warning`: <span style="color:orange">ORANGE</span>
- `info`: <span style="color:lightgray">LIGHT GRAY</span>
- `debug`: <span style="color:cyan">CYAN</span>

## Log file name format

The flag {{ page.url-log-file-name-format }} defines how the file names will be printed at the logs output, see more details at [Program Arguments > Arguments > --log.file-name-format](usage.html#--logfile-name-format).
