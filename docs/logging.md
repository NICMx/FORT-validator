---
title: Logging
command: fort
url-log-enabled: "[`--log.enabled`](usage.html#--logenabled)"
url-log-level: "[`--log.level`](usage.html#--loglevel)"
url-log-output: "[`--log.output`](usage.html#--logoutput)"
url-log-color-output: "[`--log.color-output`](usage.html#--logcolor-output)"
url-log-file-name-format: "[`--log.file-name-format`](usage.html#--logfile-name-format)"
url-log-facility: "[`--log.facility`](usage.html#--logfacility)"
url-log-prefix: "[`--log.prefix`](usage.html#--logprefix)"
url-vlog-enabled: "[`--validation-log.enabled`](usage.html#--validation-logenabled)"
url-vlog-level: "[`--validation-log.level`](usage.html#--validation-loglevel)"
url-vlog-output: "[`--validation-log.output`](usage.html#--validation-logoutput)"
url-vlog-color-output: "[`--validation-log.color-output`](usage.html#--validation-logcolor-output)"
url-vlog-file-name-format: "[`--validation-log.file-name-format`](usage.html#--validation-logfile-name-format)"
url-vlog-facility: "[`--validation-log.facility`](usage.html#--validation-logfacility)"
url-vlog-prefix: "[`--validation-log.prefix`](usage.html#--validation-logprefix)"
---

# {{ page.title }}

## Index

1. [Log types](#log-types)
	1. [Operation](#operation)
	2. [Validation](#validation)
2. [Configuration](#configuration)
	1. [Enabled](#enabled)
	2. [Output](#output)
	3. [Level](#level)
	4. [Color output](#color-output)
	5. [File name format](#file-name-format)
	6. [Facility](#facility)
	7. [Prefix](#prefix)

## Log types

Currently there are two kinds of log messages: those related to the operation, and the ones regarding RPKI objects validation.

Each type is described above, as well as how it can be configured.

### Operation

These type of messages are the ones where the user/operator can be directly involved. Probably these messages are of greater interest to most of the RP operators.

The following messages are included at the operation logs:
- Configuration information, warnings and errors. E.g. if the location set at [`--tal`](usage.html#--tal) can't be accessed, or a configuration echo at the beginning.
- RTR information, warnings and errors; such as server binding status, and client connections (accepted, closed or terminated).
- SLURM information, warnings and errors. E.g. bad SLURM syntax, or SLURM data being applied in case of an error with a newer SLURM file.
- Out of memory errors.
- Read/write errors on local files.
- Persistent communication errors with RPKI repositories (see [`--stale-repository-period`](usage.html#--stale-repository-period)).
- Start and end of a validation cycle, including: number of valid Prefixes and Router Keys, current RTR serial number (only when [`--mode=server`](usage.html#--mode), and real execution time.
- Programming errors (of course, those that could be expected due to an API misuse).

### Validation

These type of messages are the ones related to one of the main tasks performed by FORT validator: the RPKI validation. So, they are useful to know the current RPKI state.

All this messages are result of RPKI objects (certificates, CRLs, ROAs, etc.) processing, so probably the operator can't take a direct action trying to solve an error logged here, but it can get to know if something is wrong at the data published at the RPKI repositories.

Here are some examples of messages included at the validation logs:
- Validation failures causing an RPKI object rejection (e.g. expired certificate).
- Suspicious validation outcome, but the RPKI object isn't rejected (e.g. serial numbers duplicated).
- An [incidence](incidence.html).
- RRDP file information, warnings and errors.

> ![img/warn.svg](img/warn.svg) These messages are disabled by default, in order to enable them set [`--validation-log.enabled=true`](usage.html#--validation-logenabled).

## Configuration

Both type of logs share a set of configuration arguments, each one of them applying to the corresponding log type.

The operation log arguments are those that have the prefix `log.`, while the validation log arguments begin with `validation-log.`. The next suffixes can be added to configure each log type:
- [`enabled`](#enabled)
- [`level`](#level)
- [`output`](#output)
- [`color-output`](#color-output)
- [`file-name-format`](#file-name-format)
- [`facility`](#facility)
- [`prefix`](#prefix)

For instance, to enable the validation log the argument {{ page.url-vlog-enabled }} should be used (prefix: `validation-log.`, suffix: `enabled`).

The following sub-sections describe how each argument works.

### Enabled

Enables the corresponding log. If disabled (e.g. `--log.enabled=false`) none of the corresponding messages will be logged.

The arguments of each log type are:
- {{ page.url-log-enabled }}
- {{ page.url-vlog-enabled }}

### Output

During the brief period in which configuration has not been completely parsed yet (and therefore, the validator is not yet aware of the desired log output), the standard streams and syslog are used simultaneously.

Once the configuration has been loaded, all the log messages will be printed at the configured `*.output`, which can have two values:
- `syslog`: all logging is sent to syslog, using the configured [`*.facility`](#facility).
- `console`: informational and debug messages are printed in standard output, error and critical messages are thrown to standard error.

> Syslog configuration and usage is out of this docs scope, here's a brief introduction from [Wikipedia](https://en.wikipedia.org/wiki/Syslog). You can do some research according to your prefered OS distro to familiarize with syslog, since distinct implementations exists (the most common are: syslog, rsyslog, and syslog-ng).

The arguments of each log type are:
- {{ page.url-log-output }}
- {{ page.url-vlog-output }}

### Level

The `*.level` argument defines which messages will be logged according to its priority. Any log message of equal or higher importance to the one configured, will be logged, e.g. a value of `info` will log messages of equal or higher level (`info`, `warning`, and `error`).

The validator uses exactly five levels of priority (they're just some of all the syslog priority levels), but only four of them can be utilized in the configured [`*.output`](#output). These are their meanings and priority from highest to lowest:
- `crit`: Programming errors. (These lead to program termination.)
	- **This level can't be indicated at `level`**, since `error` and `crit` messages are relevant for an adequate operation.
- `error`: A failure that can stop an internal task (e.g. a certificate has expired so the childs are discarded) or is definitely an operational problem (e.g. no more memory can be allocated).
- `warning`: Something suspicious, but not a stopper for a task.
- `info`: Information deemed useful to the user.
- `debug`: Information deemed useful to the developer. Expect a lot of messages when utilized.

The arguments of each log type are:
- {{ page.url-log-level }}
- {{ page.url-vlog-level }}

### Color output

The flag `*.color-output` is only meaningful when [`*.output`](#output) is `console` (it doesn't affect to `syslog`). When the flag is enabled, the log messages will have the following colors according to its priority:
- `crit`: <span style="color:magenta">CYAN</span>
- `error`: <span style="color:red">RED</span>
- `warning`: <span style="color:orange">ORANGE</span>
- `info`: <span style="color:lightgray">LIGHT GRAY</span>
- `debug`: <span style="color:cyan">CYAN</span>

These are some examples of how the logs could be displayed when the flag is enabled:
<pre><code class="terminal">$ {{ page.command }} --log.color-output --validation-log.color-output (...)
<span style="color:cyan">DBG: Manifest '62gPOPXWxxu0sQa4vQZYUBLaMbY.mft' {</span>
<span style="color:lightgray">INF: Configuration {</span>
<span style="color:orange">WRN: H2jRmyC2M.mft: The signature algorithm has parameters.</span>
<span style="color:red">ERR: H2jRmyC2M.mft: Certificate validation failed: certificate has expired</span>
<span style="color:magenta">CRT: Programming error: Array size is 1 but array is NULL.</span>
</code></pre>

The arguments of each log type are:
- {{ page.url-log-color-output }}
- {{ page.url-vlog-color-output }}

### File name format

Decides which version of file names should be printed during most debug/error messages. It can have the values:
- `global-url`: Prints the global name of the file; the URL that can be used to download it (always starts with `rsync://` or `https://`).
- `local-path`: Prints a path that points to the local cached version of the file (always starts with [`--local-repository`](usage.html#--local-repository)'s value).
- `file-name`: Strips prefixes, leaving only the base name of the file (including extension).

Suppose a certificate was downloaded from `rsync://rpki.example.com/foo/bar/baz.cer` into the local cache `repository/`:

- `global-url`: Will print the certificate's name as `rsync://rpki.example.com/foo/bar/baz.cer`.
- `local-path`: Will print the certificate's name as `repository/rpki.example.com/foo/bar/baz.cer`.
- `file-name`: Will print the certificate's name as `baz.cer`.

{% highlight bash %}
$ {{ page.command }} --validation-log.file-name-format=global-url --local-repository=repository/ (...)
ERR: rsync://rpki.example.com/foo/bar/baz.cer: Certificate validation failed: certificate has expired

$ {{ page.command }} --validation-log.file-name-format=local-path --local-repository=repository/ (...)
ERR: repository/rpki.example.com/foo/bar/baz.cer: Certificate validation failed: certificate has expired

$ {{ page.command }} --validation-log.file-name-format=file-name  --local-repository=repository/ (...)
ERR: baz.cer: Certificate validation failed: certificate has expired
{% endhighlight %}

This flag affects any of the log output configured at [`*.output`](#output) (`syslog` and `console`).

The arguments of each log type are:
- {{ page.url-log-file-name-format }}
- {{ page.url-vlog-file-name-format }}

### Facility

Sets the syslog facility, so it's only meaningful when [`*.output`](#output) is `syslog`.

Currently the supported facilites are:

--|--|--|--|--|--
auth | daemon | mail | uucp | local2 | local5
authpriv | ftp | news | local0 | local3 | local6
cron | lpr | user | local1 | local4 | local7


You could read more about facilites [here](https://en.wikipedia.org/wiki/Syslog#Facility) (since it's out of this docs scope).

The arguments of each log type are:
- {{ page.url-log-facility }}
- {{ page.url-vlog-facility }}

### Prefix

Text prefix that will be added to each message of the corresponding log type. The prefix will be added after the message level, inside square brackets.

It's a simple mean to differentiate each message according to its type, probably useful if the [`*.output`](#output) is the same for both log types.

E.g. If a validation error is found, it could be logged like this:
{% highlight bash %}
$ {{ page.command }} --validation-log.prefix="Validation" (...)
ERR [Validation]: rsync://rpki.example.com/foo/bar/baz.cer: Certificate validation failed: certificate has expired
{% endhighlight %}

The arguments of each log type are:
- {{ page.url-log-prefix }}
- {{ page.url-vlog-prefix }}
