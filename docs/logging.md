---
title: Logging
command: fort
description: This is a guide to configure and use the logging attributes of FORT Validator.
url-log-enabled: "[`--log.enabled`](usage.html#--logenabled)"
url-log-level: "[`--log.level`](usage.html#--loglevel)"
url-log-output: "[`--log.output`](usage.html#--logoutput)"
url-log-color-output: "[`--log.color-output`](usage.html#--logcolor-output)"
url-log-file-name-format: "[`--log.file-name-format`](usage.html#--logfile-name-format)"
url-log-facility: "[`--log.facility`](usage.html#--logfacility)"
url-log-tag: "[`--log.tag`](usage.html#--logtag)"
url-vlog-enabled: "[`--validation-log.enabled`](usage.html#--validation-logenabled)"
url-vlog-level: "[`--validation-log.level`](usage.html#--validation-loglevel)"
url-vlog-output: "[`--validation-log.output`](usage.html#--validation-logoutput)"
url-vlog-color-output: "[`--validation-log.color-output`](usage.html#--validation-logcolor-output)"
url-vlog-file-name-format: "[`--validation-log.file-name-format`](usage.html#--validation-logfile-name-format)"
url-vlog-facility: "[`--validation-log.facility`](usage.html#--validation-logfacility)"
url-vlog-tag: "[`--validation-log.tag`](usage.html#--validation-logtag)"
---

# {{ page.title }}

## Index

1. [Log types](#log-types)
	1. [Operation Log](#operation-log)
	2. [Validation Log](#validation-log)
2. [Configuration](#configuration)
	1. [Enabled](#enabled)
	2. [Output](#output)
	3. [Level](#level)
	4. [Color output](#color-output)
	5. [File name format](#file-name-format)
	6. [Facility](#facility)
	7. [Tag](#tag)

## Log types

Fort has two different types of log messages: Operation logs and Validation logs.

They will be described below.

### Operation Log

Operation logs are of likely interest to the operator running Fort; Issues reported here require human intervention. These include

| Type | INFO example | WARNING example| ERROR example |
|------|--------------|----------------|---------------|
| Configuration logs | "And now I'm going to echo my configuration, in case you want to review it." | "This configuration argument is deprecated." | "Bad file syntax." |
| RTR Server logs | "Accepted connection from client." | "Huh? Peer is not speaking the RTR protocol." | "Cannot bind to address." |
| Out of memory errors | - | - | "Out of memory." |
| Read/write errors on local files | - | "The SLURM directory seems to lack SLURM files." | "I don't have permissions to access the repository cache." |
| Start and end of a validation cycle | "Validation cycle ended. I got _R_ ROAs, _K_ router keys, my new serial is _S_, and it took _T_ seconds." | - | - |
| Programming errors | - | - | "Array size is 1, but array is NULL." |

### Validation Log

These are messages generated during the RPKI validation cycle, and refer specifically to quirks found in the RPKI objects. (ie. Certificates, CRLs, ROAs, etc.)

These are likely more meaningful to repository administrators, for the sake of reviewing their objects.

They are [disabled by default](usage.html#--validation-logenabled).

| Type | WARNING example| ERROR example |
|------|-----------------|---------------|
| Validation eventualities | "Maximum retries reached; skipping object." | "Certificate is expired." |
| [Incidences](incidence.html) | "Manifest is stale." | "Manifest is stale." |

(Most informational validation messages have DEBUG priority. Incidence severity is configurable.)

## Configuration

Both type of logs share a set of configuration arguments, each one of them applying to the corresponding log type.

The operation log arguments are those that have the prefix `log.`, while the validation log arguments begin with `validation-log.`. The next suffixes can be added to configure each log type:
- [`enabled`](#enabled)
- [`level`](#level)
- [`output`](#output)
- [`color-output`](#color-output)
- [`file-name-format`](#file-name-format)
- [`facility`](#facility)
- [`tag`](#tag)

For instance, to enable the "validation log", the argument {{ page.url-vlog-enabled }} should be used (prefix: `validation-log.`, suffix: `enabled`).

The following sub-sections describe how each argument works.

### Enabled

Sets whether the corresponding log type is printed or suppressed. When `false`, the rest of the corresponding log type's arguments are ignored.

- {{ page.url-log-enabled }}
- {{ page.url-vlog-enabled }}

### Output

Either `syslog` or `console`. The former sends the output to the environment's [syslog](https://en.wikipedia.org/wiki/Syslog) server (using the configured [`*.facility`](#facility)), while the latter employs the standard streams. (DEBUG and INFO are sent to standard output, WARNING and ERROR to standard error.)

> During the brief period in which configuration has not been completely parsed yet (and therefore, the validator is not yet aware of the desired log output), the standard streams and syslog are used simultaneously.

- {{ page.url-log-output }}
- {{ page.url-vlog-output }}

### Level

Only messages of equal or higher priority than `*.level` will be logged. For example, `--log.level=warning` will discard DEBUG and INFO operation messages, and log WARNING and ERROR.

The available values are

- `error`: A failure that can stop an internal task (e.g. a certificate has expired so the childs are discarded) or is definitely an operational problem (e.g. no more memory can be allocated). Also detected programming errors.
- `warning`: Something suspicious, but not a stopper for a task.
- `info`: Inoffensive messages that might be of interest to the administrator.
- `debug`: Information deemed useful to the developer.

Variants:

- {{ page.url-log-level }}
- {{ page.url-vlog-level }}

### Color output

Causes the output to contain ASCII color codes. Meant for human consumption. Only applies when [output](#output) is `console`.

Each color depends on the message's priority:

- `error`: <span style="color:red">RED</span> (Critical errors are <span style="color:magenta">CYAN</span>)
- `warning`: <span style="color:orange">ORANGE</span>
- `info`: <span style="color:lightgray">LIGHT GRAY</span>
- `debug`: <span style="color:cyan">CYAN</span>

Examples:

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

Sets the syslog [facility](https://en.wikipedia.org/wiki/Syslog#Facility); only meaningful when [`*.output`](#output) is `syslog`.

The available facilites are

auth | daemon | mail | uucp | local2 | local5
authpriv | ftp | news | local0 | local3 | local6
cron | lpr | user | local1 | local4 | local7

- {{ page.url-log-facility }}
- {{ page.url-vlog-facility }}

### Tag

Text tag that will be added to each message of the corresponding log type. The tag will be added after the message level, inside square brackets.

It's a simple means to differentiate each message according to its type, useful if both log types are [enabled](#enabled), and are printing to the same [`*.output`](#output).

Example:

{% highlight bash %}
$ {{ page.command }} --log.tag="!Operation!" --validation-log.tag="!Validation!" (...)
ERR [!Operation!]: Invalid rsync.enabled: 'tr0ue', must be boolean (true|false)
ERR [!Validation!]: rsync://rpki.example.com/foo/bar/baz.cer: Certificate validation failed: certificate has expired
{% endhighlight %}

- {{ page.url-log-tag }}
- {{ page.url-vlog-tag }}
