---
title: Program Arguments
command: fort
description: Guide to use arguments of FORT Validator.
---

# {{ page.title }}

## Index

1. [Syntax](#syntax)
2. [Arguments](#arguments)
	1. [`--help`](#--help)
	2. [`--usage`](#--usage)
	3. [`--version`](#--version)
	5. [`--tal`](#--tal)
	4. [`--init-tals`](#--init-tals)
	4. [`--init-as0-tals`](#--init-as0-tals)
	6. [`--local-repository`](#--local-repository)
	7. [`--work-offline`](#--work-offline)
	8. [`--daemon`](#--daemon)
	10. [`--maximum-certificate-depth`](#--maximum-certificate-depth)
	11. [`--mode`](#--mode)
	12. [`--server.address`](#--serveraddress)
	13. [`--server.port`](#--serverport)
	14. [`--server.backlog`](#--serverbacklog)
	15. [`--server.interval.validation`](#--serverintervalvalidation)
	16. [`--server.interval.refresh`](#--serverintervalrefresh)
	17. [`--server.interval.retry`](#--serverintervalretry)
	18. [`--server.interval.expire`](#--serverintervalexpire)
	18. [`--server.deltas.lifetime`](#--serverdeltaslifetime)
	19. [`--slurm`](#--slurm)
	20. [`--log.enabled`](#--logenabled)
	21. [`--log.level`](#--loglevel)
	22. [`--log.output`](#--logoutput)
	23. [`--log.color-output`](#--logcolor-output)
	24. [`--log.file-name-format`](#--logfile-name-format)
	25. [`--log.facility`](#--logfacility)
	26. [`--log.tag`](#--logtag)
	27. [`--validation-log.enabled`](#--validation-logenabled)
	28. [`--validation-log.level`](#--validation-loglevel)
	29. [`--validation-log.output`](#--validation-logoutput)
	30. [`--validation-log.color-output`](#--validation-logcolor-output)
	31. [`--validation-log.file-name-format`](#--validation-logfile-name-format)
	32. [`--validation-log.facility`](#--validation-logfacility)
	33. [`--validation-log.tag`](#--validation-logtag)
	34. [`--http.enabled`](#--httpenabled)
	35. [`--http.priority`](#--httppriority)
	36. [`--http.retry.count`](#--httpretrycount)
	37. [`--http.retry.interval`](#--httpretryinterval)
	38. [`--http.user-agent`](#--httpuser-agent)
	38. [`--http.max-redirs`](#--httpmax-redirs)
	39. [`--http.connect-timeout`](#--httpconnect-timeout)
	40. [`--http.transfer-timeout`](#--httptransfer-timeout)
	41. [`--http.low-speed-limit`](#--httplow-speed-limit)
	41. [`--http.low-speed-time`](#--httplow-speed-time)
	41. [`--http.max-file-size`](#--httpmax-file-size)
	42. [`--http.ca-path`](#--httpca-path)
	43. [`--output.roa`](#--outputroa)
	44. [`--output.bgpsec`](#--outputbgpsec)
	45. [`--output.format`](#--outputformat)
	46. [`--asn1-decode-max-stack`](#--asn1-decode-max-stack)
	48. [`--thread-pool.server.max`](#--thread-poolservermax)
	50. [`--rsync.enabled`](#--rsyncenabled)
	51. [`--rsync.priority`](#--rsyncpriority)
	53. [`--rsync.retry.count`](#--rsyncretrycount)
	54. [`--rsync.retry.interval`](#--rsyncretryinterval)
	55. [`--configuration-file`](#--configuration-file)
	56. [`rsync.program`](#rsyncprogram)
	57. [`rsync.arguments-recursive`](#rsyncarguments-recursive)
	59. [`incidences`](#incidences)
3. [Deprecated arguments](#deprecated-arguments)
	9. [`--shuffle-uris`](#--shuffle-uris)
	47. [`--stale-repository-period`](#--stale-repository-period)
	52. [`--rsync.strategy`](#--rsyncstrategy)
	58. [`rsync.arguments-flat`](#rsyncarguments-flat)
	49. [`--thread-pool.validation.max`](#--thread-poolvalidationmax)

## Syntax

```
{{ page.command }}
	[--help]
	[--usage]
	[--version]
	[--configuration-file=<file>]
	[--tal=<file>|<directory>]
	[--local-repository=<directory>]
	[--sync-strategy=off|root|root-except-ta]
	[--shuffle-uris=true|false]
	[--maximum-certificate-depth=<unsigned integer>]
	[--slurm=<file>|<directory>]
	[--mode=server|standalone]
	[--work-offline=true|false]
	[--daemon=true|false]
	[--server.address=<sequence of strings>]
	[--server.port=<string>]
	[--server.backlog=<unsigned integer>]
	[--server.interval.validation=<unsigned integer>]
	[--server.interval.refresh=<unsigned integer>]
	[--server.interval.retry=<unsigned integer>]
	[--server.interval.expire=<unsigned integer>]
	[--server.deltas.lifetime=<unsigned integer>]
	[--rsync.enabled=true|false]
	[--rsync.priority=<32-bit unsigned integer>]
	[--rsync.strategy=root|root-except-ta]
	[--rsync.retry.count=<unsigned integer>]
	[--rsync.retry.interval=<unsigned integer>]
	[--rrdp.enabled=true|false]
	[--rrdp.priority=<32-bit unsigned integer>]
	[--rrdp.retry.count=<unsigned integer>]
	[--rrdp.retry.interval=<unsigned integer>]
	[--http.enabled=true|false]
	[--http.priority=<32-bit unsigned integer>]
	[--http.retry.count=<unsigned integer>]
	[--http.retry.interval=<unsigned integer>]
	[--http.user-agent=<string>]
	[--http.connect-timeout=<unsigned integer>]
	[--http.transfer-timeout=<unsigned integer>]
	[--http.low-speed-limit=<unsigned integer>]
	[--http.low-speed-time=<unsigned integer>]
	[--http.max-file-size=<unsigned integer>]
	[--http.ca-path=<directory>]
	[--log.enabled=true|false]
	[--log.output=syslog|console]
	[--log.level=error|warning|info|debug]
	[--log.tag=<string>]
	[--log.facility=auth|authpriv|cron|daemon|ftp|lpr|mail|news|user|uucp|local0|local1|local2|local3|local4|local5|local6|local7]
	[--log.file-name-format=global-url|local-path|file-name]
	[--log.color-output=true|false]
	[--validation-log.enabled=true|false]
	[--validation-log.output=syslog|console]
	[--validation-log.level=error|warning|info|debug]
	[--validation-log.tag=<string>]
	[--validation-log.facility=auth|authpriv|cron|daemon|ftp|lpr|mail|news|user|uucp|local0|local1|local2|local3|local4|local5|local6|local7]
	[--validation-log.file-name-format=global-url|local-path|file-name]
	[--validation-log.color-output=true|false]
	[--output.roa=<file>]
	[--output.bgpsec=<file>]
	[--output.format=csv|json]
	[--asn1-decode-max-stack=<unsigned integer>]
	[--stale-repository-period=<unsigned integer>]
	[--init-tals=true|false]
	[--init-as0-tals=true|false]
	[--thread-pool.server.max=<unsigned integer>]
	[--thread-pool.validation.max=<unsigned integer>]
```

If an argument is specified more than once, the last one takes precedence:

{% highlight bash %}
$ {{ page.command }} --tal="foo"                          # tal is "foo"
$ {{ page.command }} --tal="foo" --tal="bar"              # tal is "bar"
$ {{ page.command }} --tal="foo" --tal="bar" --tal="qux"  # tal is "qux"
{% endhighlight %}

## Arguments

### `--help`

- **Type:** None
- **Availability:** `argv` only

Prints a medium-sized description of the command-line syntax, then exits.

{% highlight bash %}
$ {{ page.command }} --help
Usage: {{ page.command }}
	[--help]
		(Give this help list)
	[--usage]
		(Give a short usage message)
	[--version]
		(Print program version)
	...
	[--init-as0-tals=true|false]
		(Fetch the currently-known AS0 TAL files into --tal)
	[--thread-pool.server.max=<unsigned integer>]
		(Maximum number of active threads (one thread per RTR client) that can live at the thread pool)
	[--thread-pool.validation.max=<unsigned integer>]
		(Maximum number of active threads (one thread per TAL) that can live at the thread pool)
{% endhighlight %}

The slightly larger usage message is `man {{ page.command }}` and the large usage message is this documentation.

### `--usage`

- **Type:** None
- **Availability:** `argv` only

Prints a small-sized syntax reminder message, then exits.

{% highlight bash %}
$ {{ page.command }} --usage
Usage: {{ page.command }}
        [--help]
        [--usage]
        [--version]
	...
        [--log.file-name-format=global-url|local-path|file-name]
        [--output.roa=<file>]
        [--output.bgpsec=<file>]
{% endhighlight %}

### `--version`

- **Type:** None
- **Availability:** `argv` only

Prints the program's version, then exits.

{% highlight bash %}
$ {{ page.command }} --version
fort {{ site.fort-latest-version }}
{% endhighlight %}

### `--tal`

- **Type:** String (Path to file or directory)
- **Availability:** `argv` and JSON

Path to the _Trust Anchor Locator_ (TAL), or to a directory that contains TALs.

A TAL is a file that points to a _Trust Anchor_ (TA). A TA is an RPKI tree's root certificate.

The reason why you provide locators instead of anchors is to allow the latter to be officially updated without the need to awkwardly redistribute them. (TALs rarely need to change.)

Registries which own TAs are responsible for providing you with their TALs. For convenience, you can use [`--init-tals`](#--init-tals) and [`--init-as0-tals`](#--init-as0-tals) to speed up and automate this process. Alternatively, by following these links, you can download them manually:

- [AFRINIC](https://afrinic.net/resource-certification/tal)
- [APNIC](https://www.apnic.net/community/security/resource-certification/tal-archive/)
- [ARIN](https://www.arin.net/resources/manage/rpki/tal/)
- [LACNIC](https://www.lacnic.net/4984/2/lacnic/rpki-rpki-trust-anchor)
- [RIPE NCC](https://www.ripe.net/manage-ips-and-asns/resource-management/rpki/ripe-ncc-rpki-trust-anchor-structure)

The TAL file format has been standardized in [RFC 8630](https://tools.ietf.org/html/rfc8630). It is a text file that contains zero or more comments (each comment must start with the character "#" and end with a line break), a list of URLs (which serve as alternate access methods for the TA), followed by a blank line, followed by the Base64-encoded public key of the TA.

Just for completeness sake, here's an example on what a typical TAL looks like:

```
https://rpki.example.com/repository/root-ca.cer
rsync://rpki.example.com/repository/root-ca.cer

MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsqS+PDB1kArJlBTHeYCu
4anCWv8DzE8fHHexlGBm4TQBWC0IhNVbpUFg7SOp/7VddcGWyPZQRfdpQi4fdaGu
d6JJcGRECibaoc0Gs+d2mNyFJ1XXNppLMr5WH3iaL86r00jAnGJiCiNWzz7Rwyvy
UH0Z4lO12h+z0Zau7ekJ2Oz9to+VcWjHzV4y6gcK1MTlM6fMhKOzQxEA3TeDFgXo
SMiU+kLHI3dJhv4nJpjc0F+8+6hokIbF0p79yaCgyk0IGz7W3oSPa13KLN6mIPs6
4/UUJU5DDQvdq5T9FRF0I1mdtLToLSBnDCkTAAC6486UYV1j1Yzv1+DWJHSmiLna
LQIDAQAB
```

### `--init-tals`

- **Type:** None
- **Availability:** `argv` only

Downloads the currently known core TALs into the [`--tal`](#--tal) directory, then exits. It's a convenience option, meant for quick TAL retrieval, in case you don't have a more formal means to do it.

```bash
$ {{ page.command }} --init-tals --tal /etc/fort/tal
Jul 30 12:00:55 DBG: HTTP GET: https://rpki.afrinic.net/tal/afrinic.tal
Successfully fetched '/etc/fort/tal/afrinic.tal'!

Jul 30 12:00:57 DBG: HTTP GET: https://tal.apnic.net/apnic.tal
Successfully fetched '/etc/fort/tal/apnic.tal'!

Jul 30 12:01:04 DBG: HTTP GET: https://www.arin.net/resources/manage/rpki/arin.tal
Successfully fetched '/etc/fort/tal/arin.tal'!

Jul 30 12:01:05 DBG: HTTP GET: https://www.lacnic.net/innovaportal/file/4983/1/lacnic.tal
Successfully fetched '/etc/fort/tal/lacnic.tal'!

Jul 30 12:01:06 DBG: HTTP GET: https://tal.rpki.ripe.net/ripe-ncc.tal
Successfully fetched '/etc/fort/tal/ripe-ncc.tal'!
```

This flag can be used in conjunction with `--init-as0-tals`.

### `--init-as0-tals`

- **Type:** None
- **Availability:** `argv` only

Download the currently known _AS0 Trust Anchor Locators_ (AS0 TALs) into the [`--tal`](#--tal) directory, then exit.

Here's an example. The following command downloads the AS0 TALs into `/etc/fort/tal` (assuming it exists, and is a writable directory):

```bash
$ {{ page.command }} --init-as0-tals --tal /etc/fort/tal
Jul 30 12:02:51 DBG: HTTP GET: https://tal.apnic.net/apnic-as0.tal
Successfully fetched '/etc/fort/tal/apnic-as0.tal'!

Jul 30 12:02:52 DBG: HTTP GET: https://www.lacnic.net/innovaportal/file/4983/1/lacnic-as0.tal
Successfully fetched '/etc/fort/tal/lacnic-as0.tal'!
```

This flag can be used in conjunction with `--init-tals`.

### `--local-repository`

- **Type:** String (Path to directory)
- **Availability:** `argv` and JSON
- **Default:** `/tmp/fort/repository`

Path to the directory where Fort will store a local cache of the entire repository trees.

This cache is updated (based on the trees pointed by the TALs) during every validation cycle, and Fort's entire validation process operates on it.

Assuming not much time has passed since the last time the repository was cached, updating the cache is most of the time much faster than downloading it from scratch. You're therefore encouraged to keep it around.

### `--work-offline`

- **Type:** Boolean (`true`, `false`)
- **Availability:** `argv` and JSON

Skip the repository cache update?

If `true`, Fort will disable all outgoing RRDP and RSYNC requests during the validation cycle. The validation results will be entirely based on the (possibly outdated) existing cache. ([`--local-repository`](#--local-repository))

Mostly intended for debugging. See [`--rsync.enabled`](#--rsyncenabled) and [`--http.enabled`](#--httpenabled) if you want to disable a specific protocol.

### `--daemon`

- **Type:** Boolean (`true`, `false`)
- **Availability:** `argv` and JSON

Send process to the background?

All enabled logs will be sent to syslog; [`--log.output`](#--logoutput) and [`--validation-log.output`](#--validation-logoutput) will be ignored.

### `--maximum-certificate-depth`

- **Type:** Integer
- **Availability:** `argv` and JSON
- **Default:** 32
- **Range:** [5, [`UINT_MAX`](http://pubs.opengroup.org/onlinepubs/9699919799/basedefs/limits.h.html))

Maximum allowable RPKI tree height. Meant to protect Fort from iterating infinitely due to certificate chain loops.

Fort's tree traversal is actually iterative (not recursive), so there should be no risk of stack overflow, regardless of this value.

### `--mode`

- **Type:** Enumeration (`server`, `standalone`)
- **Availability:** `argv` and JSON
- **Default:** `server`

In `server` mode, Fort runs endlessly, performing RPKI validation cycles [repeatedly](#--serverintervalvalidation). In parallel, it also starts an [RTR server](#--serveraddress) that will perpetually serve the validation results to upcoming RTR clients. (Which are usually routers.)

In `standalone` mode, Fort simply performs one immediate RPKI validation, then exits. This mode is usually coupled with [`--output.roa`](#--outputroa).

### `--server.address`

- **Type:** String array
- **Availability:** `argv` and JSON
- **Default:** `NULL`

List of hostnames or numeric host addresses the RTR server will be bound to. Must resolve to (or be) bindable IP addresses. IPv4 and IPv6 are supported.

The address list must be comma-separated, and each address must have the following format: `<address>[#<port>]`. The port defaults to [`--server.port`](#--serverport).

Here are some examples:
- `--server.address="localhost"`: Bind to 'localhost', port [`--server.port`](#--serverport).
- `--server.address="localhost, ::1#8324"`: Same as above, and also bind to IPv6 address '::1', port '8324'.
- `--server.address="localhost#8323, ::1#8324"`: Bind to 'localhost' at port '8323', and to '::1' port '8324'. [`--server.port`](#--serverport) is ignored.

If this field is omitted, the server will accept connections on any of the host's network addresses.

### `--server.port`

- **Type:** String
- **Availability:** `argv` and JSON
- **Default:** `"323"`

TCP port or service the server address(es) will be bound to, if [`--server.address`](#--serveraddress) doesn't override it.

This is a string because a service alias can be used as a valid value. The available aliases are commonly located at `/etc/services`. (See '`$ man 5 services`'.)

> ![img/warn.svg](img/warn.svg) The default port is privileged. To improve security, either change or jail it. See [Non root port binding](run.html#non-root-port-binding).

### `--server.backlog`

- **Type:** Integer
- **Availability:** `argv` and JSON
- **Default:** [`SOMAXCONN`](http://pubs.opengroup.org/onlinepubs/9699919799.2008edition/basedefs/sys_socket.h.html)
- **Range:** [1, `SOMAXCONN`]

RTR server's listen queue length. It is the second argument of [`listen()`](http://pubs.opengroup.org/onlinepubs/9699919799.2008edition/functions/listen.html):

> The backlog argument provides a hint to the implementation which the implementation shall use to limit the number of outstanding connections in the socket's listen queue. Implementations may impose a limit on backlog and silently reduce the specified value. Normally, a larger backlog argument value shall result in a larger or equal length of the listen queue. Implementations shall support values of backlog up to SOMAXCONN, defined in <sys/socket.h>.

See the corresponding manual page from your operating system (likely `man 2 listen`) for specific implementation details.

### `--server.interval.validation`

- **Type:** Integer
- **Availability:** `argv` and JSON
- **Default:** 3600
- **Range:** [60, [`UINT_MAX`](http://pubs.opengroup.org/onlinepubs/9699919799/basedefs/limits.h.html)]

Number of seconds Fort will sleep between validation cycles, when in [`server`](#--mode) mode.

The timer starts counting every time a validation is finished, not every time it begins. The actual validation loop is, therefore, longer than this number.

"Validation cycle" includes the rsync update along with the validation operation. Because you are taxing the global repositories every time the validator performs a cache synchronization, it is recommended not to reduce the validation interval to the point you might be contributing to DoS'ing the global repository. The minimum value (60) was taken from the [RRDP RFC](https://tools.ietf.org/html/rfc8182#section-3.1), which means it's not necessarily a good value for heavy rsyncs.

### `--server.interval.refresh`

- **Type:** Integer
- **Availability:** `argv` and JSON
- **Default:** 3600
- **Range:** [1, 86400]

To synchronize their cache of RPKI prefix origin data and router keys, RTR clients (routers) poll Fort's RTR Server at regular intervals.

`--server.interval.refresh` is the length of that interval (in seconds), as _suggested_ by Fort, to the RTR clients. It is only employed if the peers manage to negociate usage of the RTRv1 protocol for the communication.

See [RFC 8210, section 6](https://tools.ietf.org/html/rfc8210#section-6).

### `--server.interval.retry`

- **Type:** Integer
- **Availability:** `argv` and JSON
- **Default:** 600
- **Range:** [1, 7200]

To synchronize their cache of RPKI prefix origin data and router keys, RTR clients (routers) poll Fort's RTR Server at regular intervals.

`--server.interval.retry` is the number of seconds a router should wait before retrying a failed synchronization. It is _suggested_ to them by Fort, and only employed if the peers manage to negociate usage of the RTRv1 protocol for the communication.

See [RFC 8210, section 6](https://tools.ietf.org/html/rfc8210#section-6).

### `--server.interval.expire`

- **Type:** Integer
- **Availability:** `argv` and JSON
- **Default:** 7200
- **Range:** [600, 172800]

To synchronize their cache of RPKI prefix origin data and router keys, RTR clients (routers) poll Fort's RTR Server at regular intervals.

`--server.interval.expire` is the number of seconds a router should retain their data while unable to perform a successful synchronization with Fort. It is _suggested_ to them by Fort, and only employed if the peers manage to negociate usage of the RTRv1 protocol for the communication.

See [RFC 8210, section 6](https://tools.ietf.org/html/rfc8210#section-6).

### `--server.deltas.lifetime`

- **Type:** Integer
- **Availability:** `argv` and JSON
- **Default:** 2
- **Range:** [0, [`UINT_MAX`](http://pubs.opengroup.org/onlinepubs/9699919799/basedefs/limits.h.html)]

When routers first connect to Fort, they request a _snapshot_ of the validation results. (ROAs and Router Keys.) Because they need to keep their validated objects updated, and snapshots tend to be relatively large amounts of information, they request _deltas_ afterwards over configurable intervals. ("Deltas" being the differences between snapshots.)

During each validation cycle, Fort generates a new snapshot, as well as the deltas needed to build the new snapshot from the previous one. These are all stored in RAM. `--server.deltas.lifetime` is the number of iterations a set of deltas will be kept before being deallocated. (Recall that every iteration lasts [`--server.interval.validation`](#--serverintervalvalidation) seconds, plus however long the validation takes.)

If a router lags behind, to the point Fort has already deleted the deltas it needs to update the router's snapshot, Fort will have to fall back to fetch the entire latest snapshot instead.

### `--slurm`

- **Type:** String (path to file or directory)
- **Availability:** `argv` and JSON
- **Default:** `NULL`

SLURM file, or directory containing SLURM files. See [SLURM](slurm.html).

### `--log.enabled`

- **Type:** Boolean (`true`, `false`)
- **Availability:** `argv` and JSON
- **Default:** `true`

Enable the operation logs?

See [Logging](logging.html).

### `--log.level`

- **Type:** Enumeration (`error`, `warning`, `info`, `debug`)
- **Availability:** `argv` and JSON
- **Default:** `warning`

Minimum allowed severity of operation log messages. (Lower severity messages will be dropped.) The highest priority is `error`, and the lowest is `debug`.

For example, `--log.level=warning` will cause only `warning` and `error` messages to be logged.

See [Logging > Configuration > Level](logging.html#level).

### `--log.output`

- **Type:** Enumeration (`syslog`, `console`)
- **Availability:** `argv` and JSON
- **Default:** `console`

Desired target that will take care of actually printing the operation logs.

`console` will log messages in the standard streams; `syslog` will log on [Syslog](https://en.wikipedia.org/wiki/Syslog).

See [Logging > Configuration > Output](logging.html#output).

### `--log.color-output`

- **Type:** Boolean (`true`, `false`)
- **Availability:** `argv` and JSON
- **Default:** `false`

Include ANSI color codes in the logging? Meant to ease human consumption. Only applies when [`--log.output`](#--logoutput) is `console`.

See [Logging > Configuration > Color output](logging.html#color-output).

### `--log.file-name-format`

- **Type:** Enumeration (`global-url`, `local-path`, `file-name`)
- **Availability:** `argv` and JSON
- **Default:** `global-url`

Decides which version of file names should be printed during most debug/error messages at the operation logs.

See [Logging > Configuration > File name format](logging.html#file-name-format).

### `--log.facility`

- **Type:** Enumeration (`auth`, `authpriv`, `cron`, `daemon`, `ftp`, `lpr`, `mail`, `news`, `user`, `uucp`, from `local0` to `local7`)
- **Availability:** `argv` and JSON
- **Default:** `daemon`

Syslog facility utilized for operation logs (meaningful only if [`--log.output`](#--logoutput) is `syslog`).

See [Logging > Configuration > Facility](logging.html#facility).

### `--log.tag`

- **Type:** String
- **Availability:** `argv` and JSON
- **Default:** `NULL`

Prefix tag that will be added to all operation log messages. It's meant to help identify operation logs from other types of logs.

The tag will be surrounded by square brackets.

See [Logging > Configuration > Tag](logging.html#tag).

### `--validation-log.enabled`

- **Type:** Boolean (`true`, `false`)
- **Availability:** `argv` and JSON
- **Default:** `false`

Enable the validation logs?

See [Logging](logging.html).

### `--validation-log.level`

- **Type:** Enumeration (`error`, `warning`, `info`, `debug`)
- **Availability:** `argv` and JSON
- **Default:** `warning`

Minimum allowed severity of validation log messages. (Lower severity messages will be dropped.) The highest priority is `error`, and the lowest is `debug`.

For example, `--validation-log.level=warning` will cause only warning and error messages to be logged.

See [Logging > Configuration > Level](logging.html#level).

### `--validation-log.output`

- **Type:** Enumeration (`syslog`, `console`)
- **Availability:** `argv` and JSON
- **Default:** `console`

Desired target that will take care of actually printing the validation logs.

`console` will log messages in the standard streams; `syslog` will log on Syslog.

See [Logging > Configuration > Output](logging.html#output).

### `--validation-log.color-output`

- **Type:** Boolean (`true`, `false`)
- **Availability:** `argv` and JSON
- **Default:** `false`

Include ANSI color codes in the logging? Meant to ease human consumption. Only applies when `--validation-log.output` is `console`.

See [Logging > Configuration > Color output](logging.html#color-output).

### `--validation-log.file-name-format`

- **Type:** Enumeration (`global-url`, `local-path`, `file-name`)
- **Availability:** `argv` and JSON
- **Default:** `global-url`

Decides which version of file names should be printed during most debug/error messages at the validation logs.

See [Logging > Configuration > File name format](logging.html#file-name-format).

### `--validation-log.facility`

- **Type:** Enumeration (`auth`, `authpriv`, `cron`, `daemon`, `ftp`, `lpr`, `mail`, `news`, `user`, `uucp`, from `local0` to `local7`)
- **Availability:** `argv` and JSON
- **Default:** `daemon`

Syslog facility utilized for validation logs (meaningful only if [`--validation-log.output`](#--validation-logoutput) is `syslog`).

See [Logging > Configuration > Facility](logging.html#facility).

### `--validation-log.tag`

- **Type:** String
- **Availability:** `argv` and JSON
- **Default:** `Validation`

Prefix tag that will be added to all operation log messages. It's meant to help identify operation logs from other types of logs.

The tag will be surrounded by square brackets.

See [Logging > Configuration > Tag](logging.html#tag).

### `--http.enabled`

- **Type:** Boolean (`true`, `false`)
- **Availability:** `argv` and JSON
- **Default:** `true`

Enable HTTP requests during validation?

If disabled (`--http.enabled=false`), Fort will skip all outgoing HTTP requests during the validation cycle. The relevant validation results will be entirely based on the (possibly outdated) existing cache. ([`--local-repository`](#--local-repository))

Mostly intended for debugging.

### `--http.priority`

- **Type:** Integer
- **Availability:** `argv` and JSON
- **Default:** 60
- **Range:** [0, 100]

HTTP's (and therefore RRDP's) precedence when choosing the protocol used to download files (assuming Fort has to choose, and both protocols are [enabled](#--httpenabled)). The protocol with the highest priority is used first, and the runner-up is employed as fallback.

> At the moment, only two protocols (RRDP/HTTP and RSYNC) are supported. Yes, `--http.priority`'s range is overkill.

See [`--rsync.priority`](#--rsyncpriority).

### `--http.retry.count`

- **Type:** Integer
- **Availability:** `argv` and JSON
- **Default:** 0
- **Range:** [0, [`UINT_MAX`](http://pubs.opengroup.org/onlinepubs/9699919799/basedefs/limits.h.html)]

Number of additional HTTP requests after a failed attempt.

If a transient error is returned when Fort tries to perform an HTTP transfer, it will retry this number of times before giving up. Setting the number to 0 makes Fort do no retries (which is the default). "Transient error" is a timeout, an HTTP 408 response code, or an HTTP 5xx response code.

### `--http.retry.interval`

- **Type:** Integer
- **Availability:** `argv` and JSON
- **Default:** 5
- **Range:** [0, [`UINT_MAX`](http://pubs.opengroup.org/onlinepubs/9699919799/basedefs/limits.h.html)]

Period of time (in seconds) to wait between each retry to request an HTTP URI.

### `--http.user-agent`

- **Type:** String
- **Availability:** `argv` and JSON
- **Default:** `{{ page.command }}/{{ site.fort-latest-version }}`

_**All requests are made using HTTPS, verifying the peer and the certificate name vs host**_

User-Agent to use at HTTP requests.

The value specified (either by the argument or the default value) is utilized in libcurl's option [CURLOPT_USERAGENT](https://curl.haxx.se/libcurl/c/CURLOPT_USERAGENT.html).

### `--http.max-redirs`

- **Type:** Integer
- **Availability:** `argv` and JSON
- **Default:** 10
- **Range:** [0, [`UINT_MAX`](http://pubs.opengroup.org/onlinepubs/9699919799/basedefs/limits.h.html)]

Maximum allowed number of redirections to follow per HTTP request. (The total number of requests is `--http.max-redirs + 1`.)

Unlike [`curl`'s `--max-redirs`](https://curl.se/docs/manpage.html#--max-redirs), Fort does not provide a means to allow for infinite redirects.

### `--http.connect-timeout`

- **Type:** Integer
- **Availability:** `argv` and JSON
- **Default:** 30
- **Range:** [1, [`UINT_MAX`](http://pubs.opengroup.org/onlinepubs/9699919799/basedefs/limits.h.html)]

_**All requests are made using HTTPS, verifying the peer and the certificate name vs host**_

Timeout (in seconds) for the connect phase.

Whenever an HTTP connection will try to be established, the validator will wait a maximum of `http.connect-timeout` for the peer to respond to the connection request; if the timeout is reached, the connection attempt will be aborted.

The value specified (either by the argument or the default value) is utilized in libcurl's option [CURLOPT_CONNECTTIMEOUT](https://curl.haxx.se/libcurl/c/CURLOPT_CONNECTTIMEOUT.html).

### `--http.transfer-timeout`

- **Type:** Integer
- **Availability:** `argv` and JSON
- **Default:** 0
- **Range:** [0, [`UINT_MAX`](http://pubs.opengroup.org/onlinepubs/9699919799/basedefs/limits.h.html)]

_**All requests are made using HTTPS, verifying the peer and the certificate name vs host**_

Maximum time in seconds (once the connection is established) that the request can last.

Once the connection is established with the server, the request will last a maximum of `http.transfer-timeout` seconds. A value of 0 means unlimited time.

The value specified (either by the argument or the default value) is utilized in libcurl's option [CURLOPT_TIMEOUT](https://curl.haxx.se/libcurl/c/CURLOPT_TIMEOUT.html).

### `--http.low-speed-limit`

- **Type:** Integer
- **Availability:** `argv` and JSON
- **Default:** 100000 (100 kilobytes/second)
- **Range:** [0, [`UINT_MAX`](http://pubs.opengroup.org/onlinepubs/9699919799/basedefs/limits.h.html)]

The value Fort employs as [CURLOPT_LOW_SPEED_LIMIT](https://curl.haxx.se/libcurl/c/CURLOPT_LOW_SPEED_LIMIT.html) during every HTTP transfer.

It is the average transfer speed (in bytes per second) that HTTP transfers (between Fort and RPKI repositories) should be below during [`--http.low-speed-time`](#--httplow-speed-time) seconds for Fort to consider it to be too slow. (Slow connections are dropped.)

For example:

```
--http.low-speed-limit 30 --http.low-speed-time 60
```

Whenever Fort attempts to retrieve a file from an RPKI repository through HTTP, it will abort the transfer if the connection stays slower than 30 bytes per second, over a period of 60 seconds.

The intent is to prevent malicious repositories from slowing down Fort.

Zero disables the validation.

### `--http.low-speed-time`

- **Type:** Integer
- **Availability:** `argv` and JSON
- **Default:** 10
- **Range:** [0, [`UINT_MAX`](http://pubs.opengroup.org/onlinepubs/9699919799/basedefs/limits.h.html)]

The value Fort employs as [CURLOPT_LOW_SPEED_TIME](https://curl.haxx.se/libcurl/c/CURLOPT_LOW_SPEED_TIME.html) during every HTTP transfer.

It is the number of seconds that the transfer speed should be below `--http.low-speed-limit` for the Fort to consider it too slow. (Slow connections are dropped.)

See [`--http.low-speed-limit`](#--httplow-speed-limit) for an example.

### `--http.max-file-size`

- **Type:** Integer
- **Availability:** `argv` and JSON
- **Default:** 1,000,000,000 (1 Gigabyte)
- **Range:** [0, 2000000000] (2 Gigabytes)

The maximum amount of bytes files are allowed to length during HTTP transfers. Files that exceed this limit are dropped, either early (through [CURLOPT_MAXFILESIZE](https://curl.haxx.se/libcurl/c/CURLOPT_MAXFILESIZE.html)) or as they hit the limit (when the file size is not known prior to download).

This is intended to prevent malicious RPKI repositories from stagnating Fort.

As of 2021-10-05, the largest legitimate file in the repositories is an RRDP snapshot that weights ~150 megabytes. (But will double in size during key rollover.)

This configuration value is _transient_. It is expected that the IETF will eventually standardize a more versatile means to prevent unbounded file transfers. In particular, because RRDP snapshots tend to grow over time, `--http.max-file-size`'s default value will likely eventually be exceeded by legitimate files.

Watch out for the following warning in the operation logs:

	File size exceeds 50% of the configured limit

### `--http.ca-path`

- **Type:** String (Path to directory)
- **Availability:** `argv` and JSON

_**All requests are made using HTTPS, verifying the peer and the certificate name vs host**_

Path to a directory containing CA certificates, which Fort might employ to verify peers while performing HTTPS requests.

Useful when the CA from the peer isn't located at the default OS certificate bundle. If specified, the peer certificate will be verified using the CAs at the path. The directory MUST be prepared using the `rehash` utility from the SSL library:

- OpenSSL command (with help): `$ openssl rehash -h`
- LibreSSL command (with help): `$ openssl certhash -h`

The value specified is utilized in libcurl's option [CURLOPT_CAPATH](https://curl.haxx.se/libcurl/c/CURLOPT_CAPATH.html).

### `--output.roa`

- **Type:** String (Path to file)
- **Availability:** `argv` and JSON

File where the ROAs (found during each validation run) will be stored. See [`--output.format`](#--outputformat).

If the file already exists, it will be overwritten. If it doesn't exist, it will be created. To print to standard output, use a hyphen (`-`). If the RTR server is [enabled](#--mode), then the ROAs will be printed every [`--server.interval.validation`](#--serverintervalvalidation) secs.

When `--output.format` equals `csv`, each line of the result is printed in the following order: _AS, Prefix, Max prefix length_. The first line contains the column names.

When `--output.format` equals `json`, each element is printed in an object array of `roas`:

{% highlight json %}
{
	"roas": [
		{
			"asn": "AS64496",
			"prefix": "198.51.100.0/24",
			"maxLength": 24
		},
		{
			"asn": "AS64496",
			"prefix": "2001:DB8::/32",
			"maxLength": 48
		}
	]
}
{% endhighlight %}

If `--output.roa` is omitted, the ROAs are not printed.

### `--output.bgpsec`

- **Type:** String (Path to file)
- **Availability:** `argv` and JSON

> ![Warning!](img/warn.svg) BGPsec certificate validation has been disabled in version 1.5.2 because of [this bug](https://github.com/NICMx/FORT-validator/issues/58).

File where the BGPsec Router Keys (found during each validation run) will be stored. See [`--output.format`](#--outputformat).

Since most of the data (Subject Key Identifier and Subject Public Key Info) is binary, it is base64url-encoded, without trailing pads.

If the file already exists, it will be overwritten. If it doesn't exist, it will be created. To print to standard output, use a hyphen (`-`). If the RTR server is [enabled](#--mode), the BGPsec Router Keys will be printed every [`--server.interval.validation`](#--serverintervalvalidation) seconds.

When `--output.format` equals `csv`, each line of the result is printed in the following order: _AS, Subject Key Identifier, Subject Public Key Info_. The first line contains the column names.

When `--output.format` equals `json`, each element is printed in an object array of `router-keys`:

{% highlight json %}
{
	"router-keys": [
		{
			"asn": "AS64496",
			"ski": "<Base64 Encoded SKI>",
			"spki": "<Base64 Encoded SPKI>"
		},
		{
			"asn": "AS64497",
			"ski": "<Base64 Encoded SKI>",
			"spki": "<Base64 Encoded SPKI>"
		}
	]
}
{% endhighlight %}

If `--output.bgpsec` is ommited, then the BGPsec Router Keys are not printed.

### `--output.format`

- **Type:** Enumeration (`csv`, `json`)
- **Availability:** `argv` and JSON
- **Default:** `csv`

Output format for [`--output.roa`](#--outputroa) and [`--output.bgpsec`](#--outputbgpsec).

### `--asn1-decode-max-stack`

- **Type:** Integer
- **Availability:** `argv` and JSON
- **Default:** 4096
- **Range:** [1, [`UINT_MAX`](http://pubs.opengroup.org/onlinepubs/9699919799/basedefs/limits.h.html)]

ASN1 decoder max allowed stack size in bytes, utilized to avoid a stack overflow when a large nested ASN1 object is parsed.

This check is merely a caution, since ASN1 decoding functions are recursive and might cause a stack overflow. So, this argument probably won't be necessary in most cases, since the RPKI ASN1 objects don't have nested objects that require too much stack allocation (for now).

### `--thread-pool.server.max`

- **Type:** Integer
- **Availability:** `argv` and JSON
- **Default:** 20
- **Range:** [1, [`UINT_MAX`](http://pubs.opengroup.org/onlinepubs/9699919799/basedefs/limits.h.html)]

Number of threads the RTR server will reserve for RTR client (router) request handling. The server will be able to handle `--thread-pool.server.max` requests at most, at once. Additional requests will queue.

> Before Fort 1.5.1, this value used to represent the maximum number of client _connections_ the server would be able to hold at any given time. It scales better now.

### `--rsync.enabled`

- **Type:** Boolean (`true`, `false`)
- **Availability:** `argv` and JSON
- **Default:** `true`

Enables RSYNC requests during validation?

If disabled (`--rsync.enabled=false`), Fort will skip all outgoing RSYNC requests during the validation cycle. The relevant validation results will be entirely based on the (possibly outdated) existing cache. ([`--local-repository`](#--local-repository))

Mostly intended for debugging.

### `--rsync.priority`

- **Type:** Integer
- **Availability:** `argv` and JSON
- **Default:** 50
- **Range:** [0, 100]

RSYNC's precedence when choosing the protocol used to download files (assuming Fort has to choose, and both protocols are [enabled](#--rsyncenabled)). The protocol with the highest priority is used first, and the runner-up is employed as fallback.

> At the moment, only two protocols (RRDP/HTTP and RSYNC) are supported. Yes, `--rsync.priority`'s range is overkill.

See [`--http.priority`](#--httppriority).

### `--rsync.retry.count`

- **Type:** Integer
- **Availability:** `argv` and JSON
- **Default:** 0
- **Range:** [0, [`UINT_MAX`](http://pubs.opengroup.org/onlinepubs/9699919799/basedefs/limits.h.html)]

Maximum number of retries whenever there's an error executing an RSYNC.

A value of **0** means **no retries**.

Whenever is necessary to execute an RSYNC, the validator will try at least one time the execution. If there was an error executing the RSYNC, the validator will retry it at most `--rsync.retry.count` times, waiting [`--rsync.retry.interval`](#--rsyncretryinterval) seconds between each retry.

### `--rsync.retry.interval`

- **Type:** Integer
- **Availability:** `argv` and JSON
- **Default:** 5
- **Range:** [0, [`UINT_MAX`](http://pubs.opengroup.org/onlinepubs/9699919799/basedefs/limits.h.html)]

Period of time (in seconds) to wait between each retry to execute an RSYNC.

### `--configuration-file`

- **Type:** String (Path to file)
- **Availability:** `argv` only

Path to a JSON file from which additional configuration will be read.

The configuration options are mostly the same as the ones from the `argv` interface. (See the "Availability" metadata of each field.) Here's a (possibly slightly outdated) full configuration file example:

<pre><code>{
	"<a href="#--tal">tal</a>": "/tmp/fort/tal/",
	"<a href="#--local-repository">local-repository</a>": "/tmp/fort/repository/",
	"<a href="#--work-offline">work-offline</a>": false,
	"<a href="#--shuffle-uris">shuffle-uris</a>": true,
	"<a href="#--maximum-certificate-depth">maximum-certificate-depth</a>": 32,
	"<a href="#--mode">mode</a>": "server",
	"<a href="#--daemon">daemon</a>": false,
	"<a href="#--slurm">slurm</a>": "/tmp/fort/test.slurm",

	"server": {
		"<a href="#--serveraddress">address</a>": [
			"192.0.2.1",
			"2001:db8::1"
		],
		"<a href="#--serverport">port</a>": "8323",
		"<a href="#--serverbacklog">backlog</a>": 16,
		"interval": {
			"<a href="#--serverintervalvalidation">validation</a>": 3600,
			"<a href="#--serverintervalrefresh">refresh</a>": 3600,
			"<a href="#--serverintervalretry">retry</a>": 600,
			"<a href="#--serverintervalexpire">expire</a>": 7200
		},
		"deltas": {
			"<a href="#--serverdeltaslifetime">lifetime</a>": 4
		}
	},

	"log": {
		"<a href="#--logenabled">enabled</a>": true,
		"<a href="#--loglevel">level</a>": "warning",
		"<a href="#--logoutput">output</a>": "console",
		"<a href="#--logcolor-output">color-output</a>": true,
		"<a href="#--logfile-name-format">file-name-format</a>": "file-name",
		"<a href="#--logfacility">facility</a>": "daemon",
		"<a href="#--logtag">tag</a>": "Operation"
	},

	"validation-log": {
		"<a href="#--validation-logenabled">enabled</a>": false,
		"<a href="#--validation-loglevel">level</a>": "warning",
		"<a href="#--validation-logoutput">output</a>": "console",
		"<a href="#--validation-logcolor-output">color-output</a>": true,
		"<a href="#--validation-logfile-name-format">file-name-format</a>": "global-url",
		"<a href="#--validation-logfacility">facility</a>": "daemon",
		"<a href="#--validation-logtag">tag</a>": "Validation"
	},

	"http": {
		"<a href="#--httpenabled">enabled</a>": true,
		"<a href="#--httppriority">priority</a>": 60,
		"retry": {
			"<a href="#--httpretrycount">count</a>": 2,
			"<a href="#--httpretryinterval">interval</a>": 5
		},
		"<a href="#--httpuser-agent">user-agent</a>": "{{ page.command }}/{{ site.fort-latest-version }}",
		"<a href="#--httpconnect-timeout">connect-timeout</a>": 30,
		"<a href="#--httptransfer-timeout">transfer-timeout</a>": 0,
		"<a href="#--httplow-speed-limit">low-speed-limit</a>": 30,
		"<a href="#--httplow-speed-time">low-speed-time</a>": 10,
		"<a href="#--httpmax-file-size">max-file-size</a>": 10000000,
		"<a href="#--httpca-path">ca-path</a>": "/usr/local/ssl/certs"
	},

	"rsync": {
		"<a href="#--rsyncenabled">enabled</a>": true,
		"<a href="#--rsyncpriority">priority</a>": 50,
		"<a href="#--rsyncstrategy">strategy</a>": "root-except-ta",
		"retry": {
			"<a href="#--rsyncretrycount">count</a>": 2,
			"<a href="#--rsyncretryinterval">interval</a>": 5
		},
		"<a href="#rsyncprogram">program</a>": "rsync",
		"<a href="#rsyncarguments-recursive">arguments-recursive</a>": [
			"--recursive",
			"--delete",
			"--times",
			"--contimeout=20",
			"--timeout=15",
			"$REMOTE",
			"$LOCAL"
		],
		"<a href="#rsyncarguments-flat">arguments-flat</a>": [
			"--times",
			"--contimeout=20",
			"--timeout=15",
			"--dirs",
			"$REMOTE",
			"$LOCAL"
		]
	},

	"<a href="#incidences">incidences</a>": [
		{
			"name": "incid-hashalg-has-params",
			"action": "ignore"
		},
		{
			"name": "incid-obj-not-der-encoded",
			"action": "ignore"
		},
		{
			"name": "incid-file-at-mft-not-found",
			"action": "error"
		},
		{
			"name": "incid-file-at-mft-hash-not-match",
			"action": "error"
		},
		{
			"name": "incid-mft-stale",
			"action": "error"
		},
		{
			"name": "incid-crl-stale",
			"action": "error"
		}
	],

	"output": {
		"<a href="#--outputroa">roa</a>": "/tmp/fort/roas.csv",
		"<a href="#--outputbgpsec">bgpsec</a>": "/tmp/fort/bgpsec.csv",
		"<a href="#--outputformat">format</a>": "csv"
	},

	"thread-pool": {
		"server": {
			"<a href="#--thread-poolservermax">max</a>": 20
		},
		"validation": {
			"<a href="#--thread-poolvalidationmax">max</a>": 5
		}
	},

	"<a href="#--asn1-decode-max-stack">asn1-decode-max-stack</a>": 4096,
	"<a href="#--stale-repository-period">stale-repository-period</a>": 43200
}
</code></pre>

The file acts as a collection of equivalent `argv` arguments; precedence is not modified:

{% highlight bash %}
$ cat cfg.json
{
	"tal": "bar"
}

$ {{ page.command }} --tal="foo"                                              # tal is "foo"
$ {{ page.command }} --tal="foo" --configuration-file="cfg.json"              # tal is "bar"
$ {{ page.command }} --tal="foo" --configuration-file="cfg.json" --tal="qux"  # tal is "qux"

$ cat a.json
{
	"local-repository": "a",
	"rsync.strategy": "root",
	"maximum-certificate-depth": 5
}

$ cat b.json
{
	"rsync.strategy": "strict"
	"maximum-certificate-depth": 6
}

$ cat c.json
{
	"maximum-certificate-depth": 8
}

$ {{ page.command }} \
	--configuration-file="a.json" \
	--configuration-file="b.json" \
	--configuration-file="c.json"
$ # local-repository is "a", rsync.strategy is "strict" and maximum-certificate-depth is 8
{% endhighlight %}

### `rsync.program`

- **Type:** String
- **Availability:** JSON only
- **Default:** `"rsync"`

Name of the program needed to invoke an rsync file transfer.

### `rsync.arguments-recursive`

- **Type:** String array
- **Availability:** JSON only
- **Default:** `[ "--recursive", "--delete", "--times", "--omit-dir-times", "--contimeout=20", "--timeout=15", "--max-size=20MB", "$REMOTE", "$LOCAL" ]`

Arguments needed by [`rsync.program`](#rsyncprogram) to perform a recursive rsync.

Fort will replace `"$REMOTE"` with the remote URL it needs to download, and `"$LOCAL"` with the target local directory where the file is supposed to be dropped.

### `incidences`

- **Type:** JSON Object array
- **Availability:** JSON only

A listing of actions to be performed by validation upon encountering certain error conditions. See [Incidences](incidence.html).

## Deprecated arguments

### `--shuffle-uris`

- **Type:** Boolean (`true`, `false`)
- **Availability:** `argv` and JSON

> ![img/warn.svg](img/warn.svg) This argument **is DEPRECATED**.

Does nothing as of Fort 1.6.0.

### `--stale-repository-period`

- **Type:** Integer
- **Availability:** `argv` and JSON
- **Default:** 43200 (12 hours)
- **Range:** [0, [`UINT_MAX`](http://pubs.opengroup.org/onlinepubs/9699919799/basedefs/limits.h.html)]

> ![img/warn.svg](img/warn.svg) This argument **is DEPRECATED**.

Does nothing as of Fort 1.6.0.

### `--rsync.strategy`

- **Type:** Enumeration (`strict`, `root`, `root-except-ta`)
- **Availability:** `argv` and JSON
- **Default:** `root-except-ta`

> ![img/warn.svg](img/warn.svg) This argument **is DEPRECATED**.

Does nothing as of Fort 1.6.0.

### `rsync.arguments-flat`

- **Type:** String array
- **Availability:** JSON only
- **Default:** `[ "--times", "--contimeout=20", "--timeout=15", "--max-size=20MB", "--dirs", "$REMOTE", "$LOCAL" ]`

> ![img/warn.svg](img/warn.svg) This argument **is DEPRECATED**.

Does nothing as of Fort 1.6.0.

### `--thread-pool.validation.max`

- **Type:** Integer
- **Availability:** `argv` and JSON
- **Default:** 5
- **Range:** [1, 100]

> ![img/warn.svg](img/warn.svg) This argument **is DEPRECATED**.

Does nothing as of Fort 1.6.0.
