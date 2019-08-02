---
title: Fort Usage
command: fort
---

[Documentation](index.html) > {{ page.title }}

# {{ page.title }}

## Index

1. [Syntax](#syntax)
2. [Arguments](#arguments)
	1. [`--help`](#--help)
	2. [`--usage`](#--usage)
	3. [`--version`](#--version)
	4. [`--tal`](#--tal)
	5. [`--local-repository`](#--local-repository)
	6. [`--sync-strategy`](#--sync-strategy)
		1. [`off`](#off)
		2. [`strict`](#strict)
		3. [`root`](#root)
		4. [`root-except-ta`](#root-except-ta)
	7. [`--shuffle-uris`](#--shuffle-uris)
	8. [`--maximum-certificate-depth`](#--maximum-certificate-depth)
	9. [`--mode`](#--mode)
	10. [`--server.address`](#--serveraddress)
	11. [`--server.port`](#--serverport)
	12. [`--server.backlog`](#--serverbacklog)
	13. [`--server.validation-interval`](#--servervalidation-interval)
	14. [`--slurm`](#--slurm)
	15. [`--log.color-output`](#--logcolor-output)
	16. [`--log.file-name-format`](#--logfile-name-format)
	17. [`--output.roa`](#--outputroa)
	18. [`--configuration-file`](#--configuration-file)
	19. [`rsync.program`](#rsyncprogram)
	20. [`rsync.arguments-recursive`](#rsyncarguments-recursive)
	21. [`rsync.arguments-flat`](#rsyncarguments-flat)
	22. [`incidences`](#incidences)

## Syntax

```
{{ page.command }}
        [--help]
        [--usage]
        [--version]
        [--configuration-file=<file>]
        [--tal=<file>|<directory>]
        [--local-repository=<directory>]
        [--sync-strategy=off|strict|root|root-except-ta]
        [--shuffle-uris]
        [--maximum-certificate-depth=<unsigned integer>]
        [--mode=server|standalone]
        [--server.address=<string>]
        [--server.port=<string>]
        [--server.backlog=<unsigned integer>]
        [--server.validation-interval=<unsigned integer>]
        [--slurm=<file>|<directory>]
        [--log.color-output]
        [--log.file-name-format=global-url|local-path|file-name]
        [--output.roa=<file>]
```

If an argument is declared more than once, the last one takes precedence:

{% highlight bash %}
$ {{ page.command }} --tal="foo"                          # tal is "foo"
$ {{ page.command }} --tal="foo" --tal="bar"              # tal is "bar"
$ {{ page.command }} --tal="foo" --tal="bar" --tal="qux"  # tal is "qux"
{% endhighlight %}


## Arguments

### `--help`

- **Type:** None
- **Availability:** `argv` only

Prints medium-sized syntax remainder message.

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
        [--log.file-name-format=global-url|local-path|file-name]
            (File name variant to print during debug/error messages)
        [--output.roa=<file>]
            (File where the valid ROAs will be dumped.)
{% endhighlight %}

The slightly larger usage message is `man {{ page.command }}` and the large usage message is this documentation.

### `--usage`

- **Type:** None
- **Availability:** `argv` only

Prints small-sized syntax remainder message.

{% highlight bash %}
$ {{ page.command }} --usage
Usage: {{ page.command }}
        [--help]
        [--usage]
        [--version]
	...
        [--log.file-name-format=global-url|local-path|file-name]
        [--output.roa=<file>]
{% endhighlight %}

### `--version`

- **Type:** None
- **Availability:** `argv` only

Prints program version.

{% highlight bash %}
$ {{ page.command }} --version
fort 0.0.1
{% endhighlight %}

### `--tal`

- **Type:** String (Path to file)
- **Availability:** `argv` and JSON

Path to the _Trust Anchor Locator_ (TAL), or to a directory that contains TALs.

A TAL is a file that points to a _Trust Anchor_ (TA). A TA is a self-signed certificate that serves as root of an RPKI tree you want validated.

The reason why you provide locators instead of anchors is to allow the latter to be officially updated without the need to awkwardly redistribute them.

Whichever registry serves as root of the tree you want to validate is responsible for providing you with its TAL. For convenience, Fort currently ships with the TALs of four of the five RIRs. (The exception is ARIN's, since you need to read and accept an [agreement](https://www.arin.net/resources/manage/rpki/tal/) before you can use it.) If you installed the Debian package, they can be found at `/etc/fort/tal/`, otherwise it the `tal/` directory of whatever release tarball you downloaded.

If you are paranoid, however, you'd be advised to get your own TALs.

The TAL file format has been standardized in [RFC 7730](https://tools.ietf.org/html/rfc7730). It is a text file that contains a list of URLs (which serve as alternate access methods for the TA), followed by a blank line, followed by the Base64-encoded public key of the TA.

Just for completeness sake, here's an example on what a typical TAL looks like:

```
rsync://rpki.example.com/repository/root-ca.cer

MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsqS+PDB1kArJlBTHeYCu
4anCWv8DzE8fHHexlGBm4TQBWC0IhNVbpUFg7SOp/7VddcGWyPZQRfdpQi4fdaGu
d6JJcGRECibaoc0Gs+d2mNyFJ1XXNppLMr5WH3iaL86r00jAnGJiCiNWzz7Rwyvy
UH0Z4lO12h+z0Zau7ekJ2Oz9to+VcWjHzV4y6gcK1MTlM6fMhKOzQxEA3TeDFgXo
SMiU+kLHI3dJhv4nJpjc0F+8+6hokIbF0p79yaCgyk0IGz7W3oSPa13KLN6mIPs6
4/UUJU5DDQvdq5T9FRF0I1mdtLToLSBnDCkTAAC6486UYV1j1Yzv1+DWJHSmiLna
LQIDAQAB
```

### `--local-repository`

- **Type:** String (Path to directory)
- **Availability:** `argv` and JSON
- **Default:** `/tmp/fort/repository`

Path to the directory where Fort will store a local cache of the repository.

Right now, Fort accesses RPKI repositories by way of [rsync](https://en.wikipedia.org/wiki/Rsync). (The alternate protocol [RRDP](https://tools.ietf.org/html/rfc8182) is in the road map.) During each validation cycle, Fort will literally invoke an `rsync` command (see [`rsync.program`](#rsyncprogram) and [`rsync.arguments-recursive`](#rsyncarguments-recursive)), which will download the files into `--local-repository`. Fort's entire validation process operates on the resulting copy.

Because rsync uses delta encoding, you're advised to keep this cache around. It significantly speeds up subsequent validation cycles.

### `--sync-strategy`

- **Type:** Enumeration (`off`, `strict`, `root`, `root-except-ta`)
- **Availability:** `argv` and JSON
- **Default:** `root`

rsync synchronization strategy. Commands the way rsync URLs are approached during downloads.

#### `off`

Skips all rsyncs. (Validate the existing cache repository pointed by `--local-repository`.)

#### `strict`

> In order to enable this strategy, recompile using the flag: **_ENABLE\_STRICT\_STRATEGY_**.
>
> e.g. `$ make FORT_FLAGS='-DENABLE_STRICT_STRATEGY'`

rsyncs every repository publication point separately. Only skips publication points that have already been downloaded during the current validation cycle. (Assuming each synchronization is recursive.)

For example, suppose the validator gets certificates whose caRepository access methods (in their Subject Information Access extensions) point to the following publication points:

1. `rsync://rpki.example.com/foo/bar/`
2. `rsync://rpki.example.com/foo/qux/`
3. `rsync://rpki.example.com/foo/bar/`
4. `rsync://rpki.example.com/foo/corge/grault/`
5. `rsync://rpki.example.com/foo/corge/`
6. `rsync://rpki.example.com/foo/corge/waldo/`

A  validator following the `strict` strategy would download `bar`, download `qux`, skip `bar`, download `corge/grault`, download `corge` and skip `corge/waldo`.

Though this strategy is the only "strictly" correct one, it is also extremely slow. Its usage is _not_ recommended, unless your repository contains lots of spam files, awkward permissions or can't be found in a repository rooted in a URL that follows the regular expression "`rsync://.+/.+/`".

#### `root`

For each publication point found, guess the root of its repository and rsync that instead. Then skip
any subsequent children of said root.

(To guess the root of a repository, the validator counts four slashes, and prunes the rest of the URL.)

Reusing the caRepository URLs from the `strict` strategy (above) as example, a  validator following the `root` strategy would download `rsync://rpki.example.com/foo`, and then skip everything else.

Assuming that the repository is specifically structured to be found within as few roots as possible, and they contain minimal RPKI-unrelated noise files, this is the fastest synchronization strategy. At time of writing, this is true for all the current official repositories.

#### `root-except-ta`

Synchronizes the root certificate (the one pointed by the TAL) in `strict` mode, and once it's validated, synchronizes the rest of the repository in `root` mode.

Useful if you want `root`, but the root certificate is separated from the rest of the repository. Also useful if you don't want the validator to download the entire repository without first confirming the integrity and legitimacy of the root certificate.

### `--shuffle-uris`

- **Type:** None
- **Availability:** `argv` and JSON

If enabled, Fort will access TAL URLs in random order. This is meant for load balancing. If disabled, Fort will access TAL URLs in sequential order.

(Regardless of this flag, Fort will stop iterating through the URLs as soon as it finds one that yields a successful traversal.)

Of course, this is only relevant if the TAL lists more than one URL.

### `--maximum-certificate-depth`

- **Type:** Integer
- **Availability:** `argv` and JSON
- **Default:** 32
- **Range:** 5--([`UINT_MAX`](http://pubs.opengroup.org/onlinepubs/9699919799/basedefs/limits.h.html)--1)

Maximum allowable RPKI tree height. Meant to protect Fort from iterating infinitely due to certificate chain loops.

Fort's tree traversal is actually iterative (not recursive), so there should be no risk of stack overflow, regardless of this value.

### `--mode`

- **Type:** Enumeration (`server`, `standalone`)
- **Availability:** `argv` and JSON
- **Default:** `server`

Run mode, commands the way Fort executes the validation. The two possible values and its behavior are:
- `server`: Enables the RTR server using the `server.*` arguments ([`server.address`](#--serveraddress), [`server.port`](#--serverport), [`server.backlog`](#--serverbacklog), [`server.validation-interval`](#--servervalidation-interval)).
- `standalone`:  Disables the RTR server, the `server.*` arguments are ignored, and Fort performs an in-place standalone RPKI validation.

### `--server.address`

- **Type:** String
- **Availability:** `argv` and JSON
- **Default:** `NULL`

Hostname or numeric host address the RTR server will be bound to. Must resolve to (or be) a bindable IP address. IPv4 and IPv6 are supported.

If this field is omitted, Fort will attempt to bind the server using the IP address `INADDR_ANY` (for an IPv4 address) or `IN6ADDR_ANY_INIT` (for an IPv6 address); see '`$ man getaddrinfo`'.

### `--server.port`

- **Type:** String
- **Availability:** `argv` and JSON
- **Default:** `"323"`

TCP port or service the server will be bound to.

This is a string because a service alias can be used as a valid value. The available aliases are commonly located at `/etc/services`. (See '`$ man services`'.)

> ![../img/warn.svg](../img/warn.svg) The default port is privileged. To improve security, either change or jail it.

### `--server.backlog`

- **Type:** Integer
- **Availability:** `argv` and JSON
- **Default:** [`SOMAXCONN`](http://pubs.opengroup.org/onlinepubs/9699919799.2008edition/basedefs/sys_socket.h.html)
- **Range:** 1--`SOMAXCONN`

RTR server's listen queue length. It is the second argument of [`listen()`](http://pubs.opengroup.org/onlinepubs/9699919799.2008edition/functions/listen.html):

> The backlog argument provides a hint to the implementation which the implementation shall use to limit the number of outstanding connections in the socket's listen queue. Implementations may impose a limit on backlog and silently reduce the specified value. Normally, a larger backlog argument value shall result in a larger or equal length of the listen queue. Implementations shall support values of backlog up to SOMAXCONN, defined in <sys/socket.h>.

See the corresponding manual page from your operating system (likely `man 2 listen`) for specific implementation details.

### `--server.validation-interval`

- **Type:** Integer
- **Availability:** `argv` and JSON
- **Default:** 3600
- **Range:** 60--[`UINT_MAX`](http://pubs.opengroup.org/onlinepubs/9699919799/basedefs/limits.h.html)

Number of seconds the server will sleep between validation cycles.

The timer starts counting every time a validation is finished, not every time it begins. The actual validation loop is, therefore, longer than this number.

"Validation cycle" includes the rsync update along with the validation operation. Because you are taxing the global repositories every time the validator performs an rsync, it is recommended not to reduce the validation interval to the point you might be contributing to DoS'ing the global repository. The minimum value (60) was taken from the [RRDP RFC](https://tools.ietf.org/html/rfc8182#section-3.1), which means it's not necessarily a good value for heavy rsyncs.

### `--slurm`

- **Type:** String (path to file or directory)
- **Availability:** `argv` and JSON
- **Default:** `NULL`

SLURM file, or directory containing SLURM files. See [SLURM](slurm.html).

### `--log.color-output`

- **Type:** None
- **Availability:** `argv` and JSON

If enabled, the logging output will contain ANSI color codes. Meant for human consumption.

<pre><code class="terminal">$ {{ page.command }} --color-output (...)
<span style="color:cyan">DBG: Manifest '62gPOPXWxxu0sQa4vQZYUBLaMbY.mft' {</span>
<span style="color:lightgray">INF: rpkiManifest registered. Its nid is 1061.</span>
<span style="color:orange">WRN: H2jRmyC2M.mft: The signature algorithm has parameters.</span>
<span style="color:red">ERR: H2jRmyC2M.mft: Certificate validation failed: certificate has expired</span>
<span style="color:magenta">CRT: Programming error: Array size is 1 but array is NULL.</span>
</code></pre>

### `--log.file-name-format`

- **Type:** Enumeration (`global-url`, `local-path`, `file-name`)
- **Availability:** `argv` and JSON
- **Default:** `global-url`

Decides which version of file names should be printed during most debug/error messages.

- `global-url`: Prints the global name of the file; the URL that can be used to download it. (Always starts with `rsync://`.)
- `local-path`: Prints a path that points to the local cached version of the file. (Always starts with [`--local-repository`](#--local-repository)'s value.)
- `file-name`: Strips prefixes, leaving only the base name of the file (including extension).

Suppose a certificate was downloaded from `rsync://rpki.example.com/foo/bar/baz.cer` into the local cache `repository/`:

- `global-url`: Will print the certificate's name as `rsync://rpki.example.com/foo/bar/baz.cer`.
- `local-path`: Will print the certificate's name as `repository/rpki.example.com/foo/bar/baz.cer`.
- `file-name`: Will print the certificate's name as `baz.cer`.

{% highlight bash %}
$ {{ page.command }} --log.file-name-format global-url --local-repository repository/ (...)
ERR: rsync://rpki.example.com/foo/bar/baz.cer: Certificate validation failed: certificate has expired

$ {{ page.command }} --log.file-name-format local-path --local-repository repository/ (...)
ERR: repository/rpki.example.com/foo/bar/baz.cer: Certificate validation failed: certificate has expired

$ {{ page.command }} --log.file-name-format file-name  --local-repository repository/ (...)
ERR: baz.cer: Certificate validation failed: certificate has expired
{% endhighlight %}

### `--output.roa`

- **Type:** String (Path to file)
- **Availability:** `argv` and JSON

File where the ROAs will be stored in CSV format.

When the file is specified, its content will be removed to store the ROAs; if the file doesn't exists, it will be created. To print at console, use a hyphen `"-"`. If RTR server is enabled, then the ROAs will be printed every [`--server.validation-interval`](#--servervalidation-interval) secs.

If a value isn't specified, then the ROAs aren't printed.

### `--configuration-file`

- **Type:** String (Path to file)
- **Availability:** `argv` only

Path to a JSON file from which additional configuration will be read.

The configuration options are mostly the same as the ones from the `argv` interface. (See the "Availability" metadata of each field.) Here's a full configuration file example:

<pre><code>{
	"<a href="#--tal">tal</a>": "/tmp/fort/tal/test.tal",
	"<a href="#--local-repository">local-repository</a>": "/tmp/fort/repository",
	"<a href="#--sync-strategy">sync-strategy</a>": "root",
	"<a href="#--shuffle-uris">shuffle-uris</a>": true,
	"<a href="#--slurm">slurm</a>": "/tmp/fort/test.slurm",
	"<a href="#--mode">mode</a>": "server",

	"server": {
		"<a href="#--serveraddress">address</a>": "192.0.2.1",
		"<a href="#--serverport">port</a>": "8323",
		"<a href="#--serverbacklog">backlog</a>": 16,
		"<a href="#--servervalidation-interval">validation-interval</a>": 120
	},

	"log": {
		"<a href="#--logcolor-output">color-output</a>": true,
		"<a href="#--logfile-name-format">file-name-format</a>": "file-name"
	},

	"rsync": {
		"<a href="#rsyncprogram">program</a>": "rsync",
		"<a href="#rsyncarguments-recursive">arguments-recursive</a>": [
			"--recursive",
			"--times",
			"$REMOTE",
			"$LOCAL"
		],
		"<a href="#rsyncarguments-flat">arguments-flat</a>": [
			"--times",
			"--dirs",
			"$REMOTE",
			"$LOCAL"
		]
	},

	"<a href="#incidences">incidences</a>": [
		{
			"name": "Signed Object's hash algorithm has NULL object as parameters",
			"action": "ignore"
		}
	],

	"output": {
		"<a href="#--outputroa">roa</a>": "/tmp/fort/roas.csv"
	}
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
	"sync-strategy": "root",
	"maximum-certificate-depth": 5
}

$ cat b.json
{
	"sync-strategy": "strict"
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
$ # local-repository is "a", sync-strategy is "strict" and maximum-certificate-depth is 8
{% endhighlight %}

### rsync.program

- **Type:** String
- **Availability:** JSON only
- **Default:** `"rsync"`

Name of the program needed to invoke an rsync file transfer.

### rsync.arguments-recursive

- **Type:** String array
- **Availability:** JSON only
- **Default:** `[ "--recursive", "--delete", "--times", "--contimeout=20", "$REMOTE", "$LOCAL" ]`

Arguments needed by [`rsync.program`](#rsyncprogram) to perform a recursive rsync.

Fort will replace `"$REMOTE"` with the remote URL it needs to download, and `"$LOCAL"` with the target local directory where the file is supposed to be dropped.

### rsync.arguments-flat

- **Type:** String array
- **Availability:** JSON only
- **Default:** `[ "--times", "--contimeout=20", "--dirs", "$REMOTE", "$LOCAL" ]`

Arguments needed by [`rsync.program`](#rsyncprogram) to perform a single-file rsync.

Fort will replace `"$REMOTE"` with the remote URL it needs to download, and `"$LOCAL"` with the target local directory where the file is supposed to be dropped.

### `incidences`

- **Type:** JSON Object
- **Availability:** JSON only

A listing of actions to be performed by validation upon encountering certain error conditions. See [incidence](incidence.html).
