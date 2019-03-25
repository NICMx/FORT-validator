---
title: Validator Usage
command: rpki_validator
---

# {{ page.title }}

## Index

1. [Syntax](#syntax)
2. [Arguments](#arguments)
	1. [`--help`](#--help)
	2. [`--usage`](#--usage)
	3. [`--version`](#--version)
	4. [`--tal`](#--tal)
	5. [`--local-repository`](#--local-repository)
	6. [`--roa-output-file`](#--roa-output-file)
	7. [`--sync-strategy`](#--sync-strategy)
		1. [`off`](#off)
		2. [`strict`](#strict)
		3. [`root`](#root)
		4. [`root-except-ta`](#root-except-ta)
	8. [`--maximum-certificate-depth`](#--maximum-certificate-depth)
	9. [`--shuffle-uris`](#--shuffle-uris)
	10. [`--color-output`](#--color-output)
	11. [`--output-file-name-format`](#--output-file-name-format)
	12. [`--configuration-file`](#--configuration-file)
	13. [`rsync.program`](#rsyncprogram)
	14. [`rsync.arguments-recursive`](#rsyncarguments-recursive)
	15. [`rsync.arguments-flat`](#rsyncarguments-flat)

## Syntax

```
{{ page.command }}
	[--help]
        [--usage]
        [--version]
        [--configuration-file=<file>]
        [--local-repository=<directory>]
        [--sync-strategy=off|strict|root|root-except-ta]
        [--maximum-certificate-depth=<unsigned integer>]
        [--tal=<file>]
        [--shuffle-uris]
        [--color-output]
        [--output-file-name-format=global-url|local-path|file-name]
        [--roa-output-file=<file>]
```

If an argument is declared more than once, the last one takes precedence:

{% highlight bash %}
$ {{ page.command }} --tal="foo"                          # tal is "foo"
$ {{ page.command }} --tal="foo" --tal="bar"              # tal is "bar"
$ {{ page.command }} --tal="foo" --tal="bar" --tal="qux"  # tal is "qux"
{% endhighlight %}


## Arguments

### `--help`

- Type: None
- Availability: `argv` only.

Prints medium-sized usage message.

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
        [--output-file-name-format=global-url|local-path|file-name]
            (File name variant to print during debug/error messages)
        [--roa-output-file=<file>]
            (File where the valid ROAs will be dumped.)
{% endhighlight %}

The slightly larger usage message is `man {{ page.command }}` and the large usage message is this documentation.

### `--usage`

- Type: None
- Availability: `argv` only.

Prints small-sized help message.

{% highlight bash %}
$ {{ page.command }} --usage
Usage: {{ page.command }}
        [--help]
        [--usage]
        [--version]
	...
        [--output-file-name-format=global-url|local-path|file-name]
        [--roa-output-file=<file>]
{% endhighlight %}

### `--version`

- Type: None
- Availability: `argv` only.

Prints small-sized usage message.

{% highlight bash %}
$ {{ page.command }} --version
0.0.1
{% endhighlight %}

### `--tal`

- Type: String (Path to file)
- Availability: `argv` and TOML

Path to the _Trust Anchor Locator_ (TAL).

The TAL is a file that points to the _Trust Anchor_ (TA). (The TA is the self-signed certificate that serves as the root of the tree you want validated.)

The reason why you provide a TAL instead of a TA is to allow the TA to be updated without needing to redistribute it.

Whichever registry serves as root of the tree you want to validate is responsible for providing you with its TAL. FORT currently ships with the TALs of most of the five RIRs.

> TODO state where they are and which is the missing one.

the TAL file format has been standardized in [RFC 7730](https://tools.ietf.org/html/rfc7730). It is a text file that contains a list of URLs (which serve as alternate access methods for the TA), followed by a blank line, followed by the Base64-encoded public key of the TA.

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

- Type: String (Path to directory)
- Availability: `argv` and TOML
- Default: `/tmp/fort/repository`

> TODO I just came up with the default value. Commit it.

Path to the directory where FORT will store a local cache of the repository.

RPKI repositories are typically accessed by way of [rsync](https://en.wikipedia.org/wiki/Rsync). During the validation cycle, FORT will literally invoke an `rsync` command (see `rsync.program` and `rsync.arguments`), which will download the files into `--local-repository`, and validate the result.

Because rsync uses delta encoding, keeping this cache around significantly speeds up subsequent validation cycles.

### `--roa-output-file`

- Type: String (Path to file)
- Availability: `argv` and TOML
- Default: `NULL`

Path to a file where FORT will dump successfully validated ROAs (in CSV format). If `NULL`, the ROAs will be printed in standard error.

This file is meant to be consumed by the beta version of the RTR Server. (In subsequent releases, this will no longer be required.)

### `--sync-strategy`

- Type: Enumeration (`off`, `strict`, `root`, `root-except-ta`)
- Availability: `argv` and TOML
- Default: `root`

rsync synchronization strategy. Commands the way rsync URLs are approached during downloads.

#### `off`

Skips all rsyncs. (Validate the existing cache repository pointed by `--local-repository`.)

#### `strict`

rsyncs every repository publication point separately. Only skips publication points that have already been downloaded during the current validation cycle. (Assuming each synchronization is recursive.)

For example, suppose the validator gets certificates whose caRepository access methods (in their Subject Information Access extensions) point to the following publication points:

1. `rsync://rpki.example.com/foo/bar/`
2. `rsync://rpki.example.com/foo/qux/`
3. `rsync://rpki.example.com/foo/bar/`
4. `rsync://rpki.example.com/foo/corge/grault/`
5. `rsync://rpki.example.com/foo/corge/`
6. `rsync://rpki.example.com/foo/corge/waldo/`

A  validator following the `strict` strategy would download `bar`, download `qux`, skip `bar`, download `corge/grault`, download `corge` and skip `corge/waldo`.

Though this strategy is the only "strictly" correct one, it is also extremely slow. Its usage is _not_ recommended, unless your repository contains lots of spam files, awkward permissions or can't be found in a repository rooted in a URL that follows the pattern `rsync://.+/.+/`.

#### `root`

For each publication point found, guess the root of its repository and rsync that instead. Then skip
any subsequent children of said root.

(To guess the root of a repository, the validator counts four slashes, and prunes the rest of the URL.)

Reusing the caRepository URLs from the `strict` strategy (above) as example, a  validator following the `root` strategy would download `rsync://rpki.example.com/foo`, and then skip everything else.

Assuming that the repository is specifically structured to be found within as few roots as possible, and they contain minimal RPKI-unrelated noise files, this is the fastest synchronization strategy. At time of writing, this is true for all the current official repositories.

#### `root-except-ta`

Synchronizes the root certificate (the one pointed by the TAL) in `strict` mode, and once it's validated, synchronizes the rest of the repository in `root` mode.

Useful if you want `root`, but the root certificate is separated from the rest of the repository. Also useful if you don't want the validator to download the entire repository without first confirming the integrity and legitimacy of the root certificate.

### `--maximum-certificate-depth`

### `--shuffle-uris`

- Availability: `argv` and TOML

If enabled, FORT will access TAL URLs in random order. This is meant for load balancing. If disabled, FORT will access TAL URLs in sequential order.

(Regardless of this flag, FORT will stop iterating through the URLs as soon as it finds one that yields a successful traversal.)

Of course, this is only relevant if the TAL lists more than one URL.

### `--color-output`

- Availability: `argv` and TOML

If enabled, the logging output will contain ANSI color codes. Meant for human consumption.

<pre><code class="terminal">$ {{ page.command }} --color-output (...)
<span style="color:cyan">DBG: Manifest '62gPOPXWxxu0sQa4vQZYUBLaMbY.mft' {</span>
<span style="color:lightgray">INF: rpkiManifest registered. Its nid is 1061.</span>
<span style="color:orange">WRN: H2jRmyC2M.mft: The signature algorithm has parameters.</span>
<span style="color:red">ERR: H2jRmyC2M.mft: Certificate validation failed: certificate has expired</span>
<span style="color:magenta">CRT: Programming error: Array size is 1 but array is NULL.</span>
</code></pre>

### `--output-file-name-format`

- Type: Enumeration (`global-url`, `local-path`, `file-name`)
- Availability: `argv` and TOML
- Default: `global-url`

Decides which version of file names should be printed during most debug/error messages.

Suppose a certificate was downloaded from `rsync://rpki.example.com/foo/bar/baz.cer` into the local cache `repository/`:

- `global-url`: Will print the certificate's name as `rsync://rpki.example.com/foo/bar/baz.cer`.
- `local-path`: Will print the certificate's name as `repository/rpki.example.com/foo/bar/baz.cer`.
- `file-name`: Will print the certificate's name as `baz.cer`.

{% highlight bash %}
$ {{ page.command }} --output-file-name-format global-url --local-repository tmp/repository/ (...)
ERR: rsync://rpki.afrinic.net/repository/arin/uHxadfPZV0E6uZhkaUbUVB1RFFU.mft: Certificate validation failed: certificate has expired
$ {{ page.command }} --output-file-name-format local-path --local-repository tmp/repository/ (...)
ERR: tmp/repository/rpki.afrinic.net/repository/arin/uHxadfPZV0E6uZhkaUbUVB1RFFU.mft: Certificate validation failed: certificate has expired
$ {{ page.command }} --output-file-name-format file-name --local-repository tmp/repository/ (...)
ERR: uHxadfPZV0E6uZhkaUbUVB1RFFU.mft: Certificate validation failed: certificate has expired
{% endhighlight %}

### `--configuration-file`

- Type: String (Path to file)
- Availability: `argv`

Path to a TOML file from which additional configuration will be read.

The configuration options are mostly the same as the ones from the `argv` interface. Here's a full configuration file example:

<pre><code>[root]
<a href="#--local-repository">local-repository</a> = "/tmp/fort/repository"
<a href="#--sync-strategy">sync-strategy</a> = "root"
<a href="#--maximum-certificate-depth">maximum-certificate-depth</a> = 32

[tal]
<a href="#--tal">tal</a> = "/tmp/fort/example.tal"
<a href="#--shuffle-uris">shuffle-uris</a> = true

[rsync]
<a href="#rsyncprogram">program</a> = "rsync"
<a href="#rsyncarguments-recursive">arguments-recursive</a> = [ "--recursive", "--times", "$REMOTE", "$LOCAL" ]
<a href="#rsyncarguments-flat">arguments-flat</a> = [ "--times", "$REMOTE", "$LOCAL" ]

[output]
<a href="#--color-output">color-output</a> = true
<a href="#--output-file-name-format">output-file-name-format</a> = "file-name"
<a href="#--roa-output-file">roa-output-file</a> = "/tmp/fort/roas.csv"
</code></pre>

The file acts as a collection of equivalent `argv` arguments; precedence is not modified:

{% highlight bash %}
$ cat cfg.toml
[tal]
tal = "bar"
$ {{ page.command }} --tal="foo"                                              # tal is "foo"
$ {{ page.command }} --tal="foo" --configuration-file="cfg.toml"              # tal is "bar"
$ {{ page.command }} --tal="foo" --configuration-file="cfg.toml" --tal="qux"  # tal is "qux"

$ cat a.toml
[root]
local-repository = "a"
sync-strategy = "root"
maximum-certificate-depth = 1

$ cat b.toml
[root]
sync-strategy = "strict"
maximum-certificate-depth = 2

$ cat c.toml
[root]
maximum-certificate-depth = 4

$ {{ page.command }} \
	--configuration-file="a.toml" \
	--configuration-file="b.toml" \
	--configuration-file="c.toml"
$ # local-repository is "a", sync-strategy is "strict" and maximum-certificate-depth is 4
{% endhighlight %}

### rsync.program

- Type: String
- Availability: TOML
- Default: `"rsync"`

Name of the program needed to invoke an rsync file transfer.

### rsync.arguments-recursive

- Type: String array
- Availability: TOML
- Default: `[ "--recursive", "--delete", "--times", "--contimeout=20", "$REMOTE", "$LOCAL" ]`

Arguments needed by [`rsync.program`](#rsyncprogram) to perform a recursive rsync.

FORT will replace `"$REMOTE"` with the remote URL it needs to download, and `"$LOCAL"` with the target local directory where the file is supposed to be dropped.

### rsync.arguments-flat

- Type: String array
- Availability: TOML
- Default: `[ "--times", "--contimeout=20", "$REMOTE", "$LOCAL" ]`

Arguments needed by [`rsync.program`](#rsyncprogram) to perform a single-file rsync.

FORT will replace `"$REMOTE"` with the remote URL it needs to download, and `"$LOCAL"` with the target local directory where the file is supposed to be dropped.
