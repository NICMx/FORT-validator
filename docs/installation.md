---
title: Compilation and Installation
description: Guide to compile and install FORT Validator.
---

# {{ page.title }}

## Index

1. [Dependencies](#dependencies)
2. [Option 1: Installing the package](#option-1-installing-the-package)
	1. [Debian package](#debian-package)
	2. [Gentoo package](#gentoo-package)
	3. [RHEL/CentOS package](#rhelcentos-package)
3. [Option 2: Compiling and installing the release tarball](#option-2-compiling-and-installing-the-release-tarball)
	1. [Debian version](#debian-version)
	2. [OpenBSD version](#openbsd-version)
	3. [RHEL/CentOS version](#rhelcentos-version)
	4. [Fedora version](#fedora-version)
	5. [openSUSE Leap version](#opensuse-leap-version)
	6. [FreeBSD version](#freebsd-version)
	7. [Slackware version](#slackware-version)
	8. [Gentoo version](#gentoo-version)
	9. [Alpine version](#alpine-version)
4. [Option 3: Compiling and installing the git repository](#option-3-compiling-and-installing-the-git-repository)
5. [Option 4: Running from a Docker container](#option-4-running-from-a-docker-container)
6. [Fetching the TALs](#fetching-the-tals)
	1. [`--init-tals` argument](#--init-tals-argument)
	2. [Setup script](#setup-script)

## Dependencies

> Note: This section is included in case you intend to install Fort in an unlisted OS (and therefore need a little research). For Debians, OpenBSD, RHEL/CentOS, Fedora, openSUSE Leap, FreeBSD, and Slackware just follow the steps in the sections below.

The dependencies are

1. [jansson](http://www.digip.org/jansson/)
2. libcrypto (Either [LibreSSL](http://www.libressl.org/) or [OpenSSL](https://www.openssl.org/) >= 1.1)
3. [rsync](http://rsync.samba.org/)
4. [libcurl](https://curl.haxx.se/libcurl/)
5. [libxml2](http://www.xmlsoft.org/)

Fort currently supports *64-bit* Operating Systems. A 32-bit OS may face the [Year 2038 problem](https://en.wikipedia.org/wiki/Year_2038_problem) when handling certificate dates, and there's no workaround for this at the moment.

## Option 1: Installing the package

### Debian package

Currently, there are 2 alternatives to install a debian package:
- [Latest version](#latest-version): this package is created as part of the latest release (currently {{ site.fort-latest-version }}) and is manually installed.
- [Debian repository version](#debian-repository-version): this package is at Debian repositories, so it can be fetched from there.

#### Latest version

Just download the .deb package and install it. The fort service is automatically started once the installation is done.

{% highlight bash %}
wget https://github.com/NICMx/FORT-validator/releases/download/{{ site.fort-latest-version }}/fort_{{ site.fort-latest-version }}-1_amd64.deb
sudo apt install ./fort_{{ site.fort-latest-version }}-1_amd64.deb
{% endhighlight %}

> If a dependency can't be found at the repositories (i.e. libcurl4), try using a newer repository, such as Debian Buster.
> 
> Add the following line to `/etc/apt/sources.list`, replacing the mirror (_http://ftp.mx.debian.org/debian_) with your [preferred one](https://www.debian.org/mirror/list):
> 
> `deb http://ftp.mx.debian.org/debian buster main`

This version ships with 4 of the 5 TALs, so in order to get the missing one, the [`--init-tals` argument](#--init-tals-argument) can be utilized using also the argument `--tal=/etc/fort/tal`:

{% highlight bash %}
sudo fort --init-tals --tal=/etc/fort/tal
# Don't forget to restart fort service
sudo service fort restart
{% endhighlight %}

Aside from the `fort` binary documented elsewhere in this documentation, the Debian package also ships with a systemd service, which is just the binary ran as a daemon. You can [configure](usage.html#--configuration-file) it at `/etc/fort/config.json`.

{% highlight bash %}
sudo service fort start
service fort status
tail /var/log/syslog
sudo service fort stop
{% endhighlight %}

Or, using systemctl:

{% highlight bash %}
sudo systemctl start fort
systemctl status fort
sudo systemctl stop fort

# In case you don't need to run fort on start
sudo systemctl disable fort
sudo systemctl enable fort
{% endhighlight %}

#### Debian repository version

Special thanks to [Marco d'Itri](https://github.com/rfc1036) for this collaboration.

To know the current status of this package, visit [`fort-validator` debian package tracker](https://tracker.debian.org/pkg/fort-validator).

The main differences between this version (fort-validator package) and the [Latest version](#latest-version) package are:
- [`rpki-trust-anchors`](https://tracker.debian.org/pkg/rpki-trust-anchors) dependency: this package has such dependency, while [Latest version](#latest-version) doesn't.
- Since this package isn't maintained by FORT validator's team, it could be at least one version behind than [Latest version](#latest-version).
- This version reads the TALs from `/etc/tals`, while [Latest version](#latest-version) reads them from `/etc/fort/tal`.

Assuming that the package is still at the `testing` repository, such repository can be added to the APT sources list in order to do a simple `apt install`.

First, check if the file `/etc/apt/apt.conf` exists, otherwise create it. The file should have the following line to keep using the stable repository as the default:

{% highlight bash %}
APT::Default-Release "stable";
{% endhighlight %}

Now add the Debian `testing` repositories, add the following lines to `/etc/apt/sources.list`:

{% highlight bash %}
deb http://deb.debian.org/debian/ testing main
deb-src http://deb.debian.org/debian/ testing main
{% endhighlight %}

Finally, just run:

{% highlight bash %}
sudo apt update
sudo apt -t testing install fort-validator
{% endhighlight %}

FORT validator is now installed as a service, check the status with `sudo service fort start`.

### Gentoo package

Thanks to [@alarig](https://github.com/alarig) for [his collaboration](https://github.com/NICMx/FORT-validator/issues/23) creating this package.

> ![img/warn.svg](img/warn.svg) The package is currently at the [GURU repository](https://wiki.gentoo.org/wiki/Project:GURU), it could be at least one version behind the latest version, so please check first which version is the latest at the repository '[net-misc/FORT-validator](https://gitweb.gentoo.org/repo/proj/guru.git/tree/net-misc/FORT-validator)'.

Layman will be utilized, so it must be installed in order to add the GURU repository:

{% highlight bash %}
root# emerge --ask app-portage/layman
root# layman -a guru
{% endhighlight %}

Now, allow to install the unstable FORT validator package (use according to your architecture). The following lines can be used for **amd64** arch:

{% highlight bash %}
root# nano /etc/portage/package.accept_keywords
## Add the following line and save
net-misc/FORT-validator ~amd64
{% endhighlight %}

FORT validator can now be installed. Don't forget to add ARIN's TAL and restart the validator:

{% highlight bash %}
root# emerge --ask net-misc/FORT-validator
root# su -s /bin/sh -c '/usr/libexec/fort/fort_setup.sh /usr/share/fort/tal/' fort
root# rc-service fort restart
{% endhighlight %}

The configuration file utilized by the service can be found at `/etc/fort/config.json` (see more about [configuration file](usage.html#--configuration-file)).

### RHEL/CentOS package

> **RHEL/CentOS 7** users: the EPEL repository must be enabled to successfully install FORT validator.
>
> The following command will do: `sudo yum install epel-release`

Download the .rpm and install it (currently tested at CentOS 7 and 8):

{% highlight bash %}
wget https://github.com/NICMx/FORT-validator/releases/download/{{ site.fort-latest-version }}/fort-{{ site.fort-latest-version }}-1.el8.x86_64.rpm
sudo yum install fort-{{ site.fort-latest-version }}-1.el8.x86_64.rpm
{% endhighlight %}

This version ships with 4 of the 5 TALs, so in order to get the missing one, the [`--init-tals` argument](#--init-tals-argument) can be utilized using also the argument `--tal=/etc/fort/tal`:

{% highlight bash %}
sudo fort --init-tals --tal=/etc/fort/tal
{% endhighlight %}

By default, FORT validator service isn't initialized once it's installed; so, initialize the service:

{% highlight bash %}
sudo systemctl start fort
systemctl status fort

# In case you want to stop it
sudo systemctl stop fort
{% endhighlight %}

The configuration file utilized by the service can be found at `/etc/fort/config.json` (see more about [configuration file](usage.html#--configuration-file)).

## Option 2: Compiling and installing the release tarball

### Debian version

{% highlight bash %}
sudo apt install autoconf automake build-essential libjansson-dev libssl-dev pkg-config rsync libcurl4-openssl-dev libxml2-dev

wget https://github.com/NICMx/FORT-validator/releases/download/{{ site.fort-latest-version }}/fort-{{ site.fort-latest-version }}.tar.gz
tar xvzf fort-{{ site.fort-latest-version }}.tar.gz
cd fort-{{ site.fort-latest-version }}/
./configure
make
sudo make install
{% endhighlight %}

### OpenBSD version

{% highlight bash %}
su
pkg_add jansson libexecinfo rsync libxml # OpenBSD already ships with LibreSSL
exit

ftp https://github.com/NICMx/FORT-validator/releases/download/{{ site.fort-latest-version }}/fort-{{ site.fort-latest-version }}.tar.gz
tar xvzf fort-{{ site.fort-latest-version }}.tar.gz
cd fort-{{ site.fort-latest-version }}/
# clang is needed because of gnu11.
env CC=clang CFLAGS=-I/usr/local/include LDFLAGS=-L/usr/local/lib ./configure
make
su
make install
exit
{% endhighlight %}

### RHEL/CentOS version

#### RHEL/CentOS 8

The following steps are for RHEL/CentOS 8.

{% highlight bash %}
sudo dnf install autoconf automake gcc jansson-devel libcurl-devel libxml2-devel make openssl-devel pkgconfig rsync tar wget

wget https://github.com/NICMx/FORT-validator/releases/download/{{ site.fort-latest-version }}/fort-{{ site.fort-latest-version }}.tar.gz
tar xvzf fort-{{ site.fort-latest-version }}.tar.gz
cd fort-{{ site.fort-latest-version }}/
./configure
make
sudo make install
{% endhighlight %}

#### RHEL/CentOS 7

The following steps are for RHEL/CentOS 7.

This OS requires additional steps due to its default GCC version (currently 4.8.5, fort needs >= 4.9) and its default OpenSSL version (currently 1.0.2k, fort needs >= 1.1.0).

**Upgrade OpenSSL from 1.0.2k to 1.1.1c**

There are two options to upgrade OpenSSL:
1. Compile and install a newer version >= 1.1.0 (manual process).
2. Use the [EPEL](https://fedoraproject.org/wiki/EPEL) repository (indicated at the following steps).

**Upgrade GCC**

There are two options to upgrade GCC:
1. Compile and install a newer version >= 4.9 (slow process).
2. Use [Software Collections](https://www.softwarecollections.org) (indicated at the following steps).

{% highlight bash %}
sudo yum install centos-release-scl epel-release
sudo yum install autoconf automake devtoolset-8-gcc jansson-devel libcurl-devel libxml2-devel make openssl11-devel pkgconfig rsync tar wget
# Start a session using the upgraded GCC
scl enable devtoolset-8 bash
cd ~
wget https://github.com/NICMx/FORT-validator/releases/download/{{ site.fort-latest-version }}/fort-{{ site.fort-latest-version }}.tar.gz
tar xvzf fort-{{ site.fort-latest-version }}.tar.gz
cd fort-{{ site.fort-latest-version }}/
# Insert paths from newer OpenSSL version
export CFLAGS+=" $(pkg-config --cflags openssl11)" LDFLAGS+=" $(pkg-config --libs openssl11)"
./configure
make
sudo make install
# Close the 'devtoolset' session
exit
{% endhighlight %}

### Fedora version

The following steps are for Fedora 30 (and later).

{% highlight bash %}
sudo dnf install autoconf automake gcc jansson-devel libcurl-devel libxml2-devel make openssl-devel pkgconfig rsync tar wget
wget https://github.com/NICMx/FORT-validator/releases/download/{{ site.fort-latest-version }}/fort-{{ site.fort-latest-version }}.tar.gz
tar xvzf fort-{{ site.fort-latest-version }}.tar.gz
cd fort-{{ site.fort-latest-version }}/
./configure
make
sudo make install
{% endhighlight %}

### openSUSE Leap version

The following steps are for openSUSE Leap 15.1.

{% highlight bash %}
sudo zypper install autoconf automake gcc libopenssl-devel libjansson-devel libcurl-devel libxml2-devel

wget https://github.com/NICMx/FORT-validator/releases/download/{{ site.fort-latest-version }}/fort-{{ site.fort-latest-version }}.tar.gz
tar xvzf fort-{{ site.fort-latest-version }}.tar.gz
cd fort-{{ site.fort-latest-version }}/
./configure
make
sudo make install
{% endhighlight %}

### FreeBSD version

The following steps are for FreeBSD 12.0.

`curl` library is needed, so in case it isn't already installed there's a port to install it:

{% highlight bash %}
cd /usr/ports/ftp/curl
make config
su
make install clean
exit
{% endhighlight %}

From there on, the installation steps are:

{% highlight bash %}
su
pkg install autoconf automake gcc jansson pkgconf rsync libxml2
exit

curl -L https://github.com/NICMx/FORT-validator/releases/download/{{ site.fort-latest-version }}/fort-{{ site.fort-latest-version }}.tar.gz --output fort-{{ site.fort-latest-version }}.tar.gz
tar xvzf fort-{{ site.fort-latest-version }}.tar.gz
cd fort-{{ site.fort-latest-version }}/
./configure
make
su
make install
exit
{% endhighlight %}

### Slackware version

The following steps are for Slackware "current" release (as of 2020-07-13).

All dependencies are included in the current release, so there's no need to install any dependency.

{% highlight bash %}
wget https://github.com/NICMx/FORT-validator/releases/download/{{ site.fort-latest-version }}/fort-{{ site.fort-latest-version }}.tar.gz
tar xvzf fort-{{ site.fort-latest-version }}.tar.gz
cd fort-{{ site.fort-latest-version }}/
./configure
make
sudo make install
{% endhighlight %}

### Gentoo version

The following steps are for Gentoo "current" release (as of 2020-07-13).

It's very likely that most of the dependencies are already installed (except `dev-libs/jansson`), still you can execute the following commands.

{% highlight bash %}
su
emerge sys-devel/autoconf sys-devel/automake net-misc/rsync net-misc/curl dev-libs/jansson 
exit

wget https://github.com/NICMx/FORT-validator/releases/download/{{ site.fort-latest-version }}/fort-{{ site.fort-latest-version }}.tar.gz
tar xvzf fort-{{ site.fort-latest-version }}.tar.gz
cd fort-{{ site.fort-latest-version }}/
./configure
make
su
make install
exit
{% endhighlight %}

### Alpine version

The following steps are for Alpine Linux 3.12.0

{% highlight bash %}
su
apk add build-base autoconf automake pkgconfig openssl openssl-dev jansson jansson-dev bsd-compat-headers rsync libexecinfo libexecinfo-dev libxml2 libxml2-dev libcurl curl-dev
exit

wget https://github.com/NICMx/FORT-validator/releases/download/{{ site.fort-latest-version }}/fort-{{ site.fort-latest-version }}.tar.gz
tar xvzf fort-{{ site.fort-latest-version }}.tar.gz
cd fort-{{ site.fort-latest-version }}/
./configure
make
su
make install
exit
{% endhighlight %}

## Option 3: Compiling and installing the git repository

In case you wan't a fresh version of Fort validator, there's this third option. The steps are mostly the same as in [Option 2](#option-2-compiling-and-installing-the-release-tarball), just another dependency (as minimum) must be installed: "git"; and a few steps are included in order to get the source code and generate configuration scripts.

The following example is the process to clone, compile and install in Debian OS.

{% highlight bash %}
sudo apt install autoconf automake build-essential git libjansson-dev libssl-dev pkg-config rsync libcurl4-openssl-dev libxml2-dev

git clone https://github.com/NICMx/FORT-validator.git
cd FORT-validator/
./autogen.sh
./configure
make
sudo make install
{% endhighlight %}

## Option 4: Running from a Docker container

There's also the option to run FORT validator from a Docker container. The image can be pulled from [Docker Hub](https://hub.docker.com/r/nicmx/fort-validator) or built from the official Github repository: [FORT-validator/docker](https://github.com/NICMx/FORT-validator/tree/master/docker).

To pull the image from the official repository, run:

{% highlight bash %}
docker pull nicmx/fort-validator:latest
{% endhighlight %}

Or to build from the source Dockerfile, just run (from the same directory where the Dockerfile is):

{% highlight bash %}
docker build -t fort-validator:latest .
{% endhighlight %}

A basic example to run the container using the default values, reading from a local TAL directory (i.e. `host/path/to/tals`), and binding to the local port `8323`:

{% highlight bash %}
docker run --name fort-validator -v host/path/to/tals:/etc/fort/tal:ro -p 8323:323 -d fort-validator
{% endhighlight %}

Read more about the Docker container at the Github repository [FORT-validator/docker](https://github.com/NICMx/FORT-validator/tree/master/docker).

## Fetching the TALs

Once FORT validator is installed and ready to run, you should have the TAL files from the 5 RIRs. You can obtain them one by one from each RIR, or also you can use the following options.

### `--init-tals` argument

Probably this is a more straight forward approach, since you only need to run Fort binary using the [`--init-tals`](usage.html#--init-tals) argument:

{% highlight bash %}
fort --init-tals --tal /etc/fort/tal
{% endhighlight %}

See more about this argument at [Program Arguments - `--init-tals`](usage.html#--init-tals).

### Setup script

> ![img/warn.svg](img/warn.svg) This script exists merely to ease the ARIN TAL download (and some other additional stuff), it isn't a prerequisite to compile or run FORT validator, although we strongly advise to fetch ARIN TAL (using this script or by other means) in order to get the whole RPKI validated by FORT validator.

The script can be found [here](https://github.com/NICMx/FORT-validator/blob/{{ site.fort-latest-version }}/fort_setup.sh). It only expects one argument: an _existent directory path_ where the 5 RIRs TALS will be downloaded.

Basically, it does the following:
1. Display message to agree ARIN RPA.
2. If agreed, download ARIN TAL to the received arg (named `TALS_PATH` from now on).
3. Download the rest of the TALs to `TALS_PATH`.
4. Try to create directory `/var/cache/fort/repository`, on error create `/tmp/fort/repository`.
5. Create configuration file with [`tal`](https://nicmx.github.io/FORT-validator/usage.html#--tal) and [`local-repository`](https://nicmx.github.io/FORT-validator/usage.html#--local-repository) members, with a value of `TALS_PATH` (absolute path) and the directory path created at the previous step.
6. Display FORT validator execution examples:
  - Using the created configuration file (uses the arg [`-f`](https://nicmx.github.io/FORT-validator/usage.html#--configuration-file)).
  - Using the values of the configuration file (uses the args [`--tal`](https://nicmx.github.io/FORT-validator/usage.html#--tal) and [`--local-repository`](https://nicmx.github.io/FORT-validator/usage.html#--local-repository)).

Preferably, run this script with the same user what will run FORT validator. It's recommended that the user has write permission in `/var/cache`, since the script will try to create a directory there ([see more](https://refspecs.linuxfoundation.org/FHS_3.0/fhs/ch05s05.html)). Here's an execution example:

{% highlight bash %}
# Get the script
wget https://raw.githubusercontent.com/NICMx/FORT-validator/{{ site.fort-latest-version }}/fort_setup.sh
mkdir ~/tal
./fort_setup.sh ~/tal
{% endhighlight %}
