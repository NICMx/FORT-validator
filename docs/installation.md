---
title: Compilation and Installation
---

# {{ page.title }}

## Index

1. [Dependencies](#dependencies)
2. [Setup script](#setup-script)
3. [Option 1: Installing the Debian package](#option-1-installing-the-debian-package)
4. [Option 2: Compiling and installing the release tarball](#option-2-compiling-and-installing-the-release-tarball)
	1. [Debian version](#debian-version)
	2. [OpenBSD version](#openbsd-version)
	3. [RHEL/CentOS version](#rhelcentos-version)
	4. [Fedora version](#fedora-version)
	5. [openSUSE Leap version](#opensuse-leap-version)
	6. [FreeBSD version](#freebsd-version)
	7. [Slackware version](#slackware-version)
5. [Option 3: Compiling and installing the git repository](#option-3-compiling-and-installing-the-git-repository)

## Dependencies

> Note: I'm only including this section in case you intend to install Fort in an unlisted OS (and therefore need a little research). For: Debians, OpenBSD, RHEL/CentOS, Fedora, openSUSE Leap, FreeBSD, and Slackware just follow the steps in the sections below.

The dependencies are

1. [jansson](http://www.digip.org/jansson/)
2. libcrypto (Either [LibreSSL](http://www.libressl.org/) or [OpenSSL](https://www.openssl.org/) >= 1.1)
3. [rsync](http://rsync.samba.org/)
4. [libcurl](https://curl.haxx.se/libcurl/)
5. [libxml2](http://www.xmlsoft.org/)

Fort is currently supported in *64-bit* OS. A 32-bit OS may face the [Year 2038 problem](https://en.wikipedia.org/wiki/Year_2038_problem) when handling dates at certificates, and currently there's no work around for this.

## Setup script

> ![img/warn.svg](img/warn.svg) This script exists merely to ease the ARIN TAL download (and some other additional stuff), it isn't a prerequisite to compile or run FORT validator, although we strongly advise to fetch ARIN TAL (using this script or by other means) in order to get the whole RPKI validated by FORT validator.

The script can be found [here](https://github.com/NICMx/FORT-validator/blob/v{{ site.fort-latest-version }}/fort_setup.sh). It only expects one argument: an _existent directory path_ where the 5 RIRs TALS will be downloaded.

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
wget https://raw.githubusercontent.com/NICMx/FORT-validator/v{{ site.fort-latest-version }}/fort_setup.sh
mkdir ~/tal
./fort_setup.sh ~/tal
{% endhighlight %}

## Option 1: Installing the Debian package

{% highlight bash %}
wget https://github.com/NICMx/FORT-validator/releases/download/v{{ site.fort-latest-version }}/fort_{{ site.fort-latest-version }}-1_amd64.deb
sudo apt install ./fort_{{ site.fort-latest-version }}-1_amd64.deb
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

## Option 2: Compiling and installing the release tarball

### Debian version

{% highlight bash %}
sudo apt install autoconf automake build-essential libjansson-dev libssl-dev pkg-config rsync libcurl4-openssl-dev libxml2-dev

wget https://github.com/NICMx/FORT-validator/releases/download/v{{ site.fort-latest-version }}/fort-{{ site.fort-latest-version }}.tar.gz
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

ftp https://github.com/NICMx/FORT-validator/releases/download/v{{ site.fort-latest-version }}/fort-{{ site.fort-latest-version }}.tar.gz
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

wget https://github.com/NICMx/FORT-validator/releases/download/v{{ site.fort-latest-version }}/fort-{{ site.fort-latest-version }}.tar.gz
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
wget https://github.com/NICMx/FORT-validator/releases/download/v{{ site.fort-latest-version }}/fort-{{ site.fort-latest-version }}.tar.gz
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
wget https://github.com/NICMx/FORT-validator/releases/download/v{{ site.fort-latest-version }}/fort-{{ site.fort-latest-version }}.tar.gz
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

wget https://github.com/NICMx/FORT-validator/releases/download/v{{ site.fort-latest-version }}/fort-{{ site.fort-latest-version }}.tar.gz
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

curl -L https://github.com/NICMx/FORT-validator/releases/download/v{{ site.fort-latest-version }}/fort-{{ site.fort-latest-version }}.tar.gz --output fort-{{ site.fort-latest-version }}.tar.gz
tar xvzf fort-{{ site.fort-latest-version }}.tar.gz
cd fort-{{ site.fort-latest-version }}/
./configure
make
su
make install
exit
{% endhighlight %}

### Slackware version

The following steps are for Slackware "current" release (as of 2020-01-31).

All dependencies are included in the current release, so there's no need to install any dependency.

{% highlight bash %}
wget https://github.com/NICMx/FORT-validator/releases/download/v{{ site.fort-latest-version }}/fort-{{ site.fort-latest-version }}.tar.gz
tar xvzf fort-{{ site.fort-latest-version }}.tar.gz
cd fort-{{ site.fort-latest-version }}/
./configure
make
sudo make install
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
