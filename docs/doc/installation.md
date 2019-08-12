---
title: Compilation and Installation
---

[Documentation](index.html) > {{ page.title }}

# {{ page.title }}

## Index

1. [Dependencies](#dependencies)
2. [Option 1: Installing the Debian package](#option-1-installing-the-debian-package)
3. [Option 2: Compiling and installing the release tarball](#option-2-compiling-and-installing-the-release-tarball)
	1. [Debian version](#debian-version)
	2. [OpenBSD version](#openbsd-version)
	3. [CentOS version](#centos-version)
	4. [Fedora version](#fedora-version)
	5. [openSUSE Leap version](#opensuse-leap-version)
	6. [FreeBSD version](#freebsd-version)
	7. [Slackware version](#slackware-version)
4. [Option 3: Compiling and installing the git repository](#option-3-compiling-and-installing-the-git-repository)

## Dependencies

> Note: I'm only including this section in case you intend to install Fort in an unlisted OS (and therefore need a little research). For: Debians, OpenBSD, CentOS, Fedora, openSUSE Leap, FreeBSD, and Slackware just follow the steps in the sections below.

The dependencies are

1. [jansson](http://www.digip.org/jansson/)
2. libcrypto (Either [LibreSSL](http://www.libressl.org/) or [OpenSSL](https://www.openssl.org/) >= 1.1)
3. [rsync](http://rsync.samba.org/)

Fort is currently supported in *64-bit* OS. A 32-bit OS may face the [Year 2038 problem](https://en.wikipedia.org/wiki/Year_2038_problem) when handling dates at certificates, and currently there's no work around for this.

## Option 1: Installing the Debian package

> TODO Upload to Debian, add more archs

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

etc.

## Option 2: Compiling and installing the release tarball

### Debian version

{% highlight bash %}
sudo apt install autoconf automake build-essential libjansson-dev libssl-dev pkg-config rsync

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
pkg_add jansson libexecinfo rsync # OpenBSD already ships with LibreSSL
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

### CentOS version

The following steps are for CentOS 7, previous versions may require more steps to install Fort validator.

This OS requires additional steps due to its GCC supported version (currently 4.8.5, fort needs >= 4.9 to compile) and default OpenSSL version (currently 1.0.2k, fort needs >= 1.1.0).

**Install dependencies**

OpenSSL devel (openssl-devel) package isn't necessary, if it's previously installed remove it to avoid future conflicts with newer OpenSSL versions.

{% highlight bash %}
sudo yum install autoconf automake git jansson-devel pkgconfig rsync
# Install supported GCC to compile OpenSSL
sudo yum groupinstall "Development Tools"
{% endhighlight %}

**Upgrade OpenSSL from 1.0.2k to 1.1.0k**

The OpenSSL version must be greater than 1.0, in this case the version 1.1.0k is installed.

{% highlight bash %}
curl https://www.openssl.org/source/openssl-1.1.0k.tar.gz | tar xvz
cd openssl-1.1.0k
./config --prefix=/usr/local --openssldir=/usr/local/openssl
make
sudo make install
# Update library files
sudo mv libcrypto.so.1.1 libssl.so.1.1 /usr/lib64/
sudo ln -sfn /usr/local/bin/openssl /usr/bin/openssl
# Verify installed version
openssl version
{% endhighlight %}

**Upgrade GCC**

There are two options to upgrade GCC:
1. Compile and install a newer version >= 4.9 (slow process).
2. Use [Software Collections](https://www.softwarecollections.org) (indicated at the following steps).

{% highlight bash %}
sudo yum install centos-release-scl
sudo yum install devtoolset-7-gcc
# Start a session using the upgraded GCC
scl enable devtoolset-7 bash
cd ~
curl -L https://github.com/NICMx/FORT-validator/releases/download/v{{ site.fort-latest-version }}/fort-{{ site.fort-latest-version }}.tar.gz --output fort-{{ site.fort-latest-version }}.tar.gz
tar xvzf fort-{{ site.fort-latest-version }}.tar.gz
cd fort-{{ site.fort-latest-version }}
./configure
make
sudo make install
# Close the 'devtoolset' session
exit
{% endhighlight %}

### Fedora version

The following steps are for Fedora 30.

{% highlight bash %}
sudo yum install autoconf automake gcc make openssl-devel jansson-devel

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
sudo zypper install autoconf automake gcc libopenssl-devel libjansson-devel

wget https://github.com/NICMx/FORT-validator/releases/download/v{{ site.fort-latest-version }}/fort-{{ site.fort-latest-version }}.tar.gz
tar xvzf fort-{{ site.fort-latest-version }}.tar.gz
cd fort-{{ site.fort-latest-version }}/
./configure
make
sudo make install
{% endhighlight %}

### FreeBSD version

The following steps are for FreeBSD 12.0.

{% highlight bash %}
su
pkg install autoconf automake gcc jansson pkgconf rsync
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

The following steps are for Slackware "current" release (as of 2019-08-12).

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

The following example is the processo to clone, compile and install in Debian OS.

{% highlight bash %}
sudo apt install autoconf automake build-essential git libjansson-dev libssl-dev pkg-config rsync

git clone https://github.com/NICMx/FORT-validator.git
cd FORT-validator/
./autogen.sh
./configure
make
sudo make install
{% endhighlight %}
