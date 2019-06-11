---
title: Compilation and Installation
---

[Documentation](index.html) > {{ page.title }}

# {{ page.title }}

> TODO update with proper .tar.gz releases, once they are created

## Index

1. [Dependencies](#dependencies)
2. [Option 1: Installing the Debian package](#option-1-installing-the-debian-package)
3. [Option 2: Compiling and installing the release tarball](#option-2-compiling-and-installing-the-release-tarball)
	1. [Debian version](#debian-version)
	2. [OpenBSD version](#openbsd-version)
4. [Option 3: Compiling from the git repositories](#option-3-compiling-from-the-git-repositories)

## Dependencies

> Note: I'm only including this section in case you intend to install Fort in an unlisted OS (and therefore need a little research). For Debians and OpenBSD, just follow the steps in the sections below.

The dependencies are

1. [jansson](http://www.digip.org/jansson/)
2. [libcmscodec](https://github.com/NICMx/libcmscodec)
3. libcrypto (Either [LibreSSL](http://www.libressl.org/) or [OpenSSL](https://www.openssl.org/))
4. [rsync](http://rsync.samba.org/)

The build dependencies are

- [autoconf](https://www.gnu.org/software/autoconf/)
- unzip (or [git](https://git-scm.com/))

(Some builds do not need all these dependencies.)

## Option 1: Installing the Debian package

> TODO Upload to Debian, add more archs and/or host these links on Github releases properly.

{% highlight bash %}
wget https://www.dropbox.com/s/dbdhn4yd9m3nnct/libcmscodec1_0.0.1-1_amd64.deb
wget https://www.dropbox.com/s/7c0rs49ewcu6m93/fort_0.0.1-1_amd64.deb
sudo apt install ./libcmscodec1_0.0.1-1_amd64.deb ./fort_0.0.1-1_amd64.deb
{% endhighlight %}

Aside from the `fort` binary documented elsewhere in this documentation, the Debian package also ships with a systemd service, which you can [configure](usage.html#--configuration-file) at `/etc/fort/config.json`.

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
########### normal dependencies ###########
sudo apt install autoconf build-essential libjansson-dev libssl-dev pkg-config rsync unzip

############### libcmscodec ###############
mkdir libcmscodec
cd libcmscodec/
wget https://github.com/NICMx/libcmscodec/releases/download/{{ site.libcmscodec-latest-version }}/libcmscodec-{{ site.libcmscodec-latest-version }}.tar.gz
tar xvzf libcmscodec-{{ site.libcmscodec-latest-version }}.tar.gz
cd libcmscodec-{{ site.libcmscodec-latest-version }}/
./configure
make
sudo make install
sudo ldconfig
cd ../../

################## fort ###################
mkdir fort
cd fort/
wget https://github.com/NICMx/FORT-validator/archive/master.zip
# tar xvzf fort-{{ site.fort-latest-version }}.tar.gz
unzip master.zip
cd FORT-validator-master/
./autogen.sh
./configure
make
sudo make install
cd ../../
{% endhighlight %}

### OpenBSD version

> TODO: The autotools are weird in this OS.
> 
> They require some global variables the installer doesn't setup on its own for some reason, and then spew error messages encouraging long deprecated macros. WTF?
> 
> For now, I'm working around this by running the `autogen.sh`s in Debian. It probably needn't be fixed, since the releases are going to ship with the `autogen.sh`s already executed anyway.

{% highlight bash %}
########### normal dependencies ###########
su
# OpenBSD already ships with LibreSSL
pkg_add jansson libexecinfo rsync unzip
exit

############### libcmscodec ###############
mkdir libcmscodec
cd libcmscodec/
ftp https://github.com/NICMx/libcmscodec/releases/download/{{ site.libcmscodec-latest-version }}/libcmscodec-{{ site.libcmscodec-latest-version }}.tar.gz
tar xvzf libcmscodec-{{ site.libcmscodec-latest-version }}.tar.gz
cd libcmscodec-{{ site.libcmscodec-latest-version }}/
./configure
make
su
make install
exit
cd ../../

################## fort ###################
mkdir fort
cd fort/
ftp https://github.com/NICMx/FORT-validator/archive/master.zip
# tar xvzf fort-{{ site.fort-latest-version }}.tar.gz
unzip master.zip
cd FORT-validator-master
./autogen.sh # Run this elsewhere
# clang is needed because of gnu11.
env CC=clang CFLAGS=-I/usr/local/include LDFLAGS=-L/usr/local/lib ./configure
make
su
make install
exit
cd ../../
{% endhighlight %}

## Option 3: Compiling the git repositories

{% highlight bash %}
########### normal dependencies ###########
sudo apt install autoconf build-essential git libjansson-dev libssl-dev pkg-config rsync

################## asn1c ##################
# (Needed by libcmscodec's autogen. Relatively recent commit required.)
git clone https://github.com/vlm/asn1c.git
cd asn1c
test -f configure || autoreconf -iv
./configure
make
sudo make install

############### libcmscodec ###############
git clone https://github.com/NICMx/libcmscodec.git
cd libcmscodec/
./autogen.sh
./configure
make
sudo make install
sudo ldconfig
cd ../

################## fort ###################
git clone https://github.com/NICMx/FORT-validator.git
cd FORT-validator/
./autogen.sh
./configure
make
sudo make install
cd ../
{% endhighlight %}
