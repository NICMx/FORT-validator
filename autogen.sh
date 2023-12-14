#!/bin/sh
#
# Script to help bootstrap the build system when checked out from git
#

bsd_environment() {
	# Based on https://github.com/rvm/rvm/blob/59fe3b39f0fb5ae01ed5b9aa187201080815ac16/scripts/functions/build_config_system#L123
	if [ -z "${AUTOCONF_VERSION}" ]
	then
		export AUTOCONF_VERSION
		AUTOCONF_VERSION="$(
		    ls -1 /usr/local/bin/autoreconf-* |
		    awk -F- '{print $NF}' |
		    sort |
		    tail -n 1
		)"
		echo "Using autoconf version: $AUTOCONF_VERSION"
	fi

	if [ -z "${AUTOMAKE_VERSION}" ]
	then
		export AUTOMAKE_VERSION
		# FreeBSD might have automake-wrapper
		AUTOMAKE_VERSION="$(
		    ls -1 /usr/local/bin/automake-1* |
		    awk -F- '{print $NF}' |
		    sort |
		    tail -n 1
		)"
		echo "Using automake version: $AUTOMAKE_VERSION"
	fi
}

# Use the uname string to figure out if this is a BSD
case "$(uname)" in
	*BSD*) bsd_environment ;;
esac

test -n "$srcdir" || srcdir="$(dirname "$0")"
test -n "$srcdir" || srcdir=.

autoreconf --force --install --verbose "$srcdir"
