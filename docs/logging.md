---
title: Logging
---

# {{ page.title }}

- If Fort is run in [server mode](usage.html#--mode), all logging is sent to syslog.
- If Fort is run in standalone mode, informational messages are printed in standard output and error messages are thrown to standard error.

During the brief period in which configuration has not been completely parsed yet (and therefore, Fort is not yet aware of the desired running mode), the standard streams and syslog are used simultaneously.

Fort uses exactly five syslog levels of priority. These are their meanings:

- `crit`: Programming errors. (These lead to program termination.)
- `err`: Validation failures. (RPKI object rejected.)
- `warning`: Suspicious validation outcome. (RPKI object not rejected.)
- `info`: Information deemed useful to the user:
	- Configuration echo at the beginning.
	- Server binding status.
	- Additional noise we're considering downgrading to `debug`.
- `debug`: Information deemed useful to the developer. These messages are usually compiled out of the binary by default. If you want them, you need to enable `-DDEBUG` (eg. by uncommenting [`CFLAGS_DEBUG`](https://github.com/NICMx/FORT-validator/blob/master/src/Makefile.am#L3)).

When standard streams are enabled, `info` and `debug` are printed in standard output, while rest are printed in standard error.

