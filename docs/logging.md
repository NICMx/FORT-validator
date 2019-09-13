---
title: Logging
---

# {{ page.title }}

- If Fort is run in [server mode](usage.html#--mode), all logging is sent to syslog.
- If Fort is run in standalone mode, informational messages are printed in standard output and error messages are thrown to standard error.

During the brief period in which configuration has not been completely parsed yet (and therefore, Fort is not yet aware of the desired running mode), the standard streams and syslog are used simultaneously.

