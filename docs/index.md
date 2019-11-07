---
title: Home
---

# {{ page.title }}

## Introduction

FORT validator is an MIT-licensed RPKI Relying Party, this is a tool offered as part of the [FORT project](https://www.fortproject.net/). It is a service that performs the validation of the entire RPKI repository, and which serves the resulting ROAs for easy access by your routers.

## Status

Version [{{ site.fort-latest-version }}](https://github.com/NICMx/FORT-validator/releases/tag/v{{ site.fort-latest-version }}){:target="_blank"} is the latest official release, includes minor upgrades:
- New program arguments: `log.level` and `log.output` (see [Logging](logging.html)).
- Add license for asn1c created code.
- Remove `<sys/cdefs.h>` header since isn't really necessary.
- Add `-Wno-cpp` flag at compilation to avoid such warnings.