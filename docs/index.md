---
title: Home
---

# {{ page.title }}

## Introduction

FORT validator is an MIT-licensed RPKI Relying Party, this is a tool offered as part of the [FORT project](https://www.fortproject.net/). It is a service that performs the validation of the entire RPKI repository, and which serves the resulting ROAs for easy access by your routers.

## Status

Version [{{ site.fort-latest-version }}](https://github.com/NICMx/FORT-validator/releases/tag/v{{ site.fort-latest-version }}){:target="_blank"} is the latest official release, includes several updates, including:
- RRDP support (see [RFC 8182](https://tools.ietf.org/html/rfc8182)).
- Support HTTPS URIs at TALs (see [RFC 8630](https://tools.ietf.org/html/rfc8630)).
- Remember last valid SLURM in case of syntax error with a newer version.
- Setup script to fetch ARINs TAL.
- Add incidence to validate signed objects DER encoding.