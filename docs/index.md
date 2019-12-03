---
title: Home
---

# {{ page.title }}

## Introduction

FORT validator is an MIT-licensed RPKI Relying Party, this is a tool offered as part of the [FORT project](https://www.fortproject.net/). It is a service that performs the validation of the entire RPKI repository, and which serves the resulting ROAs for easy access by your routers.

## Status

Version [{{ site.fort-latest-version }}](https://github.com/NICMx/FORT-validator/releases/tag/v{{ site.fort-latest-version }}){:target="_blank"} is the latest official release, includes a bug fix:
- Whenever multiple TAL's are being validated, if an error occurs while fetching the root certificate from one of them, discard the validation results from the rest of the TALs. This will avoid to send a considerable amount of withdrawal PDUs to the router(s) due to an error that isn't proper of the RPKI validation.