---
title: Introduction to Fort
description: FORT Validator is a command line application intended for UNIX operating systems, written in C.
---

# {{ page.title }}

## Design

Fort is an MIT-licensed RPKI Relying Party. It is a service that downloads the RPKI repositories, validates their entirety and serves the resulting ROAs for easy access by your routers.

![img/design.svg](img/design.svg)

The Validator is a timer that, [every once in a while](usage.html#--serverintervalvalidation), resynchronizes its [local cache of the RPKI Repository](usage.html#--local-repository), validates the resulting [certificate chains](intro-rpki.html) and stores the resulting valid ROAs in memory. The RTR [Server](usage.html#--serveraddress) (which is part of the same binary) delivers these ROAs to any requesting routers.

Fort is a command-line application intended for UNIX operating systems, written in C.

## Roadmap

| Issue | Title | Urgency | Due release |
|-------|-------|---------|-------------|
| [issue82](https://github.com/NICMx/FORT-validator/issues/82) | Reach 100% RFC 9286 compliance | <span class="urgency-critical">Critical</span> | <a href="https://github.com/NICMx/FORT-validator/milestone/12">2.0.0</a> |
| [issue112](https://github.com/NICMx/FORT-validator/issues/112) | Enforce same origin for RRDP files | <span class="urgency-high">High</span> | <a href="https://github.com/NICMx/FORT-validator/milestone/12">2.0.0</a> |
| [issue149](https://github.com/NICMx/FORT-validator/issues/149) | Lock the cache during updates | <span class="urgency-high">High</span> | <a href="https://github.com/NICMx/FORT-validator/milestone/12">2.0.0</a> |
| [issue113](https://github.com/NICMx/FORT-validator/issues/113) | Detect and properly respond to subtler RRDP session desynchronization | <span class="urgency-medium">Medium</span> | <a href="https://github.com/NICMx/FORT-validator/milestone/12">2.0.0</a> |
| [issue124](https://github.com/NICMx/FORT-validator/issues/124) | Atomize output files (`--output.roa` and `--output.bgpsec`) | <span class="urgency-medium">Medium</span> | <a href="https://github.com/NICMx/FORT-validator/milestone/12">2.0.0</a> |
| [issue114](https://github.com/NICMx/FORT-validator/issues/114) | Support automatic TA key rollover | <span class="urgency-very-high">Very High</span> | <a href="https://github.com/NICMx/FORT-validator/milestone/13">2.0.1</a> |
| [issue50](https://github.com/NICMx/FORT-validator/issues/50) | Provide prometheus endpoint | <span class="urgency-very-high">Very High</span> | <a href="https://github.com/NICMx/FORT-validator/milestone/14">2.0.2</a> |
| [issue58](https://github.com/NICMx/FORT-validator/issues/58) | Fort's validation produces no router keys | <span class="urgency-very-high">Very High</span> | <a href="https://github.com/NICMx/FORT-validator/milestone/15">2.0.3</a> |
| [issue116](https://github.com/NICMx/FORT-validator/issues/116) | SLURM review | <span class="urgency-high">High</span> | - |
| [issue118](https://github.com/NICMx/FORT-validator/issues/118) | Implement validation re-reconsidered | <span class="urgency-high">High</span> | - |
| [issue119](https://github.com/NICMx/FORT-validator/issues/119) | Review IRIs to file names transition | <span class="urgency-high">High</span> | - |
| [issue120](https://github.com/NICMx/FORT-validator/issues/120) | Error messages review | <span class="urgency-high">High</span> | - |
| [issue121](https://github.com/NICMx/FORT-validator/issues/121) | Refactor validation and operation logging | <span class="urgency-high">High</span> | - |
| [issue72](https://github.com/NICMx/FORT-validator/issues/72) | Encrypt RTR | <span class="urgency-medium">Medium</span> | - |
| [issue73](https://github.com/NICMx/FORT-validator/issues/73) | Minimize probability of RTR session ID and serial reuse | <span class="urgency-medium">Medium</span> | - |
| [issue90](https://github.com/NICMx/FORT-validator/issues/90) | Add "metadata" section to json output | <span class="urgency-medium">Medium</span> | - |
| [issue91](https://github.com/NICMx/FORT-validator/issues/91) | Add "ta" field to ROAs in json output | <span class="urgency-medium">Medium</span> | - |
| [issue97](https://github.com/NICMx/FORT-validator/issues/97) | Add "incidence" fields for every nonfatal RFC incompliance | <span class="urgency-medium">Medium</span> | - |
| [issue117](https://github.com/NICMx/FORT-validator/issues/117) | Warn on maxLength defined on SLURM | <span class="urgency-medium">Medium</span> | - |
| [issue125](https://github.com/NICMx/FORT-validator/issues/125) | ASN.1 review | <span class="urgency-medium">Medium</span> | - |
| [issue126](https://github.com/NICMx/FORT-validator/issues/126) | Exhaustive URL validation | <span class="urgency-medium">Medium</span> | - |
| [issue127](https://github.com/NICMx/FORT-validator/issues/127) | Stream RRDP files | <span class="urgency-medium">Medium</span> | - |
| [issue128](https://github.com/NICMx/FORT-validator/issues/128) | Reuse TCP connections for HTTP requests to same server | <span class="urgency-medium">Medium</span> | - |
| [issue129](https://github.com/NICMx/FORT-validator/issues/129) | Rethink the thread pools | <span class="urgency-medium">Medium</span> | - |
| [issue130](https://github.com/NICMx/FORT-validator/issues/130) | Improve documentation | <span class="urgency-medium">Medium</span> | - |
| [issue151](https://github.com/NICMx/FORT-validator/issues/151) | [Enhancement]: Add ability to set ACLs for router connections | <span class="urgency-medium">Medium</span> | - |
| [issue152](https://github.com/NICMx/FORT-validator/issues/152) | compliance issue: Fort accepts GeneralizedTime with fractional seconds | <span class="urgency-medium">Medium</span> | - |
| [issue153](https://github.com/NICMx/FORT-validator/issues/153) | Not enforcing DER encoding | <span class="urgency-medium">Medium</span> | - |
| [issue40](https://github.com/NICMx/FORT-validator/issues/40) | failure scenarios, monitoring and glibc recommendations | <span class="urgency-low">Low</span> | - |
| [issue42](https://github.com/NICMx/FORT-validator/issues/42) | reload feature: restart validation on SIGHUP | <span class="urgency-low">Low</span> | - |
| [issue70](https://github.com/NICMx/FORT-validator/issues/70) | Do a quick temporary offline validation to prevent `No Data Available` | <span class="urgency-low">Low</span> | - |
| [issue123](https://github.com/NICMx/FORT-validator/issues/123) | New invocation mode: Validate single file | <span class="urgency-low">Low</span> | - |
| [issue131](https://github.com/NICMx/FORT-validator/issues/131) | Implement vCard validation | <span class="urgency-low">Low</span> | - |
| [issue132](https://github.com/NICMx/FORT-validator/issues/132) | Implement RTRv2 | <span class="urgency-low">Low</span> | - |
| [issue134](https://github.com/NICMx/FORT-validator/issues/134) | Add support RFC 9589 (On the Use of the CMS Signing-Time Attribute in RPKI Signed Objects) | <span class="urgency-low">Low</span> | - |
