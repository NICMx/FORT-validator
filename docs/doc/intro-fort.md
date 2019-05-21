---
title: Introduction to Fort
---

# {{ page.title }}

## Design

Fort is an MIT-licensed RPKI Relying Party. It is a service that performs the validation of the entire RPKI repository, and which serves the resulting ROAs for easy access by your routers.

![../img/design.svg](../img/design.svg)

It is a command line application intended for UNIX operating systems. (It requires a C compiler that supports `-std=gnu11`.)

## Standards Compliance 

Further information can be found in the subsections below.

| RFC                                                                        | Implemented |
|----------------------------------------------------------------------------|-------------|
| [3779](https://tools.ietf.org/html/rfc3779) (IP & AS Extensions)           | 100%        |
| [6350](https://tools.ietf.org/html/rfc6350) (vCard)                        | 0%          |
| [6482](https://tools.ietf.org/html/rfc6482) (ROA)                          | 100%        |
| [6486](https://tools.ietf.org/html/rfc6486) (Manifests)                    | 75%         |
| [6487](https://tools.ietf.org/html/rfc6487) (Resource Certificates & CRLs) | 100%        |
| [6488](https://tools.ietf.org/html/rfc6488) (Signed Objects)               | 90%         |
| [6493](https://tools.ietf.org/html/rfc6493) (Ghostbusters)                 | 100%        |
| [7318](https://tools.ietf.org/html/rfc7318) (Policy Qualifiers)            | 100%        |
| [7730](https://tools.ietf.org/html/rfc7730) (TALs)                         | 100%        |
| [7935](https://tools.ietf.org/html/rfc7935) (RPKI algorithms)              | 100%        |
| [8182](https://tools.ietf.org/html/rfc8182) (RRDP)                         | 0%          |
| [8209](https://tools.ietf.org/html/rfc8209) (BGPSec Certificates)          | 0%          |
| [8360](https://tools.ietf.org/html/rfc8360) (Validation Reconsidered)      | 100%        |

### RFC 6350 (vCard)

The vCard format is only used by Ghostbusters records. 6350 defines the basic vCard format, while 6493 defines additional requirements for Ghostbusters-specific vCard.

The specific validations have been implemented, while the basic ones have not.

### RFC 6486 (Manifests)

This RFC states a bunch of rules that allow some level of tolerance to missing, invalid or stale manifests. Here's an example:

> signed objects (...) issued by the entity that has published the stale manifest (...) SHOULD be viewed as somewhat suspect, but MAY be used by the RP as per local policy.

These constitute the approximate missing 25%.

### RFC 6488 (Signed Objects)

6488 mandates that all signed objects must be DER-encoded. Fort's current parser cannot tell the difference between BER and DER.

### RFC 8182 (RRDP)

RRDP is a protocol intended to replace RSYNC in the RPKI. Fort only implements RSYNC, currently.

## TO-DO

- Reach full 100% RFC compliance.
- Maybe a few optimizations, marked as `TODO` in the code.
