# Fort-validator

(Not sure if that's going to be the final name.)

An RPKI Validator.

## Installation

Dependencies:

1. libcrypto ([LibreSSL](http://www.libressl.org/) or [OpenSSL](https://www.openssl.org/))
2. [tomlc99](https://github.com/cktan/tomlc99)
3. [libcmscodec](https://github.com/ydahhrk/libcmscodec)
4. [rsync](http://rsync.samba.org/)

```
./autogen.sh
./configure
make
make install
```

## Compliance 

Further information can be found in the subsections below.

| RFC                              | Implemented |
|----------------------------------|-------------|
| 3779 (IP & AS Extensions)        | 100%        |
| 6350 (VCARD)                     | 0%          |
| 6482 (ROA)                       | 100%        |
| 6486 (Manifests)                 | 75%         |
| 6488 (Signed Objects)            | 90%         |
| 6487, 7318 (Certificates & CRLs) | 100%        |
| 6493 (Ghostbusters)              | 100%        |
| 7730 (TALs)                      | 100%        |
| 7935 (RPKI algorithms)           | 100%        |
| 8182 (RRDP)                      | 0%          |
| 8209 (BGPSec Certificates)       | 0%          |
| 8360 (Validation Reconsidered)   | 100%        |

### RFC 6350 (VCARD)

The VCARD format is only used by Ghostbusters records. 6350 defines the basic VCARD format, while 6493 defines additional requirements for Ghostbusters-specific VCARDs.

The specific requirements have been implemented, while the basic ones have not.

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
