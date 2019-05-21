---
title: Incidence
---
 
[Documentation](index.html) > {{ page.title }}

# {{ page.title }} 

## Index

1. [Introduction](#introduction)
2. [`incidences` definition](#incidences-definition)
3. [Incidence types](#incidence-types)
	1. [rsaEncryption signature algorithm has parameters](#rsaencryption-signature-algorithm-has-parameters)
	2. [certificate public key algorithm is rsaEncryption](#certificate-public-key-algorithm-is-rsaencryption)

## Introduction

The RPKI RFCs define fairly strict profiles for RPKI objects, and are unequivocal in stating that incorrectly-formed objects are supposed to be rejected by Relying Party validation. In practice, however, this does not stop a significant amount of Certificate Authorities from issuing incorrect objects.

By default, Fort is as pedantic as it can reasonably be. The `incidence` section of its configuration file is a means to modify its behavior upon encountering profile violations that, from experience, are often overlooked.

## `incidences` definition

`incidences` is a JSON array that contains (anonymous) incidence elements. Here's an example:

```
"incidences": [
	{
		"name": "rsaEncryption signature algorithm has parameters",
		"action": "warn"
	}, {
		"name": "certificate public key algorithm is rsaEncryption",
		"action": "ignore"
	}
]
```

`name` is the identifier of an incidence. It's case-sensitive and developer-defined. It states the particular error condition that will be handled by the remaining field.

`action` is an enumeration that states the outcome of a violation of the corresponding incidence. It can take one of three values:

1. `error`: Print error message in `error` log level, fail validation of the offending object (and all of its children).
2. `warn`: Print error message in `warning` log level, continue validation as if nothing happened.
3. `ignore`: Do not print error message, continue validation as if nothing happened.

By Fort's pedantic nature, most incidences have an `action` of `error` by default.

## Incidence types

Presently, there are only two incidence types defined. This list might grow over time, depending on the state of the global RPKI and user demand.

### rsaEncryption signature algorithm has parameters

[RFC 6488](https://tools.ietf.org/html/rfc6488) (RPKI Signed Objects) defers signature algorithm specification to RFC 6485:

```
2.1.6.5.  signatureAlgorithm

   The signatureAlgorithm MUST conform to the RPKI Algorithms and Key
   Size Profile specification [RFC6485].
```

[6485](https://tools.ietf.org/html/rfc6485) has been obsoleted by [7935](https://tools.ietf.org/html/rfc7935), which states the following:

```
   RPKI implementations MUST
   accept either rsaEncryption or sha256WithRSAEncryption for the
   SignerInfo signatureAlgorithm field when verifying CMS SignedData
   objects (for compatibility with objects produced by implementations
   conforming to [RFC6485]).
```

Regarding `rsaEncryption`, [3370](https://tools.ietf.org/html/rfc3370) states

```
   When the rsaEncryption algorithm identifier is used, the
   AlgorithmIdentifier parameters field MUST contain NULL.
```

As of 2019-05-21, many signed objects in the global RPKI break this rule. (`parameters` is often defined as an empty object, but not NULL nonetheless.)

If not `ignore`d, Fort will report this incidence with the following error message:

```
<log level>: <offending file name>: rsaEncryption signature algorithm has parameters.
```

### certificate public key algorithm is rsaEncryption

> TODO missing code
