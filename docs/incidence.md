---
title: Incidence
---
 
# {{ page.title }} 

## Index

1. [Introduction](#introduction)
2. [`incidences` definition](#incidences-definition)
3. [Incidence types](#incidence-types)
	1. [Signed Object's hash algorithm has NULL object as parameters](#signed-objects-hash-algorithm-has-null-object-as-parameters)
	2. [Object isn't DER encoded](#object-isnt-der-encoded)

## Introduction

The RPKI RFCs define fairly strict profiles for RPKI objects, and are unequivocal in stating that incorrectly-formed objects are supposed to be rejected by Relying Party validation. In practice, however, this does not prevent a significant amount of legitimate Certificate Authorities from issuing incorrect objects.

The `incidence` section of Fort's configuration file is a means to modify its behavior upon encountering profile violations that, from experience, are often overlooked.

## `incidences` definition

`incidences` is a JSON array that contains (anonymous) incidence elements. Here's an example:

```
"incidences": [
	{
		"name": "incid-hashalg-has-params",
		"action": "warn"
	}
]
```

`name` is the identifier of an incidence. It is case-sensitive and developer-defined. It states the ID of the particular error condition that will be handled by the remaining field.

`action` is an enumeration that states the outcome of a violation of the corresponding incidence. It can take one of three values:

1. `error`: Print error message in `error` log level, fail validation of the offending object (and all of its children).
2. `warn`: Print error message in `warning` log level, continue validation as if nothing happened.
3. `ignore`: Do not print error message, continue validation as if nothing happened.

Some incidences are `ignore`d by default, because they stem from bad practices (which are nonetheless likely harmless) in the global RPKI repositories. If a strict behavior is desired, then the corresponding incidence `action` should be upgraded.

## Incidence types

Presently, there is only a pair of incidence types defined. This list might evolve further over time, depending on the state of the global RPKI and user demand.

### Signed Object's hash algorithm has NULL object as parameters

- **Name:** `incid-hashalg-has-params`
- **Default action:** `ignore`

[RFC 6488](https://tools.ietf.org/html/rfc6488) (RPKI Signed Objects) defers digest algorithm specification to RFC 6485:

```
   The digestAlgorithms set contains the OIDs of the digest algorithm(s)
   used in signing the encapsulated content.  This set MUST contain
   exactly one digest algorithm OID, and the OID MUST be selected from
   those specified in [RFC6485].
```

[6485](https://tools.ietf.org/html/rfc6485) has been obsoleted by [7935](https://tools.ietf.org/html/rfc7935), which states the following:

```
   The object identifier and
   parameters for SHA-256 (as defined in [RFC5754]) MUST be used for the
   SignedData digestAlgorithms field and the SignerInfo digestAlgorithm
   field.
```

[RFC 5754](https://tools.ietf.org/html/rfc5754):

```
   There are two possible encodings for the AlgorithmIdentifier
   parameters field associated with these object identifiers. (...)
   some implementations encode parameters as a NULL element
   while others omit them entirely.  The correct encoding is to omit the
   parameters field;
```

As of 2020-01-31, many signed objects in the global RPKI break this rule.

If not `ignore`d, Fort will report this incidence with the following error message:

```
<log level>: <offending file name>: The hash algorithm of the '<object>' has a NULL object as parameters
```

This only applies to digest parameters that have been defined as NULL objects; any other type of non-absent digest parameters will yield a different error message, and will therefore not be silenced.

### Object isn't DER encoded

- **Name:** `incid-obj-not-der-encoded`
- **Default action:** `ignore`


[RFC 6488](https://tools.ietf.org/html/rfc6488) mandates that all signed objects must be DER-encoded (see [section 3](https://tools.ietf.org/html/rfc6488#section-3)):

```
      l.  The signed object is DER encoded.
```

Altough this is mandatory, quite a few signed objects in the global RPKI ignore this rule and are simply BER-encoded.

If not `ignore`d, Fort will report this incidence with the following error message:

```
<log level>: <offending file name>: '<object>' isn't DER encoded
```
