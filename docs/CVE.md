---
title: CVE
---

# CVEs

## CVE-2024-45238

Certificate containing a malformed `subjectPublicKey` crashes Fort 1.6.2-, when compiled with OpenSSL < 3.

| Description | A malicious RPKI repository that descends from a (trusted) Trust Anchor can serve (via rsync or RRDP) a resource certificate containing a bit string that doesn't properly decode into a Subject Public Key. OpenSSL does [not report this problem during parsing](https://github.com/openssl/openssl/blob/OpenSSL_1_1_1w/crypto/x509/x_pubkey.c#L152-L157), and when compiled with OpenSSL libcrypto versions below 3, Fort was recklessly dereferencing the pointer. |
| Impact | Crash. (Potential unavailability of Route Origin Validation.) |
| Patch | Commit [5689dea](https://github.com/NICMx/FORT-validator/commit/5689dea5e878fed28c5f338a27d7cda4151a14f1), released in Fort 1.6.3. |
| Acknowledgments | Thanks to Niklas Vogel and Haya Schulmann for their research and disclosure. |

## CVE-2024-45237

Certificate containing a Key Usage bit string longer than 2 bytes causes buffer overflow on Fort 1.6.2-.

| Description | A malicious RPKI repository that descends from a (trusted) Trust Anchor can serve (via rsync or RRDP) a resource certificate containing a [Key Usage extension](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3) consisting of more than two bytes of data. Fort used to write this string on a 2-byte buffer without properly sanitizing its length, leading to buffer overflow. |
| Impact | Depending on compilation options, the vulnerability would lead to a crash (which might in turn lead to unavailability of Route Origin Validation), incorrect validation results or arbitrary code execution. |
| Patch | Commit [939d988](https://github.com/NICMx/FORT-validator/commit/939d988551d17996be73f52c376a70a3d6ba69f9), released in Fort 1.6.3. |
| Acknowledgments | Thanks to Niklas Vogel and Haya Schulmann for their research and disclosure. |

## CVE-2024-45235

Certificate containing an Authority Key Identifier missing a `keyIdentifier` crashes Fort 1.6.2-.

| Description | A malicious RPKI repository that descends from a (trusted) Trust Anchor can serve (via rsync or RRDP) a resource certificate containing an [Authority Key Identifier extension](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.1) missing the `keyIdentifier` field. Fort was referencing the pointer without sanitizing it first. |
| Impact | Crash. (Potential unavailability of Route Origin Validation.) |
| Patch | Commit [b1eb3c5](https://github.com/NICMx/FORT-validator/commit/b1eb3c507ae920859bbe294776ebc2bb30bb7e56), released in Fort 1.6.3. |
| Acknowledgments | Thanks to Niklas Vogel and Haya Schulmann for their research and disclosure. |

## CVE-2024-45236

Signed Object containing empty `signedAttrs` crashes Fort 1.6.2-.

| Description | A malicious RPKI repository that descends from a (trusted) Trust Anchor can serve (via rsync or RRDP) a signed object containing an empty [`signedAttributes`](https://datatracker.ietf.org/doc/html/rfc6488#section-2.1.6.4). Fort was accessing the set's elements without sanitizing it first. |
| Impact | Crash. (Potential unavailability of Route Origin Validation.) |
| Patch | Commit [4dafbd9](https://github.com/NICMx/FORT-validator/commit/4dafbd9de64a5a0616af97365bc1751465b29d2e), released in Fort 1.6.3. |
| Acknowledgments | Thanks to Niklas Vogel and Haya Schulmann for their research and disclosure. |

## CVE-2024-45239

Signed Object containing null `eContent` crashes Fort 1.6.2-.

| Description | A malicious RPKI repository that descends from a (trusted) Trust Anchor can serve (via rsync or RRDP) a ROA or Manifest containing a null [`eContent`](https://datatracker.ietf.org/doc/html/rfc6488#section-2.1.3.2). Fort was dereferencing the pointer without sanitizing it first. |
| Impact | Crash. (Potential unavailability of Route Origin Validation.) |
| Patch | Commit [942f921](https://github.com/NICMx/FORT-validator/commit/942f921ba7244cdcf4574cedc4c16392a7cc594b), released in Fort 1.6.3. |
| Acknowledgments | Thanks to Niklas Vogel and Haya Schulmann for their research and disclosure. |

## CVE-2024-45234

Certificate containing `signedAttrs` not in canonical form crashes Fort 1.6.2-.

| Description | A malicious RPKI repository that descends from a (trusted) Trust Anchor can serve (via rsync or RRDP) a ROA or Manifest containing a `signedAttrs` encoded in non-canonical form. This bypassed the BER-decoder, reaching a point in the code that panicked when faced with data not encoded in DER. |
| Impact | Crash. (Potential unavailability of Route Origin Validation.) |
| Patch | Commit [521b1a0](https://github.com/NICMx/FORT-validator/commit/521b1a0db5041258096fbabdf8fc1e10ecc793cf), released in Fort 1.6.3. |
| Acknowledgments | Thanks to Niklas Vogel and Haya Schulmann for their research and disclosure. |

## CVE-2024-48943

Malicious rsync repositories can block Fort by drip-feeding repository objects.

| Description | A malicious RPKI rsync repository can prevent Fort from finishing its validation run by drip-feeding its content. |
| Impact | Delayed validation. (Stale or unavailable Route Origin Validation.) |
| Patch | Commit [4ee88d1](https://github.com/NICMx/FORT-validator/commit/4ee88d1c3fa7df763dd52312134cd93c1ce50870), released in Fort 1.6.4. |
| Acknowledgments | Thanks to Koen van Hove for his research and disclosure, and Job Snijders for the proposed fix. |
