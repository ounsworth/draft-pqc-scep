---
title: "Post-Quantum updates for the Simple Certificate Enrolment Protocol (SCEP)"
abbrev: "pqc-scep"
category: info

docname: draft-pqc-scep-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
updates: 8894
date:
consensus: true
v: 3
# area: AREA
# workgroup: WG Working Group
keyword:
 - SCEP
 - PKI
 - X.509 Certificate Management
 - Post-Quantum
venue:
#  group: WG
#  type: Working Group
#  mail: WG@example.com
#  arch: https://example.com/WG
  github: "ounsworth/draft-pqc-scep"
  latest: "https://ounsworth.github.io/draft-pqc-scep/draft-pqc-scep.html"

author:
 -
    ins: M. Kushner
    fullname: Mike Agrenius Kushner
    organization: Keyfactor
    email: mike.kushner@keyfactor.com
 -
    ins: M. Ounsworth
    fullname: Mike Ounsworth
    org: Cryptic Forest Software
    abbrev: Cryptic Forest
    city: Sioux Lookout, Ontario
    country: Canada
    email: mike@ounsworth.ca
 -
   ins: A. Harrison
   fullname: Alex Harrison
   org: Cisco Systems
   email: aleharri@cisco.com

normative:
    RFC5652:
    RFC8894:
    RFC9629:

informative:
    RFC9881:
    RFC9909:
    RFC9936:

...

--- abstract

The Simple Certificate Enrolment Protocol (SCEP), as specified in RFC 8894,
was designed around RSA and the assumption that a single key pair
can be used for both signing and encryption. This assumption will not hold for post-quantum key pairs.

This document specifies several mechanisms to modernize SCEP for use with post-quantum cryptography.
The main focus areas are: 1. allowing the CA to have separate signing and encryption certificates,
2. support for KEM-based SCEP protocol encryption, and 3. supporting enrolment of KEM end entity certificates.

The changes are kept minimal so that they can be easily implemented with minimal impact on existing
SCEP tooling.


--- middle

# Introduction

The Simple Certificate Enrolment Protocol (SCEP) {{RFC8894}} predates the widespread use of TLS, and protects its own messages using the Cryptographic Message Syntax (CMS) {{RFC5652}}. Each SCEP message is signed by its sender and encrypted to its recipient. SCEP was designed around RSA, where a Certification Authority (CA) uses one key pair to decrypt SCEP requests, sign SCEP responses, and sign issued certificates. A client uses one key pair both to sign its request and to receive the encrypted response.

Post-quantum algorithms do not fit this model. ML-DSA {{RFC9881}} and SLH-DSA {{RFC9909}} can only sign, and ML-KEM {{?RFC9935}} is a Key Encapsulation Mechanism (KEM) that can only establish shared secrets. A SCEP CA or client with only post-quantum keys therefore cannot use {{RFC8894}} as it stands. Meanwhile, requests encrypted using RSA key transport, including the challengePassword they carry, are exposed to an attacker who records them now and decrypts them later with a cryptographically relevant quantum computer.

This document updates {{RFC8894}} as follows:

* The CA can hold a separate encryption certificate alongside its signing certificate, and returns both in GetCACert and GetNextCACert responses ({{ca-signing-and-encryption-certificates}}).
* Clients can encrypt requests to a CA's KEM key using the CMS KEMRecipientInfo mechanism {{RFC9629}}, for example with ML-KEM {{RFC9936}} ({{encrypting-requests-with-a-kem-algorithm}}).
* The CA encrypts responses to such requests under a key derived from the request, so a client whose key can only sign can still receive an encrypted response protected by a KEM-based key exchange ({{encrypting-responses}}).
* Options for enrolling KEM end-entity keys are described as an open problem ({{enrolment-of-kem-end-entity-certificates}}).

These changes are optional updates to the SCEP protocol and are kept to a minimum. They introduce no new message types. Existing messages change only in which certificates the CA returns in the certificate bag, and which CMS RecipientInfo types are used. CAs and clients that do not implement this document continue to interoperate as described in {{RFC8894}}. Open design questions requiring WG attention are collected in {{appdx-open-questions}}.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# CA Signing and Encryption Certificates

{{RFC8894}} assumes that the CA uses a single key pair to decrypt SCEP requests, sign SCEP responses, and sign certificates,. {{Section 2.1.2 of RFC8894}} requires the CA certificate to assert both the digitalSignature and keyEncipherment key usages. GetCACert ({{Section 4.2 of RFC8894}}) returns either that one certificate or together with a bag of intermediate CA certificates.

This document modifies {{RFC8894}} in the following ways.

The CA certificate MAY omit the keyEncipherment key usage, as required by a signing-only algorithm. When it does, unless the CA relies on the PasswordRecipientInfo mechanism as described in {{Section 3.1 of RFC8894}}, the CA MUST possess a SCEP protocol encryption certificate, which MUST carry the keyEncipherment key usage and basicConstraints.cA = false, and SHOULD be issued by the CA's signing certificate. When the CA possesses a pair of signing and encryption certificates in this way, the client encrypts SCEP requests to the CA's encryption certificate and verifies SCEP responses using the CA's signing certificate.

As with {{RFC8894}}, the client obtains the CA's certificates via the GetCACert request ({{Section 4.2 of RFC8894}}). When the CA possesses both a signing and an encryption certificate, the response is formatted exactly as described in {{Section 4.2.1.2 of RFC8894}}, with the bag of certificates containing both the CA's signing and encryption certificates MAY contain additional intermediate certificates. As the response is an un-ordered certificate bag, no order is implied, and the SCEP client MUST be capable of distinguishing the CA's signing and encryption certificates by key usage, and of path building through the provided intermediates.

When the CA possesses both a signing and an encryption certificate, the GetNextCACert response ({{Section 4.7 of RFC8894}}) behaves the same way and MUST contain both the CA's next signing certificate and its next encryption certificate, and the client distinguishes them in the same way as for GetCACert. As in {{RFC8894}}, the GetNextCACert response is signed by the CA's current signing key, and the client MUST validate that signature before trusting either certificate.

## New GetCACaps Keywords

TODO: To be done in a future version. Define GetCACaps keywords ({{Section 3.5.2 of RFC8894}}) that let a CA advertise support for the mechanisms in this document, such as KEM-based request encryption, KEK-based response encryption, and specific KEM and signature algorithms. Register them in the "SCEP CA Capabilities" registry, and note that GetCACaps responses are not authenticated ({{Section 7.5 of RFC8894}}). This will have new stuff for IANA Considerations.

# Encrypting Requests with a KEM Algorithm

This document extends the CMS encryption envelope mechanisms KeyTransRecipientInfo and PasswordRecipientInfo supported in {{Section 3.1 of RFC8894}} to additionally support KEM algorithms via the the CMS KEMRecipientInfo mechanism {{RFC9629}}. This applies to every pkiMessage that the client sends to the CA, that is, PKCSReq, RenewalReq, CertPoll, GetCert, and GetCRL. The pkcsPKIEnvelope is otherwise unchanged from {{Section 3.2.2 of RFC8894}}. When the recipient encryption key is a KEM key, the EnvelopedData MUST contain exactly one RecipientInfo, which is a KEMRecipientInfo whose rid identifies the CA's encryption certificate. The KDF and key-encryption algorithms to use are specified by an algorithm's CMS specification. For example, how to use ML-KEM within CMS is specified in {{RFC9936}}.

# Encrypting Responses

{{Section 3.1 of RFC8894}} encrypts the CertRep to the public key of the certificate that signed the request if that key is encryption capable, and otherwise uses PasswordRecipientInfo keyed with the challengePassword.

The introduction of KEMRecipientInfo allows for a more efficient response encryption mechanism that no longer depends on the type of the client's key. Responses to a request encrypted with KEMRecipientInfo MUST be encrypted with KEKRecipientInfo ({{Section 6.2.3 of !RFC5652}}) where the key-encryption key (KEK) is derived from the content-encryption key (CEK) of the request. The KEK is the output of the KDF from the request's KEMRecipientInfo, with the request CEK as input keying material, and with info set to the ASCII string "SCEP-KEM-Response" followed by the transactionID. Its length is the key size of the key-encryption algorithm from the request's KEMRecipientInfo, which the CA also uses as the keyEncryptionAlgorithm. The kekid keyIdentifier MUST contain the transactionID. Because each CertPoll is a new request with a new CEK, the response to a CertPoll is encrypted under a key derived from that CertPoll's CEK.

A worked example of this key derivation is given in {{appdx-response-kek}}.

See {{response-recipient-authentication}} for discussion of how this modifies the response authentication model relative to {{RFC8894}}.

# Enrolment of KEM End-Entity Certificates

Note: This section describes an open problem rather than a proposed solution. This section to be entirely re-written after WG adoption. The authors invite feedback on which option, or combination of options, to adopt.

{{RFC8894}} is based on PKCS#10 Certificate Signing Requests (CSRs), which assumes that the client's key can sign, which does not hold when requesting certification of a KEM end entity key.

The design goal is to allow a client to enrol a KEM public key while giving the CA assurance that the client possesses the corresponding private key, with as little new protocol machinery as possible. For comparison, CMP offers a direct and an indirect method of proof-of-possession for KEM keys ({{Section 4.3.4 of ?RFC9810}}), but both rely on messages that SCEP lacks: a challenge-response exchange, and a certificate confirmation ({{Section 7.4 of RFC8894}}). All of the options below also require a way to convey a KEM public key in a request that cannot be self-signed.

The authors lean towards Option 3: Enrol a Signing Key First, but would like to present all options to the WG.

## Option 1: Direct Decryption Challenge

The CA responds to the request with a random challenge encrypted to the client's KEM key. The client decrypts it and returns it to the CA, which then issues the certificate.

Pros: The CA verifies possession before it issues the certificate. This mirrors the CMP direct method ({{Section 5.2.8.3.3 of RFC9810}}).

Cons: It adds a round trip and requires new message types and a GetCACaps keyword, unless the existing PENDING and CertPoll messages can be reused. The client must not act as a general decryption oracle ({{Section 8.2 of RFC9810}}).

## Option 2: Indirect Decryption via Encrypted Certificate

The CA issues the certificate and returns it in a CertRep encrypted to the client's KEM key, using the mechanism in {{encrypting-requests-with-a-kem-algorithm}} with the client's KEM key as the recipient. Only the holder of the private key can recover the certificate.

Pros: It needs no new messages, and it reuses the existing CertRep envelope. This mirrors the indirect method that CMP prefers ({{Section 5.2.8.3.2 of RFC9810}}).

Cons: SCEP has no certificate confirmation, so the CA never learns whether the client could decrypt the certificate. The assurance is also lost once the certificate is published, for example in Certificate Transparency logs or via GetCert ({{Section 8.11 of RFC9810}}).

## Option 3: Enrol a Signing Key First

The client first enrols a signature key. It then requests the KEM certificate in a RenewalReq signed with the issued signing certificate. This could be coupled with privateKeyPossessionStatement from {{?RFC9883}}.

Pros: It uses the existing RenewalReq flow without new message types. It suits deployments where KEM keys are always issued alongside signing keys.

Cons: It authenticates the client but proves nothing about the KEM private key, which is the same gap as {{Section 7.6 of RFC8894}}. It also requires two coupled transactions and a prior signing certificate, which increases CA state and is laborious in cases where the client only needs an encryption certificate.

# Error Handling

If the rid in a request's KEMRecipientInfo does not identify a current CA encryption certificate, for example because the client is using an encryption certificate that has been rolled over, the CA MUST respond with failInfo set to badRequest, and the client SHOULD obtain the CA's certificates again using GetCACert. If KEM decapsulation, key unwrapping, or content decryption fails, the CA MUST respond with failInfo set to badMessageCheck, and MUST NOT indicate, in failInfo, failInfoText, or otherwise, which of these steps failed.

The client MUST reject a response if the kekid keyIdentifier of its KEKRecipientInfo does not match the transactionID of the request, or if unwrapping the response CEK or decrypting the content fails.

# Operational Considerations

## Coexistence with Legacy SCEP Deployments

The mechanisms defined in this document are intended to be as un-obtrusive as possible for existing implementations, and are intended to be delpoyed in conjunction with an upgrade to post-quantum cryptography. To facilitate this migration, it is RECOMMENDED that a PQC-capable SCEP CA be operated side by side with any legacy SCEP CA, for example at a distinct host or SCEPPATH ({{Section 4.1 of RFC8894}}), rather than replacing it. Legacy clients continue to use the legacy CA until they are upgraded or retired.

# Security Considerations

## Key Material Handling

The ephemeral symmetric keys generated for a SCEP transactions (the wrapping key, the response key and the two CEKs) MUST never be used more than once, stored or logged, and implementers should make effort to scrub them from memory as soon as they've been used.

## KEM Algorithm Requirements

The CA's encryption key is long-lived and is used to decapsulate many requests, including requests constructed by attackers. A KEM used with this document MUST therefore be secure against adaptive chosen-ciphertext attacks (IND-CCA2). ML-KEM meets this requirement. Each request uses a fresh KEM encapsulation, as required by {{RFC9629}}.

## Response Key Derivation

The response key-encryption key is derived from the request CEK, so it is no stronger than that CEK. A client SHOULD use a content-encryption algorithm for the request whose key is at least as long as the key of the key-encryption algorithm in its KEMRecipientInfo, for example AES-256-CBC when using AES-256 key wrap. The request CEK is used both to encrypt the request content and as input keying material to the KDF. The KDF and its info string, which contains a fixed label and the transactionID, separate the derived key from the CEK and from keys derived in other transactions.

## Binding of the Response to the Request

In {{RFC8894}}, the response is encrypted to the key in the certificate that signed the request, so only the holder of that key can read the response. {{Section 7.9 of RFC8894}} relies on this property when it argues that the use of SHA-1 is safe. Under this document, the response can be read by whoever constructed the request and therefore knows its CEK, which includes an attacker who forges a request. The issued certificate is not secret, so this does not affect confidentiality. However, the authorisation of a request rests entirely on the request's own authentication (the challengePassword or the signature on a RenewalReq), and the argument in {{Section 7.9 of RFC8894}} does not apply. Clients and CAs implementing this document MUST NOT use SHA-1 to sign or verify SCEP messages.

## Post-Quantum Security

An attacker who records SCEP traffic now could decrypt it later with a cryptographically relevant quantum computer, exposing the challengePassword and the request contents. Deployments requiring post-quantum confidentiality SHOULD encrypt requests using KEMRecipientInfo with a post-quantum KEM, and SHOULD NOT use KeyTransRecipientInfo with RSA. Where such deployments instead rely on PasswordRecipientInfo, the challengePassword SHOULD have at least 128 bits of entropy, since the protection is then only as strong as the challengePassword ({{Section 7.3 of RFC8894}}). Classical signatures are at risk only from an attacker who has a quantum computer at the time of the exchange. Deployments requiring post-quantum authentication SHOULD use post-quantum signature algorithms for both the CA's signing certificate and the client's signing key.

## Response Recipient Authentication

In {{RFC8894}}, a response encrypted under KeyTransRecipientInfo is implicitly authenticated to the key requesting enrolment since the private key is required to read the response.

 The KEKRecipientInfo response encryption mechanism defined in this document implicitly authenticates the response recipient to be the same client that sent the request, but does not require the subject's private key for decryption. Even in the case where the subject key being enrolled is a KEM key, such a mechanism is still not provided. This is considered to be a sufficiently similar protocol authentication model as to be acceptable.

## Decryption Oracles

The CA decapsulates and decrypts content chosen by unauthenticated clients. It MUST NOT reveal which decryption step failed (see {{error-handling}}), so that it cannot be used as a decryption oracle. A client MUST NOT return decrypted content to the CA or to any other party, except as specified for proof-of-possession in {{enrolment-of-kem-end-entity-certificates}}.


# IANA Considerations

This document has no IANA actions.

--- back

# Worked Example: Response Key Derivation {#appdx-response-kek}

This appendix shows a worked example of the derivation of the response key-encryption key described in {{encrypting-responses}}, and the resulting KEKRecipientInfo. The request is assumed to have used ML-KEM-768, for which {{RFC9936}} specifies HKDF-SHA256 as the KDF and AES-256 key wrap as the key-encryption algorithm. Both the request and the response use AES-256-CBC for content encryption. All values are hexadecimal unless otherwise noted.

~~~
{::include ./src/responseKekExample.md}
~~~

# Open Design Questions {#appdx-open-questions}

This appendix lists design questions on which the authors seek working group input.

## Downgrade Protection

GetCACaps responses are not authenticated ({{Section 7.5 of RFC8894}}), and an active attacker could also remove the CA's encryption certificate from a GetCACert response. Either change could push a client back to a classical mechanism such as RSA key transport. However, harvest-now-decrypt-later attacks are passive, and an attacker who can interfere with the exchange in real time gains little from such a downgrade. Explicit downgrade protection, for example requiring a client configured for PQC to refuse classical mechanisms, may therefore not be required. Should this document require it?

## Algorithm Profile and Mandatory-to-Implement Algorithms

{{RFC8894}} makes AES128-CBC and SHA-256 mandatory to implement ({{Section 2.9 of RFC8894}}). This document currently names no PQC algorithms, and instead relies on each algorithm's CMS specification, such as {{RFC9936}} for ML-KEM. Is it required to define an algorithm profile, for example mandatory-to-implement KEM and signature algorithms, AES-256 content encryption, or authenticated encryption using AuthEnvelopedData? Or is the document more future-proof without one?

## Message Size and HTTP Transport

PQC public keys, signatures, and KEM ciphertexts are considerably larger than their classical counterparts. As a result, SCEP messages sent via HTTP GET with base64-encoded data in the URI ({{Section 4.1 of RFC8894}}) are more likely to exceed URI length limits. Should this document require HTTP POST, as indicated by the "POSTPKIOperation" capability, for any message that uses the mechanisms in this document?

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
