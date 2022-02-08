---
title: SPAKE2+, an Augmented PAKE
abbrev: spake2plus
docname: draft-bar-cfrg-spake2plus-latest
date: {DATE}
category: info

ipr: trust200902
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs, docmapping]

author:
 -
    ins: T. Taubert
    name: Tim Taubert
    org: Apple Inc.
    street: One Apple Park Way
    city: Cupertino, California 95014
    country: United States of America
    email: ttaubert@apple.com
 -
    ins: C. A. Wood
    name: Christopher A. Wood
    email: caw@heapingbits.net

normative:
  TDH:
    title: "The Twin-Diffie Hellman Problem and Applications"
    seriesinfo: EUROCRYPT 2008, Volume 4965 of Lecture notes in Computer Science, pages 127-145, Springer-Verlag, Berlin, Germany
    date: 2008
    authors:
      - ins: D. Cash
      - ins: E. Kiltz
      - ins: V. Shoup
  SPAKE2P-Analysis:
    title: "Security analysis of SPAKE2+"
    target: https://eprint.iacr.org/2020/313.pdf
    date: 2020
    authors:
      - ins: V. Shoup
  SEC1:
    title: "Elliptic Curve Cryptography, Standards for Efficient Cryptography Group, ver. 2"
    target: https://secg.org/sec1-v2.pdf
    date: 2009

--- abstract

This document describes SPAKE2+, a Password Authenticated Key Exchange (PAKE) protocol
run between two parties for deriving a strong shared key with no risk of disclosing the password.
SPAKE2+ is an augmented PAKE protocol, as only one party has knowledge of the password.
This method is simple to implement, compatible with any prime order group and is computationally efficient.

--- middle

# Introduction {#introduction}

This document describes SPAKE2+, a Password Authenticated Key Exchange (PAKE) protocol
run between two parties for deriving a strong shared key with no risk of disclosing the password.
SPAKE2+ is an augmented PAKE protocol, as only one party makes direct use of the password during the execution of the protocol.
The other party only needs a record corresponding to the other party's registration at the time of the protocol execution instead of the password.
This record can be computed once, during an offline registration phase.
The party using the password directly would typically be a client, and acts as a prover,
while the other party would be a server, and acts as verifier.

The protocol is augmented in the sense that it provides some resilience to the compromise or extraction of the registration record.
The design of the protocol forces the adversary to recover the password from the record to successfully execute the protocol.
Hence this protocol can be advantageously combined with a salted Password Hashing Function to increase the cost of the recovery and slow down attacks.
The record cannot be used directly to successfully run the protocol as a prover,
making this protocol more robust than balanced PAKEs which don't benefit from Password Hashing Functions to the same extent.

This augmented property is especially valuable in scenarios where the execution of the protocol is constrained
and the adversary cannot not query the salt of the password hash function ahead of the attack.
Constraints may consist in being in physical proximity through a local network or
when initiation of the protocol requires a first authentication factor.

This password-based key exchange protocol appears in {{TDH}} and is proven secure in {{SPAKE2P-Analysis}}.
It is compatible with any prime-order group and relies only on group operations, making it simple and computationally efficient.
Predetermined parameters for a selection of commonly used groups are also provided.

This document has content split out from a related document specifying SPAKE2 {{!I-D.irtf-cfrg-spake2}}.

# Requirements Notation

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in {{!RFC2119}}.

# Definition of SPAKE2+

Let G be a group in which the computational Diffie-Hellman (CDH)
problem is hard. Suppose G has order p\*h where p is a large prime;
h will be called the cofactor. Let I be the unit element in
G, e.g., the point at infinity if G is an elliptic curve group. We denote the
operations in the group additively. We assume there is a representation of
elements of G as byte strings: common choices would be SEC1
uncompressed or compressed {{SEC1}} for elliptic curve groups or big
endian integers of a fixed (per-group) length for prime field DH.
We fix two random elements M and N in the prime-order subgroup of G as defined
in the table in this document for common groups, as well as a generator P
of the (large) prime-order subgroup of G. The algorithm for selecting
M and N is defined in {{pointgen}}. Importantly, this algorithm chooses M
and N such that their discrete log is not known. P is specified in the
document defining the group, and so we do not repeat it here.

|| denotes concatenation of strings. We also let len(S) denote the
length of a string in bytes, represented as an eight-byte little
endian number. Finally, let nil represent an empty string, i.e.,
len(nil) = 0.

KDF is a key-derivation function that takes as input a salt, intermediate
keying material (IKM), info string, and derived key length L to derive a
cryptographic key of length L.
MAC is a Message Authentication Code algorithm that takes a secret key and
message as input to produce an output.
Let Hash be a hash function from arbitrary strings to bit strings of a fixed length. Common choices
for Hash are SHA256 or SHA512 {{!RFC6234}}.
{{Ciphersuites}} specifies variants of KDF, MAC, and Hash
suitable for use with the protocols contained herein.

Let there be two parties, a prover and a verifier. Their identities, denoted as
idProver and idVerifier, may also have digital representations such as Media Access Control addresses
or other names (hostnames, usernames, etc). The parties may share additional data
(the context) separate from their identities which they may want to include in
the protocol transcript.
One example of additional data is a list of supported protocol versions if SPAKE2+ were
used in a higher-level protocol which negotiates the use of a particular PAKE. Another
example is the inclusion of the application name. Including those would ensure that
both parties agree upon the same set of supported protocols and therefore prevent downgrade and
cross-protocol attacks. Specification of precise context values is out of scope for this document.

## Protocol Overview

SPAKE2+ is a two round protocol that establishes a shared secret with an
additional round for key confirmation. Prior to invocation, both parties are
provisioned with information such as the input password needed to run the
protocol. The registration phase may include communicating identities, protocol
version and other parameters related to the registration record; see
{{offline-registration}} for details.

During the first round, the prover sends a public share shareP to the verifier, which in turn
responds with its own public share shareV. Both parties then derive a shared secret
used to produce encryption and authentication keys. The latter are used during the second
round for key confirmation. ({{keys}} details the key derivation and confirmation steps.)
In particular, the verifier sends a key confirmation message confirmV to the prover,
which in turn responds with its own key confirmation message confirmP.
(Note that shareV and confirmV MAY be sent in the same message.)
Both parties MUST NOT consider the protocol complete prior to receipt and
validation of these key confirmation messages.

A sample trace is shown below.

~~~
                 Prover                     Verifier

                   |        (registration)     |
                   |<- - - - - - - - - - - - ->|
                   |                           |
                   |       (setup protocol)    |
(compute shareP)   |            shareP         |
                   |-------------------------->|
                   |            shareV         | (compute shareV)
                   |<--------------------------|
                   |                           |
                   |       (derive secrets)    | (compute confirmV)
                   |           confirmV        |
                   |<--------------------------|
(compute confirmP) |           confirmP        |
                   |-------------------------->|

~~~

## Offline Registration

The registration phase computes the values w0 and w1, as well as the registration
record L=w1\*P. w0 and w1 are derived by hashing the password pw with the identities
of the two participants. w0 and the record L are then shared with the verifier and
stored as part of the registration record associated with the prover. The prover
SHOULD derive w0 and w1 from the password before the protocol begins. Both w0 and
w1 are derived using a function with range [0, p-1], which is modeled as a random
oracle in {{SPAKE2P-Analysis}}.

Protocols using this specification MUST define the method used to compute w0 and w1.
For example, it may be necessary to carry out various forms of normalization of the
password before hashing {{!RFC8265}}. This section contains requirements and default
recommendations for computing w0 and w1.

The RECOMMENDED method for generating w0 and w1 is via a Password-Based Key
Derivation Function (PBKDF), which is a function designed to slow down brute-force
attackers. Brute-force resistance may be obtained through various computation hardness
parameters such as memory or CPU cycles, and are typically configurable.
Scrypt {{?RFC7914}} and Argon2id {{?RFC9106}} are common examples of PBKDFs.
Absent an application-specific profile, RECOMMENDED parameters (N, r, p)
for Scrypt are (32768,8,1), and RECOMMENDED parameters for Argon2id
are in Section 4 of {{?RFC9106}}.

Each half of the output of the PBKDF will be interpreted as an integer and reduced
modulo p. To control bias, each half must be of length at least ceil(log2(p)) + k
bits, with k >= 64. Reducing such integers mod p gives bias at most 2^-k for any
p; this bias is negligible for any k >= 64.

The minimum total output length of the PBKDF then is 2 * (ceil(log2(p)) + k) bits.
For example, given the prime order of the P-256 curve, the output of the PBKDF
SHOULD be at least 640 bits or 80 bytes.

Given a PBKDF, password pw, and identities idProver and idVerifier, the RECOMMENDED
method for computing w0 and w1 is as follows:

~~~
w0s || w1s = PBKDF(len(pw) || pw ||
                   len(idProver) || idProver ||
                   len(idVerifier) || idVerifier)
w0 = w0s mod p
w1 = w1s mod p
~~~

If an identity is unknown at the time of computing w0s or w1s, its length is given
as zero and the identity itself is represented as the empty octet string. If both
idProver and idVerifier are unknown, then their lengths are given as zero and both
identities will be represented as empty octet strings. idProver and idVerifier are
included in the transcript TT as part of the protocol flow.

## Online Authentication

The online SPAKE2+ protocol runs between the prover and verifier to produce a
single shared secret upon completion. To begin, the prover selects x uniformly
at random from the integers in [0, p-1], computes the public share shareP=X,
and transmits it to the verifier.

~~~
x <- [0, p-1]
X = x*P + w0*M
~~~

Upon receipt of X, the verifier computes h\*X and aborts if the result is equal
to I to ensure that X is in the large prime-order subgroup of G. The verifier then
selects y uniformly at random from the integers in [0, p), computes the public
share shareV=Y and transmits it to the prover. Upon receipt of Y, the prover
computes h\*Y and aborts if the result is equal to I.

~~~
y <- [0, p-1]
Y = y*P + w0*N
~~~

Both participants compute Z and V that are now shared as common values.
The prover computes:

~~~
Z = h*x*(Y - w0*N)
V = h*w1*(Y - w0*N)
~~~

The verifier computes:

~~~
Z = h*y*(X - w0*M)
V = h*y*L
~~~

All proofs of security hold even if the discrete log of the fixed group element
N is known to the adversary. In particular, one MAY set N=I, i.e. set N to the
unit element in G.

It is essential that both Z and V be used in combination with the transcript to
derive the keying material. The protocol transcript encoding is shown below.

~~~
TT = len(Context) || Context
  || len(idProver) || idProver
  || len(idVerifier) || idVerifier
  || len(M) || M
  || len(N) || N
  || len(shareP) || shareP
  || len(shareV) || shareV
  || len(Z) || Z
  || len(V) || V
  || len(w0) || w0
~~~

Context is an application-specific customization string shared between both
parties and MUST precede the remaining transcript. It might contain the
name and version number of the higher-level protocol, or simply the name and version
number of the application. The context MAY include additional data such as the
chosen ciphersuite and PBKDF parameters like the iteration count or salt.
The context and its length prefix MAY be omitted.

If an identity is absent, its length is given as zero and the identity itself
is represented as the empty octet string. If both identities are absent, then
their lengths are given as zero and both are represented as empty octet strings.
In applications where identities are not implicit, idProver and idVerifier SHOULD always be
non-empty. Otherwise, the protocol risks Unknown Key Share attacks (discussion
of Unknown Key Share attacks in a specific protocol is given in {{?I-D.ietf-mmusic-sdp-uks}}).

Upon completion of this protocol, both parties compute shared secrets K_auth,
K_enc, K_confirmP, and K_confirmV as specified in {{keys}}. The verifier MUST send a key
confirmation message confirmV to the prover so both parties can confirm that they
agree upon these shared secrets. After receipt and verification of the verifier's
confirmation message, the prover MUST respond with its confirmation message.
The verifier MUST NOT send application data to the prover until it has received
and verified the confirmation message. Key confirmation verification requires
recomputation of confirmP or confirmV and checking for equality against that which was
received.

## Key Schedule and Key Confirmation {#keys}

The protocol transcript TT, as defined in {{online-authentication}}, is unique and secret to
the participants. Both parties use TT to derive shared symmetric secrets K_auth
and K_enc and output K_enc as the shared secret from the protocol. The length of
each key is equal to half of the digest output, e.g., |K_auth| = |K_enc| = 128
bits for Hash() = SHA-256.

~~~
K_auth || K_enc = Hash(TT)
K_confirmP || K_confirmV = KDF(nil, K_auth, "ConfirmationKeys")
~~~

K_auth is used to derive K_confirmP and K_confirmV. The length of each confirmation key
is equal to half of the digest output, e.g., |K_confirmP| = |K_confirmV| = 128 bits for
Hash() = SHA-256. Neither K_auth nor its derived confirmation keys are used for
anything except key confirmation and MUST be discarded after the protocol execution.

Both endpoints MUST employ a MAC that produces pseudorandom tags for key confirmation.
K_confirmP and K_confirmV are symmetric keys used to compute tags confirmP and
confirmV over the public key shares received from the other peer earlier.

~~~
confirmP = MAC(K_confirmP, shareV)
confirmV = MAC(K_confirmV, shareP)
~~~

Once key confirmation is complete, applications MAY use K_enc as an authenticated
shared secret as needed. For example, applications MAY derive one or more AEAD
keys and nonces from K_enc for subsequent application data encryption.

# Ciphersuites {#Ciphersuites}

This section documents SPAKE2+ ciphersuite configurations. A ciphersuite
indicates a group, cryptographic hash algorithm, and pair of KDF and MAC functions, e.g.,
P256-SHA256-HKDF-HMAC-SHA256. This ciphersuite indicates a SPAKE2+ protocol instance over
P-256 that uses SHA256 along with HKDF {{!RFC5869}} and HMAC {{!RFC2104}}
for G, Hash, KDF, and MAC functions, respectively. Since the choice of PBKDF
and its parameters for computing w0 and w1 and distributing does not affect
interoperability, the PBKDF is not included as part of the ciphersuite.

If no MAC algorithm is used in the key confirmation phase, its respective column
in the table below can be ignored and the ciphersuite name will contain no MAC
identifier.

| G              | Hash   | KDF    | MAC    |
|:---------------|:------:|:------:|:------:|
| P-256 | SHA256 {{!RFC6234}} | HKDF-SHA256 {{!RFC5869}} | HMAC-SHA256 {{!RFC2104}} |
| P-256 | SHA512 {{!RFC6234}} | HKDF-SHA512 {{!RFC5869}} | HMAC-SHA512 {{!RFC2104}} |
| P-384 | SHA256 {{!RFC6234}} | HKDF-SHA256 {{!RFC5869}} | HMAC-SHA256 {{!RFC2104}} |
| P-384 | SHA512 {{!RFC6234}} | HKDF-SHA512 {{!RFC5869}} | HMAC-SHA512 {{!RFC2104}} |
| P-521 | SHA512 {{!RFC6234}} | HKDF-SHA512 {{!RFC5869}} | HMAC-SHA512 {{!RFC2104}} |
| edwards25519 | SHA256 {{!RFC6234}} | HKDF-SHA256 {{!RFC5869}} | HMAC-SHA256 {{!RFC2104}} |
| edwards448 | SHA512 {{!RFC6234}} | HKDF-SHA512 {{!RFC5869}} | HMAC-SHA512 {{!RFC2104}} |
| P-256 | SHA256 {{!RFC6234}} | HKDF-SHA256 {{!RFC5869}} | CMAC-AES-128 {{!RFC4493}} |
| P-256 | SHA512 {{!RFC6234}} | HKDF-SHA512 {{!RFC5869}} | CMAC-AES-128 {{!RFC4493}} |

The following points represent permissible point generation seeds
for the groups listed in the Table above,
using the algorithm presented in {{pointgen}}.
These bytestrings are compressed points as in {{SEC1}}
for curves from {{SEC1}} and {{!RFC8032}}.

For P256:

~~~
M =
02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f
seed: 1.2.840.10045.3.1.7 point generation seed (M)

N =
03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49
seed: 1.2.840.10045.3.1.7 point generation seed (N)
~~~

For P384:

~~~
M =
030ff0895ae5ebf6187080a82d82b42e2765e3b2f8749c7e05eba366434b363d3dc
36f15314739074d2eb8613fceec2853
seed: 1.3.132.0.34 point generation seed (M)

N =
02c72cf2e390853a1c1c4ad816a62fd15824f56078918f43f922ca21518f9c543bb
252c5490214cf9aa3f0baab4b665c10
seed: 1.3.132.0.34 point generation seed (N)
~~~

For P521:

~~~
M =
02003f06f38131b2ba2600791e82488e8d20ab889af753a41806c5db18d37d85608
cfae06b82e4a72cd744c719193562a653ea1f119eef9356907edc9b56979962d7aa
seed: 1.3.132.0.35 point generation seed (M)

N =
0200c7924b9ec017f3094562894336a53c50167ba8c5963876880542bc669e494b25
32d76c5b53dfb349fdf69154b9e0048c58a42e8ed04cef052a3bc349d95575cd25
seed: 1.3.132.0.35 point generation seed (N)
~~~

For edwards25519:

~~~
M =
d048032c6ea0b6d697ddc2e86bda85a33adac920f1bf18e1b0c6d166a5cecdaf
seed: edwards25519 point generation seed (M)

N =
d3bfb518f44f3430f29d0c92af503865a1ed3281dc69b35dd868ba85f886c4ab
seed: edwards25519 point generation seed (N)
~~~

For edwards448:

~~~
M =
b6221038a775ecd007a4e4dde39fd76ae91d3cf0cc92be8f0c2fa6d6b66f9a12
942f5a92646109152292464f3e63d354701c7848d9fc3b8880
seed: edwards448 point generation seed (M)

N =
6034c65b66e4cd7a49b0edec3e3c9ccc4588afd8cf324e29f0a84a072531c4db
f97ff9af195ed714a689251f08f8e06e2d1f24a0ffc0146600
seed: edwards448 point generation seed (N)
~~~

# IANA Considerations

No IANA action is required.

# Security Considerations

SPAKE2+ appears in {{TDH}} and is proven secure in {{SPAKE2P-Analysis}}.

Beyond the cofactor multiplication checks to ensure that elements received from
a peer are in the prime order subgroup of G, they also MUST be checked for group
membership as failure to properly validate group elements can lead to attacks.

The ephemeral randomness used by the prover and verifier MUST be
generated using a cryptographically secure PRNG.

# Acknowledgements

Thanks to Ben Kaduk and Watson Ladd, from which this specification originally emanated.

--- back

# Algorithm used for Point Generation {#pointgen}

This section describes the algorithm that was used to generate
the points M and N in the table in {{Ciphersuites}}. This algorithm
produces M and N such that they are indistinguishable from two random
elements in the prime-order subgroup of G. See {{SPAKE2P-Analysis}}
for additional details on this requirement.

For each curve in the table below, we construct a string
using the curve OID from {{!RFC5480}} (as an ASCII
string) or its name,
combined with the needed constant, for instance "1.3.132.0.35
point generation seed (M)" for P-512.  This string is turned
into a series of blocks by hashing with SHA256, and hashing that
output again to generate the next 32 bytes, and so on.  This
pattern is repeated for each group and value, with the string
modified appropriately.

A byte string of length equal to that of an encoded group
element is constructed by concatenating as many blocks as are
required, starting from the first block, and truncating to the
desired length.  The byte string is then formatted as required
for the group.  In the case of Weierstrass curves, we take the
desired length as the length for representing a compressed point
(section 2.3.4 of {{SEC1}}),
and use the low-order bit of the first byte as the sign bit.
In order to obtain the correct format, the value of the first
byte is set to 0x02 or 0x03 (clearing the first six bits
and setting the seventh bit), leaving the sign bit as it was
in the byte string constructed by concatenating hash blocks.
For the {{!RFC8032}} curves a different procedure is used.
For edwards448 the 57-byte input has the least-significant 7 bits of the
last byte set to zero, and for edwards25519 the 32-byte input is
not modified.  For both the {{!RFC8032}} curves the
(modified) input is then interpreted
as the representation of the group element.
If this interpretation yields a valid group element with the
correct order (p), the (modified) byte string is the output.  Otherwise,
the initial hash block is discarded and a new byte string constructed
from the remaining hash blocks. The procedure of constructing a
byte string of the appropriate length, formatting it as
required for the curve, and checking if it is a valid point of the correct
order, is repeated
until a valid element is found.

The following python snippet generates the above points,
assuming an elliptic curve implementation following the
interface of Edwards25519Point.stdbase() and
Edwards448Point.stdbase() in Appendix A of {{RFC8032}}:

~~~
def iterated_hash(seed, n):
    h = seed
    for i in range(n):
        h = hashlib.sha256(h).digest()
    return h

def bighash(seed, start, sz):
    n = -(-sz // 32)
    hashes = [iterated_hash(seed, i) for i in range(start, start + n)]
    return b''.join(hashes)[:sz]

def canon_pointstr(ecname, s):
    if ecname == 'edwards25519':
        return s
    elif ecname == 'edwards448':
        return s[:-1] + bytes([s[-1] & 0x80])
    else:
        return bytes([(s[0] & 1) | 2]) + s[1:]

def gen_point(seed, ecname, ec):
    for i in range(1, 1000):
        hval = bighash(seed, i, len(ec.encode()))
        pointstr = canon_pointstr(ecname, hval)
        try:
            p = ec.decode(pointstr)
            if p != ec.zero_elem() and p * p.l() == ec.zero_elem():
                return pointstr, i
        except Exception:
            pass
~~~

# Test Vectors {#testvectors}

This section contains test vectors for SPAKE2+ using
the P256-SHA256-HKDF-HMAC-SHA256 and P256-SHA256-HKDF-CMAC-AES-128 ciphersuites.
(Choice of PBKDF is omitted and values for w and w0,w1 are provided directly.)
All points are encoded using the uncompressed format, i.e., with a 0x04 octet
prefix, specified in {{SEC1}} A and B identity strings
are provided in the protocol invocation.

~~~
[Context=b'SPAKE2+-P256-SHA256-HKDF Test Vectors']
[idProver=b'client']
[idVerifier=b'server']
w0 = 0xee282ccbc95ca96d8f9d214f9f274573e1f1355019986587174f4bd2712e4
2fd
w1 = 0xbf7e543dbc6b6f1a98affd1ef1aba25ce136a15a28c02b9ba7dfd2da56c00
73f
L = 0x0429ae2016fc29eb5fddbaae8bf60e2c2757a7db333017b842e5da4197ce8e
96d67e7ae1bc1a187bf5bbd237f236ec731bb95d4aba0eb39d74737b052bd53c83c4
x = 0x603a0a45478cde0501d809dde8f40f966e68afdf9531c2d93f5e61095b385e
2d
shareP = 0x04450765458e9d5f5ab77550a1a743bfa9db21edfb53296b50555acf9
babf05a69dcdc677f25718056ad3fe41639e768d2c49978bd96820828dae14eeabfe
509ae
y = 0xf09781e7f1f82c38018ab3da6bfa951a20626cfc1231e8c612446fffed31d3
44
shareV = 0x0494c47a11ca001e94300afc7279e343de4aef35c1dd834d4dc2fda9a
7dd57e78bf446ca2a0b9e26d23b88d0f40cce1bacbd111f94e170ae90fa9a97d9b86
67e3f
Z = 0x04b204a945c477506874a67480a5bf668f2935f3f61d78967cd584e2231a7f
a64dee8b90b31bb996d27e85561c8d6580e75f97b031ef16c5e1a34108552ade8843
V = 0x0455dfa63a958cbc5c1a758ad0f35d3f584caa438cf4a642b8a7673451640e
e45d9aa8214b44bb0ab8b6e6797070597e5a05d780a090dc6866aef8579dc0fae196
TT = 0x25000000000000005350414b45322b2d503235362d5348413235362d484b4
446205465737420566563746f72730600000000000000636c69656e7406000000000
00000736572766572410000000000000004886e2f97ace46e55ba9dd7242579f2993
b64e16ef3dcab95afd497333d8fa12f5ff355163e43ce224e0b0e65ff02ac8e5c7be
09419c785e0ca547d55a12e2d20410000000000000004d8bbd6c639c62937b04d997
f38c3770719c629d7014d49a24b4f98baa1292b4907d60aa6bfade45008a636337f5
168c64d9bd36034808cd564490b1e656edbe7410000000000000004450765458e9d5
f5ab77550a1a743bfa9db21edfb53296b50555acf9babf05a69dcdc677f25718056a
d3fe41639e768d2c49978bd96820828dae14eeabfe509ae41000000000000000494c
47a11ca001e94300afc7279e343de4aef35c1dd834d4dc2fda9a7dd57e78bf446ca2
a0b9e26d23b88d0f40cce1bacbd111f94e170ae90fa9a97d9b8667e3f41000000000
0000004b204a945c477506874a67480a5bf668f2935f3f61d78967cd584e2231a7fa
64dee8b90b31bb996d27e85561c8d6580e75f97b031ef16c5e1a34108552ade88434
1000000000000000455dfa63a958cbc5c1a758ad0f35d3f584caa438cf4a642b8a76
73451640ee45d9aa8214b44bb0ab8b6e6797070597e5a05d780a090dc6866aef8579
dc0fae1962000000000000000ee282ccbc95ca96d8f9d214f9f274573e1f13550199
86587174f4bd2712e42fd
K_auth = 0x7cded1372ce79b698a605a142e6f7ef6
K_enc = 0x8d5b065306549d66faaa57bbc4a14146
K_confirmP = 0x1e9f25ae66c422f51f418845c8e83fd7
K_confirmV = 0xc98363ead807fc1aa762a94aed152791
HMAC(K_confirmP, shareV) = 0xe6dd4e15aa4e81150edc2adade9bcf456193f36
013e85d8b5096991094322c29
HMAC(K_confirmV, shareP) = 0xa40c906dc49b82d8185ccdaeafe76ca5617b75e
feec54ba18316775c44b9e50d
CMAC(K_confirmP, shareV) = 0x54a1b49f2eb5b82be776916ed9e04802
CMAC(K_confirmV, shareP) = 0x7d73df13532ee4ec6aae03c63affecfb

[Context=b'SPAKE2+-P256-SHA256-HKDF Test Vectors']
[idProver=b'client']
[idVerifier=b'']
w0 = 0xee282ccbc95ca96d8f9d214f9f274573e1f1355019986587174f4bd2712e4
2fd
w1 = 0xbf7e543dbc6b6f1a98affd1ef1aba25ce136a15a28c02b9ba7dfd2da56c00
73f
L = 0x0429ae2016fc29eb5fddbaae8bf60e2c2757a7db333017b842e5da4197ce8e
96d67e7ae1bc1a187bf5bbd237f236ec731bb95d4aba0eb39d74737b052bd53c83c4
x = 0x0919b86ec50f390b6cb10a0b54a1899178304b63f385a11fb937d3d6134c73
eb
shareP = 0x041e75765ff1917645f50e168566f80eb4fa50bef6dc34b7dab94d672
da60c9590940bad69ddaf90d5b97c9d8f8bb8c9cde3edd5e67ce666f4746ea152143
a3ea0
y = 0xa1039fcd300fe62e7e84f1c7fdafa5f9ffd6897554f7f87c43195be4af9317
1f
shareV = 0x046cf73b054e62122c68d742bfb46b4fa4dfbd3e027b2e2b780d347d0
8d02ab343f1da7fdec1c87a68b570b50a1879a3e6e235a47833e3307e7eef058f50f
9d562
Z = 0x044c546f8c708a2c6f6a6dc9486b1099f27faa3ba808711c76818fc3f80d23
69072f9ffec1ad70e34c1c9f1658f3d997eda5169b640fef83cb3a7fff78bf6f9582
V = 0x04fada2637f1666bf973b4bb91f5d2e2e1c8559f0f95597c30645f104c390c
f99f4bc82242076d8db56d1a817b891c15e6dbe24224ea215cbb8694e6f9ecbf4d05
TT = 0x25000000000000005350414b45322b2d503235362d5348413235362d484b4
446205465737420566563746f72730600000000000000636c69656e7400000000000
00000410000000000000004886e2f97ace46e55ba9dd7242579f2993b64e16ef3dca
b95afd497333d8fa12f5ff355163e43ce224e0b0e65ff02ac8e5c7be09419c785e0c
a547d55a12e2d20410000000000000004d8bbd6c639c62937b04d997f38c3770719c
629d7014d49a24b4f98baa1292b4907d60aa6bfade45008a636337f5168c64d9bd36
034808cd564490b1e656edbe74100000000000000041e75765ff1917645f50e16856
6f80eb4fa50bef6dc34b7dab94d672da60c9590940bad69ddaf90d5b97c9d8f8bb8c
9cde3edd5e67ce666f4746ea152143a3ea04100000000000000046cf73b054e62122
c68d742bfb46b4fa4dfbd3e027b2e2b780d347d08d02ab343f1da7fdec1c87a68b57
0b50a1879a3e6e235a47833e3307e7eef058f50f9d5624100000000000000044c546
f8c708a2c6f6a6dc9486b1099f27faa3ba808711c76818fc3f80d2369072f9ffec1a
d70e34c1c9f1658f3d997eda5169b640fef83cb3a7fff78bf6f95824100000000000
00004fada2637f1666bf973b4bb91f5d2e2e1c8559f0f95597c30645f104c390cf99
f4bc82242076d8db56d1a817b891c15e6dbe24224ea215cbb8694e6f9ecbf4d05200
0000000000000ee282ccbc95ca96d8f9d214f9f274573e1f1355019986587174f4bd
2712e42fd
K_auth = 0x6b671373e6a61e6bed288301151b583c
K_enc = 0xa8ab09d0ed016e18e95083eeef1dc2f2
K_confirmP = 0xdc110c3f100a5493f4fdd857f332ef9a
K_confirmV = 0x7ded03cc3f0c12cb2cb9f6eea1f3f0a9
HMAC(K_confirmP, shareV) = 0x6fc0d9ca039041c6cbe0db4474da33719ddd892
b0b0ef143ef1fa093a9ac8f86
HMAC(K_confirmV, shareP) = 0xaee74e5c3fde49981982bd1d6795f87f3f3f4ad
13addd9ff59a94833e8fe0d96
CMAC(K_confirmP, shareV) = 0x53b2c0ded78c4152e2eaa3cb5937bffa
CMAC(K_confirmV, shareP) = 0xc68fc370af19f8806a8218f7565116d5

[Context=b'SPAKE2+-P256-SHA256-HKDF Test Vectors']
[idProver=b'']
[idVerifier=b'server']
w0 = 0xee282ccbc95ca96d8f9d214f9f274573e1f1355019986587174f4bd2712e4
2fd
w1 = 0xbf7e543dbc6b6f1a98affd1ef1aba25ce136a15a28c02b9ba7dfd2da56c00
73f
L = 0x0429ae2016fc29eb5fddbaae8bf60e2c2757a7db333017b842e5da4197ce8e
96d67e7ae1bc1a187bf5bbd237f236ec731bb95d4aba0eb39d74737b052bd53c83c4
x = 0x0ed4880b1e9c96ce9c117c6e8e25f7635a7914c823fc2087934e6aff094fd6
ee
shareP = 0x046923ee8c68ee1c59802eded233d59e588bdde6515f2b6f98532b9fe
42e0eaa5792c1204d10d3a5e60079e7b9ee2438a16ae71c154dbfb54f7fde22e9e69
7a606
y = 0x78b113d43fac6a5252256473d81941c3178def660f435e27bdbf816277c611
06
shareV = 0x0401460b43338b84606d2f78b29bbce6ff6fcf900be89cab912951262
44d9727aa232fb48fe6aa33ef6772ae373d0982479118476b18ac12a4a42973321e3
6e547
Z = 0x04197bee4e39e6ac8fee18f418cae7cc5addc1f10318c0d8d8601202aff0b3
f3f7ff8a70fc66a57f98f68c0f606fd800cfd5bc73fef6a3d0bf3f9e79e53c23b093
V = 0x042e2b0b6d65d98a64aa3b23ef29ca7497e1b443dbd39fab7d54284551bc55
f0d7e2782611cc42a60a509566a7decff5e16f4502b9272abed7e2bd17d152cebce1
TT = 0x25000000000000005350414b45322b2d503235362d5348413235362d484b4
446205465737420566563746f7273000000000000000006000000000000007365727
66572410000000000000004886e2f97ace46e55ba9dd7242579f2993b64e16ef3dca
b95afd497333d8fa12f5ff355163e43ce224e0b0e65ff02ac8e5c7be09419c785e0c
a547d55a12e2d20410000000000000004d8bbd6c639c62937b04d997f38c3770719c
629d7014d49a24b4f98baa1292b4907d60aa6bfade45008a636337f5168c64d9bd36
034808cd564490b1e656edbe74100000000000000046923ee8c68ee1c59802eded23
3d59e588bdde6515f2b6f98532b9fe42e0eaa5792c1204d10d3a5e60079e7b9ee243
8a16ae71c154dbfb54f7fde22e9e697a60641000000000000000401460b43338b846
06d2f78b29bbce6ff6fcf900be89cab91295126244d9727aa232fb48fe6aa33ef677
2ae373d0982479118476b18ac12a4a42973321e36e547410000000000000004197be
e4e39e6ac8fee18f418cae7cc5addc1f10318c0d8d8601202aff0b3f3f7ff8a70fc6
6a57f98f68c0f606fd800cfd5bc73fef6a3d0bf3f9e79e53c23b0934100000000000
000042e2b0b6d65d98a64aa3b23ef29ca7497e1b443dbd39fab7d54284551bc55f0d
7e2782611cc42a60a509566a7decff5e16f4502b9272abed7e2bd17d152cebce1200
0000000000000ee282ccbc95ca96d8f9d214f9f274573e1f1355019986587174f4bd
2712e42fd
K_auth = 0x4f93150c9179ff6bf2c1ec8e4a216ca6
K_enc = 0x09924cb6f6a9ac31a76f4ca4dd5d7a4b
K_confirmP = 0x3f08c6e872338b6d621f38afe9293af1
K_confirmV = 0xf42ea963bea3e8b37b03124875a0103b
HMAC(K_confirmP, shareV) = 0x3b176d3c750e36de42f748078df609f3ac33950
609c872310281e34b589ff85b
HMAC(K_confirmV, shareP) = 0x58caad66418e368fd12b1f5644a8668d9392d8e
3dd94902b766be47963a89e89
CMAC(K_confirmP, shareV) = 0x8969fad82610c9d62b65b98b3254fefa
CMAC(K_confirmV, shareP) = 0x210c1767f5166f226e43bbdd476ed584

[Context=b'SPAKE2+-P256-SHA256-HKDF Test Vectors']
[idProver=b'']
[idVerifier=b'']
w0 = 0xee282ccbc95ca96d8f9d214f9f274573e1f1355019986587174f4bd2712e4
2fd
w1 = 0xbf7e543dbc6b6f1a98affd1ef1aba25ce136a15a28c02b9ba7dfd2da56c00
73f
L = 0x0429ae2016fc29eb5fddbaae8bf60e2c2757a7db333017b842e5da4197ce8e
96d67e7ae1bc1a187bf5bbd237f236ec731bb95d4aba0eb39d74737b052bd53c83c4
x = 0x40f4d8302cac58d1ef586c304617d14586b6d68dcf8931dc522c5dcb3b2944
34
shareP = 0x04ec641e7062a224d695a576cec5abd763435b32e91306e7e4bd3b3fd
26c6dd87d7ba11314b1c7971397a03e69d8fed26ea546e0913b6fa38c9858d8f653a
72e2b
y = 0xde1e7620bed2053240d7cdc2766ffe024df1356aa5b1165bed45c63305e251
c8
shareV = 0x042a46a2354ea87bd67939fd18f15a6b749221553ea403e10472fe374
b8fac022d8d1ba9cc7fdda24b12f7a4ee17620ab11661064b6357dca1a47ece54046
ceb0e
Z = 0x04542d28e96100645d9d56241e1b364a39effd7f1858a1c1cd3a66bd5c20e8
26f5b3c2ae167ed539eab7bcb5f67130abb70a526d083b8c60852eb166587e6e0e01
V = 0x04e62a8a903c5d97eb477be752cad0e36a56e9fb0a01e323001626f421a5b8
43bcf96ad6499b2990955f928a53a8738186b47fdc364a68916cfc364c5dc76e1e04
TT = 0x25000000000000005350414b45322b2d503235362d5348413235362d484b4
446205465737420566563746f7273000000000000000000000000000000004100000
00000000004886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333
d8fa12f5ff355163e43ce224e0b0e65ff02ac8e5c7be09419c785e0ca547d55a12e2
d20410000000000000004d8bbd6c639c62937b04d997f38c3770719c629d7014d49a
24b4f98baa1292b4907d60aa6bfade45008a636337f5168c64d9bd36034808cd5644
90b1e656edbe7410000000000000004ec641e7062a224d695a576cec5abd763435b3
2e91306e7e4bd3b3fd26c6dd87d7ba11314b1c7971397a03e69d8fed26ea546e0913
b6fa38c9858d8f653a72e2b4100000000000000042a46a2354ea87bd67939fd18f15
a6b749221553ea403e10472fe374b8fac022d8d1ba9cc7fdda24b12f7a4ee17620ab
11661064b6357dca1a47ece54046ceb0e410000000000000004542d28e96100645d9
d56241e1b364a39effd7f1858a1c1cd3a66bd5c20e826f5b3c2ae167ed539eab7bcb
5f67130abb70a526d083b8c60852eb166587e6e0e01410000000000000004e62a8a9
03c5d97eb477be752cad0e36a56e9fb0a01e323001626f421a5b843bcf96ad6499b2
990955f928a53a8738186b47fdc364a68916cfc364c5dc76e1e04200000000000000
0ee282ccbc95ca96d8f9d214f9f274573e1f1355019986587174f4bd2712e42fd
K_auth = 0x6615e0ef7543aa8fcd3a3783fb18eced
K_enc = 0xab6c125ff291c6338b4f7e83ff65fde3
K_confirmP = 0x0d5fe5ce506a73a52d941534f75d61d8
K_confirmV = 0x3e2364b8606fe74ba2c2b0be7ecc8773
HMAC(K_confirmP, shareV) = 0x5badef038494e3a06e852f3f54d49a3b317663b
2a64c538db8a77e695a0058da
HMAC(K_confirmV, shareP) = 0x67025b4f6bd48eb9837d050718ef86125d97b47
4c048c9b340ab60b275327c7d
CMAC(K_confirmP, shareV) = 0x9b052d566c1b1ce0a40e319852012b16
CMAC(K_confirmV, shareP) = 0xd5dea068f059a5c9c76590901420cf85
~~~
