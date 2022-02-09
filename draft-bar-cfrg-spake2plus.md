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
We fix a generate P of (large) prime-order subgroup of G. P is specified
in the document defining the group, and so we do not repeat it here.

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

The registration phase also produces two random elements M and N in the prime-order
subgroup of G. The algorithm for selecting M and N is defined in {{pointgen}}.
Importantly, this algorithm chooses M and N such that their discrete logs are not
known. Pre-computed values for M and N are listed in {{Ciphersuites}} for each
group. Applications MAY use different M and N values provided they are computed,
e.g., using different input seeds to the algorithm in {{pointgen}}, as random elements
for which the discrete log is unknown.

Applications using this specification MUST define the method used to compute w0 and w1.
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

Upon receipt of X, the verifier checks the received element for group membership
and aborts if X is not in the large prime-order subgroup of G; see {{security}}
for details. The verifier then selects y uniformly at random from the integers
in [0, p-1], computes the public share shareV=Y and transmits it to the prover.
Upon receipt of Y, the prover checks the received element for group membership
and aborts if Y is not in the large prime-order subgroup of G.

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

The multiplication by the cofactor h prevents small subgroup confinement attacks.
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
the participants. Both parties use TT to derive the shared symmetric secret K_main from the
protocol. The length of K_main is equal to the length of the digest output, e.g., 256 bits
for Hash() = SHA-256. The confirmation keys K_confirmP and K_confirmV, as well as the shared
key K_shared are derived from K_main.

~~~
K_main = Hash(TT)
K_confirmP || K_confirmV = KDF(nil, K_main, "ConfirmationKeys")
K_shared = KDF(nil, K_main, "SharedKey")
~~~

Neither K_main nor its derived confirmation keys are used for anything except key
derivation and confirmation and MUST be discarded after the protocol execution.
Applications MAY derive additional keys from K_shared as needed.

The length of each confirmation key is dependent on the MAC function of the chosen
ciphersuite. For HMAC, the RECOMMENDED key length is equal to the output length of
the digest output, e.g., 256 bits for Hash() = SHA-256. For CMAC-AES, each
confirmation key MUST be of length k, where k is the chosen AES key size,
e.g., 128 bits for CMAC-AES-128.

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

The following points represent permissible point generation seeds for the groups listed
in the Table above, using the algorithm presented in {{pointgen}}. These bytestrings are
compressed points as in {{SEC1}} for curves from {{SEC1}} and {{!RFC8032}}. Note that
these values are identical to those used in the companion SPAKE2 specification {{I-D.irtf-cfrg-spake2}}.

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

# Security Considerations {#security}

SPAKE2+ appears in {{TDH}} and is proven secure in {{SPAKE2P-Analysis}}.

The ephemeral randomness used by the prover and verifier MUST be
generated using a cryptographically secure PRNG.

Elements received from a peer MUST be checked for group membership: failure to
properly deserialize and validate group elements can lead to attacks. An endpoint
MUST abort the protocol if any received public value is not a member of the
large prime-order subgroup of G. Multiplication of a public value V by the
cofactor h will yield the identity element I whenever V is an element of a
small-order subgroup. Consequently, prover and verifier MUST abort the protocol
upon of any received value V such that V\*h = I. Failure to do so may lead to subgroup
confinement attacks.

# Acknowledgements

Thanks to Ben Kaduk and Watson Ladd, from which this specification originally emanated.

--- back

# Algorithm used for Point Generation {#pointgen}

This section describes the algorithm that was used to generate
the points M and N in the table in {{Ciphersuites}}. This algorithm
produces M and N such that they are indistinguishable from two random
points in the prime-order subgroup of G, where the discrete log
of these points is unknown. See {{SPAKE2P-Analysis}} for additional
details on this requirement.

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

This section contains various test vectors for SPAKE2+.
(Choice of PBKDF is omitted and values for w0 and w1 are provided directly.)
All points are encoded using the uncompressed format, i.e., with a 0x04 octet
prefix, specified in {{SEC1}}. idProver and idVerifier identity strings
are provided in the protocol invocation.

~~~

[Context=b'SPAKE2+-P256-SHA256-HKDF-SHA256 Test Vectors']
[idProver=b'client']
[idVerifier=b'server']
w0 = 0xf8648104ede0eb4bf1f762d3f7022bf7d49a8b0911e47375d793830432d77
be7
w1 = 0x927194a92342775ece50539994adc34563f75a3223de6299727e482a914c5
f53
L = 0x0429e83599be728c68d272985ffa4dbee8f11236cb90d9b8cac5141a528ef2
947e70228df615c2629193f4b9f696b8271661ba6551959a843dbfc619aaa3c2f417
x = 0x08ed1260208254587a9516338c581a418789204aecddbb5e93d7eaf53ddd09
9f
shareP = 0x04b7f125df138ca0e39ab4be631fe4699523d3f1fff17a087775058d1
63f075a45c53b2b4f6430b1dd62b81e8eda730faa542323c5fc90766d853d491a66c
ea9cf
y = 0x4160af9ca14b36e4810c021a3bc6151c71d09bcb29eb2c37ce24ab3585bf12
8a
shareV = 0x042f259b8b8afb60be6c6ed0a21dcdbb91b9ee794c169eb93c34973dc
117f1c675b075e07a9f72a41e932a884db5b32a603ce8263259ba19438fe0789fd6e
31cc4
Z = 0x04361c13f083f8a4ee9ad179e13e1d1f7b707533860adde64c3b4a6c8cc5fe
5a648ebd56d17a6e600340e611d56da34b364ec75457c40b9d4936025fa4db059132
V = 0x04db83d6b9c5908cf3904b7fba6590bd6b34c4ba3f807507a62a14f4c1f6af
2c2cfd8a8eb07220d7c52e6fe5729a48e0e4b3823785a8109400409c8de61957349e
TT = 0x2c000000000000005350414b45322b2d503235362d5348413235362d484b4
4462d534841323536205465737420566563746f72730600000000000000636c69656
e740600000000000000736572766572410000000000000004886e2f97ace46e55ba9
dd7242579f2993b64e16ef3dcab95afd497333d8fa12f5ff355163e43ce224e0b0e6
5ff02ac8e5c7be09419c785e0ca547d55a12e2d20410000000000000004d8bbd6c63
9c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b4907d60aa6bfade
45008a636337f5168c64d9bd36034808cd564490b1e656edbe741000000000000000
4b7f125df138ca0e39ab4be631fe4699523d3f1fff17a087775058d163f075a45c53
b2b4f6430b1dd62b81e8eda730faa542323c5fc90766d853d491a66cea9cf4100000
000000000042f259b8b8afb60be6c6ed0a21dcdbb91b9ee794c169eb93c34973dc11
7f1c675b075e07a9f72a41e932a884db5b32a603ce8263259ba19438fe0789fd6e31
cc4410000000000000004361c13f083f8a4ee9ad179e13e1d1f7b707533860adde64
c3b4a6c8cc5fe5a648ebd56d17a6e600340e611d56da34b364ec75457c40b9d49360
25fa4db059132410000000000000004db83d6b9c5908cf3904b7fba6590bd6b34c4b
a3f807507a62a14f4c1f6af2c2cfd8a8eb07220d7c52e6fe5729a48e0e4b3823785a
8109400409c8de61957349e2000000000000000f8648104ede0eb4bf1f762d3f7022
bf7d49a8b0911e47375d793830432d77be7
K_main = 0xba9a70c307189e8fc5750050cc086e5f92113473f66879ff2d36d9dda
ae4121a
K_confirmP = 0xe243ab7c3d4e63b46c67783b9126f27c44a2140dae9dfbf12dab1
f58b6448964
K_confirmV = 0xca622e09a248d384f540cc7794c30bf63f7a5ec1dbc6eb8da1b37
cb8b40ca58b
HMAC(K_confirmP, shareV) = 0x3ffb4826923e29226d107b55621fd04d3ab1a95
8e8dc7d44dc18c987d1a751f1
HMAC(K_confirmV, shareP) = 0xca7b2c49670d32ae92d65d29fe734d0def731e3
984a7f5162181a26784eb2901
K_shared = 0x2c3824544f8cd7e17e721900245c3afb8f82812b2db202f275dc427
6ec6e184c

[Context=b'SPAKE2+-P256-SHA512-HKDF-SHA512 Test Vectors']
[idProver=b'client']
[idVerifier=b'server']
w0 = 0xa6ca0fe2082a8026b61be3593c6f9b6c5791a48c3da7bf722850aad586ce5
54b
w1 = 0x4285ddd0af117bcdf09989ca17fdf6ffe97a1f43cac006d2b35d010af25f8
9f1
L = 0x044c60ad505ef808adddb692015bdf97d70f1b2123770fb897c615730b2374
bacdb23c55e168ee73d46dc178596c1fc6df4571f318b47b385ca5d9ed279270a2a8
x = 0x7b5631470a63dd1b4ee6953afc1b233a260302ffebed6841ad5529862b9f05
25
shareP = 0x042352d889d4a93eee6c01d427af4057af2dba01650e2c91fdb5f9130
8bb27fad3134a51c2739cb2dcad0776228026c4af59bf68f5b4ba98eec68ffd1223e
96dd4
y = 0x515362b7b272cb74fd57fe05c2efbe215fef6fcf91240c4236c09ee3786338
49
shareV = 0x0454950843ed6e6d496326770ea18d4da4b96c48b18643bd9969c7ed8
d2c50981fe0ecba6a44455b77a069f1a2f6df9f06380b14283609027ac9bb40f5ac7
fe03f
Z = 0x0463b7feb0d7e93a0ab6bdcbe0929b613504974150b47f7e576d85898a4e45
0c533bcf22e19148537e5082a50ad284fc67399fb142fb9751de36fe145a71a021e1
V = 0x04c7997334d734a2dc1d6eb256a02916afac41adfaccae253287c7ce6dfcc6
d1a68850e16c3f71f2d520ca1e7b1c6e4455c58409f5b0b7b72b75dff4a96ad8a586
TT = 0x2c000000000000005350414b45322b2d503235362d5348413531322d484b4
4462d534841353132205465737420566563746f72730600000000000000636c69656
e740600000000000000736572766572410000000000000004886e2f97ace46e55ba9
dd7242579f2993b64e16ef3dcab95afd497333d8fa12f5ff355163e43ce224e0b0e6
5ff02ac8e5c7be09419c785e0ca547d55a12e2d20410000000000000004d8bbd6c63
9c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b4907d60aa6bfade
45008a636337f5168c64d9bd36034808cd564490b1e656edbe741000000000000000
42352d889d4a93eee6c01d427af4057af2dba01650e2c91fdb5f91308bb27fad3134
a51c2739cb2dcad0776228026c4af59bf68f5b4ba98eec68ffd1223e96dd44100000
0000000000454950843ed6e6d496326770ea18d4da4b96c48b18643bd9969c7ed8d2
c50981fe0ecba6a44455b77a069f1a2f6df9f06380b14283609027ac9bb40f5ac7fe
03f41000000000000000463b7feb0d7e93a0ab6bdcbe0929b613504974150b47f7e5
76d85898a4e450c533bcf22e19148537e5082a50ad284fc67399fb142fb9751de36f
e145a71a021e1410000000000000004c7997334d734a2dc1d6eb256a02916afac41a
dfaccae253287c7ce6dfcc6d1a68850e16c3f71f2d520ca1e7b1c6e4455c58409f5b
0b7b72b75dff4a96ad8a5862000000000000000a6ca0fe2082a8026b61be3593c6f9
b6c5791a48c3da7bf722850aad586ce554b
K_main = 0x3188ad5bd02b43b529032b9faecef136794ddd7e83ac6fc33bd3bcc69
924dc21a9415c761088e6ce67a4f2eb96baa740857983a455d6e787694ba04e6f722
86f
K_confirmP = 0xa2e97f5d438e5c29687b41b0412f657e804e7b81b4d5d46e5cad3
b572a35d83ae0bd2ca8a98e3c2e02a12803dd2fd2a89842d5fc6b68e756812976f2c
aafaedf
K_confirmV = 0x3cafba26be33c87c3f8ed4097fdeba42f60af23a045fbec4228f5
80e311df7890de90038a07da1514206eb99d1887b113fb38a115f8473d22b8cc11ac
2e389df
HMAC(K_confirmP, shareV) = 0xde84c1426e932a0c57209459d94bfd395dc0257
54fb691e107616e533bba53039f1fe601ca558be21b4f3c450759bbd0f442ac75b96
06730963a25dc19d0e0ac
HMAC(K_confirmV, shareP) = 0xcb346e37a90c235e41340700d3461b16cab5d88
a961a04f326959ce1758bf219e9975156b4a3b5eda1081df6949ae8020bab2ff3360
dcd3a174b136986cbbb8e
K_shared = 0xfc9bab1c0d759e03cf0fe33c53c7a8c590f1cd8500519165f14c87f
4807a238f8d3001019b962f435d3fff31f9a0da5396ee85f5bffbc7b675fc35ececd
95060

[Context=b'SPAKE2+-P384-SHA256-HKDF-SHA256 Test Vectors']
[idProver=b'client']
[idVerifier=b'server']
w0 = 0x8df3b215e1d72792cc264a966793374288b3383f209012d01ebcdf7442e6a
cdf0b39528dde460703326212317d3cc9cb
w1 = 0xc0bffe1adf464ca533ab3c554ea75d4ad6b941488be7e90e99112fb131587
e27da17a9425ca91f1259b4c897ec7f9a65
L = 0x04daf60c1d921f27d2c806b38e31d729d20c46b701cbb95fb6eec082478f1d
ed9ca2f5259ad6551240c3c22156943a0961c7f4e4f6d690b5d50ede38376f4fef30
e6ba9025e937e1aab2e796dfd71840664fc6dd3c575fcd423632aec5e347428f
x = 0x86a9127c6c04680b43ae347919566f757fe5fe07a44243aa6fd63c474e3505
8bfb7d27cb120a7e91ab0f4e4eb8a4c86e
shareP = 0x0454a1ca458c763fba1a6f2226a95a82640bcfa49ae3635d9064efcf9
170c5a7631f4a37627b8363655ce69ea73700ba4b16fd86d8c859641480b8c9ed1ee
c0276fdaa7db22bcebe76f3d58440ef6d2205f5fa4770c9cd596d1821e38da11c3e9
1
y = 0x3dce3fada987e3f7c5f75dc4d3dd5502c2c3595ef43d7fb95c257b1558a49e
0bb91a677a6e6fd1c563eec6971cfaf65b
shareV = 0x040d57e1f174b194c6addc97ef035a12b63c8edc35423a8337b96aa96
a8f61529be08fc0003b6bf317570d9f9112315846702349abdb224056f5805ed78f6
8282347c0696c308b9d8c4d278d202635a40444f7160445a6fe45ee346a7730784e2
b
Z = 0x041ab9a2bd4a8d842c980a8dd2b0290b2b9dcd81b75d620124e4c8e9cf38d1
0096edee33513135c2ef3ff6f9b789bd2e4329078bcf19e453a518faff37be1127c4
80854d74713cf55b2994cc069a37000889a73db50814ea9770b6799cec31257f
V = 0x0481b1a4eece5a9a01b5ea35683d75848313b847b8b1c0d7c80e44139712c0
e44b168cd058fc761b8aa994f9ce26440a3180949ec9442b70eb65965489094005a7
5cdef9ba64b4b57410fcf5465a5e3f2c37945a2b3e39d7c7c826a295dc038598
TT = 0x2c000000000000005350414b45322b2d503338342d5348413235362d484b4
4462d534841323536205465737420566563746f72730600000000000000636c69656
e7406000000000000007365727665726100000000000000040ff0895ae5ebf618708
0a82d82b42e2765e3b2f8749c7e05eba366434b363d3dc36f15314739074d2eb8613
fceec285397592c55797cdd77c0715cb7df2150220a0119866486af4234f390aad1f
6addde5930909adc67a1fc0c99ba3d52dc5dd610000000000000004c72cf2e390853
a1c1c4ad816a62fd15824f56078918f43f922ca21518f9c543bb252c5490214cf9aa
3f0baab4b665c10c38b7d7f4e7f320317cd717315a797c7e02933aef68b364cbf84e
bc619bedbe21ff5c69ea0f1fed5d7e3200418073f4061000000000000000454a1ca4
58c763fba1a6f2226a95a82640bcfa49ae3635d9064efcf9170c5a7631f4a37627b8
363655ce69ea73700ba4b16fd86d8c859641480b8c9ed1eec0276fdaa7db22bcebe7
6f3d58440ef6d2205f5fa4770c9cd596d1821e38da11c3e916100000000000000040
d57e1f174b194c6addc97ef035a12b63c8edc35423a8337b96aa96a8f61529be08fc
0003b6bf317570d9f9112315846702349abdb224056f5805ed78f68282347c0696c3
08b9d8c4d278d202635a40444f7160445a6fe45ee346a7730784e2b6100000000000
000041ab9a2bd4a8d842c980a8dd2b0290b2b9dcd81b75d620124e4c8e9cf38d1009
6edee33513135c2ef3ff6f9b789bd2e4329078bcf19e453a518faff37be1127c4808
54d74713cf55b2994cc069a37000889a73db50814ea9770b6799cec31257f6100000
0000000000481b1a4eece5a9a01b5ea35683d75848313b847b8b1c0d7c80e4413971
2c0e44b168cd058fc761b8aa994f9ce26440a3180949ec9442b70eb6596548909400
5a75cdef9ba64b4b57410fcf5465a5e3f2c37945a2b3e39d7c7c826a295dc0385983
0000000000000008df3b215e1d72792cc264a966793374288b3383f209012d01ebcd
f7442e6acdf0b39528dde460703326212317d3cc9cb
K_main = 0xc3d7c44365329cf360f7fb71a582832e1bbc6e81be270d4e30c6002f7
6612651
K_confirmP = 0xae519b5ec34283ba41901535c56dc21806dd01300c6875136f43a
9fb0232f1b2
K_confirmV = 0x995ea0d7726b3559e529fbbc43e00c6b0835a85c2086185afc21c
fdc43b837ef
HMAC(K_confirmP, shareV) = 0x24f28405b54595b73dc925fb3c551222e40f35c
477631e5e49dc1b01ef61aa7c
HMAC(K_confirmV, shareP) = 0x1999ebf6de59c5c4a4d2615af0aee57a37f73b5
3d16097452d661695e322ceca
K_shared = 0xa24a15014a7369f1e2bfe8d94c543760313ce61d9b9c81ccf24341c
2e6b11eba

[Context=b'SPAKE2+-P384-SHA512-HKDF-SHA512 Test Vectors']
[idProver=b'client']
[idVerifier=b'server']
w0 = 0x36d0590310666e9d609a8b6942453d42905cea6248d83ec878c03f7670462
fd5fdff85f1f3f59a9b0a689d78546961e3
w1 = 0x32037c012909160839cd19aef140267340e41af1a865cf725058b61da90b1
ee7dda2a0e900624bcbbcfd0d140e892979
L = 0x04e3ae94d9d90fc0c5762f48460626b1e6fc3b3dad6f014fa9582eae9e6902
8c1bf1d0d36fca13395ac3cd7f7734aa948fb022763c221b8560b8254115073eaa99
c77db2fed054c5a3ba191d0064c5da5a0f513a3a52f95698de3c28408345fbb3
x = 0x0ec8e60e0bb579fce22504b68c7a3a7f2fee75b8a1d53dce36fecfbfe28701
45131fc66b4c8dc2c3cc61cb9368abe129
shareP = 0x045a873d4a19e9e3c699c837fc5d6801150c2be8539640a3a19af40f0
f3a727a6b20415c5f38c90b1e4aca97cc2aa5b1c6def8a12d295c7ae7e58945726df
1c146340e3919119459580f4714883aa67ba364d65a958ec5fe5f7895166f717d0f7
c
y = 0xaf63c757cb9f25d6f2c768acd00a93b988a471cf63a04884782c54e76b2cd5
5b9db74b8bf351cbe22d4d921df14e47e5
shareV = 0x04f3bc58378cd91cd213b4b37c7133114f322a511f99e3dabcfcf428a
8d533504005d1f2b3ea0c503d8192633c31cd5ab3fd493438ae6a4e5d1254ceee767
3989b8705ee524f2f9263fd56a8d1c5dd096aec2d277f8d8b4fcf1775f4f1b10ffd2
6
Z = 0x04db2373483f8d01f5bd34793362187d228de0a13d21a092af46dbf2f18050
9e9b819f9272ff8dde5e1d0642eb502a05858010aa1e26aaf3cf23acbf5d077edd97
0cb45a7442bebd8c8ace7f1158e500949893da8f48cdb38cbb8eb77cbb9739d1
V = 0x045a62cc185ba69daae1e8d8f2b20f6138d9e99e3c34876eb951a07b02e2e2
2b717b9acfea31535f263aeeeb055bc1011829333f1fa8886e95adfe80275f39b11f
2e22e92aa1522cbfd6c291d8821f1da154ecd566b969cd0a649be67ee72650b2
TT = 0x2c000000000000005350414b45322b2d503338342d5348413531322d484b4
4462d534841353132205465737420566563746f72730600000000000000636c69656
e7406000000000000007365727665726100000000000000040ff0895ae5ebf618708
0a82d82b42e2765e3b2f8749c7e05eba366434b363d3dc36f15314739074d2eb8613
fceec285397592c55797cdd77c0715cb7df2150220a0119866486af4234f390aad1f
6addde5930909adc67a1fc0c99ba3d52dc5dd610000000000000004c72cf2e390853
a1c1c4ad816a62fd15824f56078918f43f922ca21518f9c543bb252c5490214cf9aa
3f0baab4b665c10c38b7d7f4e7f320317cd717315a797c7e02933aef68b364cbf84e
bc619bedbe21ff5c69ea0f1fed5d7e3200418073f406100000000000000045a873d4
a19e9e3c699c837fc5d6801150c2be8539640a3a19af40f0f3a727a6b20415c5f38c
90b1e4aca97cc2aa5b1c6def8a12d295c7ae7e58945726df1c146340e39191194595
80f4714883aa67ba364d65a958ec5fe5f7895166f717d0f7c610000000000000004f
3bc58378cd91cd213b4b37c7133114f322a511f99e3dabcfcf428a8d533504005d1f
2b3ea0c503d8192633c31cd5ab3fd493438ae6a4e5d1254ceee7673989b8705ee524
f2f9263fd56a8d1c5dd096aec2d277f8d8b4fcf1775f4f1b10ffd266100000000000
00004db2373483f8d01f5bd34793362187d228de0a13d21a092af46dbf2f180509e9
b819f9272ff8dde5e1d0642eb502a05858010aa1e26aaf3cf23acbf5d077edd970cb
45a7442bebd8c8ace7f1158e500949893da8f48cdb38cbb8eb77cbb9739d16100000
000000000045a62cc185ba69daae1e8d8f2b20f6138d9e99e3c34876eb951a07b02e
2e22b717b9acfea31535f263aeeeb055bc1011829333f1fa8886e95adfe80275f39b
11f2e22e92aa1522cbfd6c291d8821f1da154ecd566b969cd0a649be67ee72650b23
00000000000000036d0590310666e9d609a8b6942453d42905cea6248d83ec878c03
f7670462fd5fdff85f1f3f59a9b0a689d78546961e3
K_main = 0xe0eb9aebe5f6944d2749bdb28055623ce32c94538b1bc3519f789e0a0
cda41cac003c078e029e9b002a381af566e20648a16074993bea0679448b9a7e4dde
a64
K_confirmP = 0xe53b37bb0790afab9a88a423c8f3543f98cad93e5051d54e416c0
049fdfcf0f5e721239b861482fa0cd989bad5ccab1f670f8ccbbb9cdf7bf20cae6e0
35d24fa
K_confirmV = 0xffa3094d8a514b467fb1909d92bdc8e52c56eb3a390187927670b
0845f99aba44a7ca6556cf464e83349994d3a3fab86e2e65ea235be89fdb5cee8b6b
f184bce
HMAC(K_confirmP, shareV) = 0xe8c47650106dce9fad529fef1493862666d7763
2edf3dce79a39170eb6d91d4f07c97a6ba97294b458efb6e1b89820e362afdf9ef12
5343931730f0387fc63c3
HMAC(K_confirmV, shareP) = 0x8c925c3cc43eae6f4afc7d5b4150f3fafe7748e
add18cb205e856be74913d0c881b37faffa6d7bc422ebe0c6dff2a2384e7da86406f
8b2d4dfc4381bfdb552f3
K_shared = 0x8dcfc46c280ac5d5175504150e2b33a54bb1c6f2cb98d3fac282003
8d2637ddbd56bc9c15df327c8af9b33e36e89287550b2437cbc02d133c7dee26a3c3
1fa37

[Context=b'SPAKE2+-P521-SHA512-HKDF-SHA512 Test Vectors']
[idProver=b'client']
[idVerifier=b'server']
w0 = 0x017a96705627ce7722c70129b3086814926c18e91810e2ef9a00056e7aa4a
09a7343c3d6d58180b7a36e9e0ab59b0008f59802bb1878ee80168e3db07da32ed6a
638
w1 = 0x00bdad70389acf68c79f4f4b528e262ac69162379c95c74b449ee7af5d6c4
8b9ee491e96c713bc13be6dae09bad144b84111c2a1e300ebf2611522ae34f7493f8
5d4
L = 0x0401d6a4589d99f5d3257e640360af1b95ffec98b0d988fd1cca4ae78719f4
55f96e8d74f151128ed8d2af2f4cc7448d5b0965ee4b488f8d27ab03997cf1db4653
d491000aa87a4800e8cc7f220cd0da2685e4dbb37fd908e18d687b28505dda445c2e
7952d2ec9067b9bd0e785d30a06cbe521c25aaf7eba1c52b3c586b5f6ba90f21f26f
x = 0x004aa1f3bce58d216022d4845bdc21e5ee811c1601ed9630e8e9212b104267
f3710483baeda3f4d49987090e7183be66ad7fd427b75378cfeb780bd26ba00b6ebe
f4
shareP = 0x04008898917df964164ec0482f04dc0721dbca8182401f46d368a7e5a
800c7b914ba1bdde537faf9603edf694a818fb7166d9dbabaf84756e79be55d76323
58ecb11a401779fdee916a83d4bcb717dba6154c8e292112166d5a4c3dedadab2ba3
bc9a9fd4d4329b142ff240fb8521a18c4dcf8451edc736330e7edd14bb7fac74c5c4
2cf6f
y = 0x00685ee6041d134e080e3e489013636c4af2fc0906de2ee6ab7e30ca378886
d2ff5ef9602ebe6e967e6b03ea9dda796447d005ca9ddcd2cfdf1f0ee0ac392b04c8
54
shareV = 0x04017f4061479175e111278744f9edf2a79f0c045250b920e91c463d7
e5fcea26e4bd63612dee1a98881bb4d6e78b64dbbf58a9373d2de39ed1fe7012d0cb
fa7018dc700f090dda7744f4b589ae223e287a6a6fd3cde1be2078f8ddd9f98107c1
4b928f26fabce675adb9d54ed89a1382317df78d9c81f1660488db4152bcd5fbfcc3
32e72
Z = 0x0401d345c38852ab77a34922dfcdc37e13971ab410eb0537bf366665bce37a
28af809de8fc088175306f4d9db5d25e965a040f63fcf733c76b1afd65bf76f9ffe8
2607018a87e5aef261cd8ef021508c3e6d785a21945a8fe24e2d251f2ea2aff874a7
26e9b9aa089b7b7996644419695fb6edcd667d01b4a8dea6b9f33be182a591dcd6c8
V = 0x04004e1126360747d971ccd2be5ab424e680334b22468b0418113f11efc0b1
0d7d6169ff3d6d5cb2914c3db62ceb9c0993d88c21fd78dc13ff8c480e7820e619d2
a35300a025184c21f7a238f6dbdb038452bd748bc7a951a34e5e57f7bb838ed571f3
e59d6ca5cd81cf630ab9830e8e65abe02eda3fb0dccf8763ade6aff5eeba36140d10
TT = 0x2c000000000000005350414b45322b2d503532312d5348413531322d484b4
4462d534841353132205465737420566563746f72730600000000000000636c69656
e740600000000000000736572766572850000000000000004003f06f38131b2ba260
0791e82488e8d20ab889af753a41806c5db18d37d85608cfae06b82e4a72cd744c71
9193562a653ea1f119eef9356907edc9b56979962d7aa01bdd179a3d547610892e9b
96dea1eab10bdd7ac5ae0cf75aa0f853bfd185cf782f894301998b11d1898ede2701
dca37a2bb50b4f519c3d89a7d054b51fb8491219285000000000000000400c7924b9
ec017f3094562894336a53c50167ba8c5963876880542bc669e494b2532d76c5b53d
fb349fdf69154b9e0048c58a42e8ed04cef052a3bc349d95575cd2501c62bee650c9
287a651bb75c7f39a2006873347b769840d261d17760b107e29f091d556a82a2e4cd
e0c40b84b95b878db2489ef760206424b3fe7968aa8e0b1f33485000000000000000
4008898917df964164ec0482f04dc0721dbca8182401f46d368a7e5a800c7b914ba1
bdde537faf9603edf694a818fb7166d9dbabaf84756e79be55d7632358ecb11a4017
79fdee916a83d4bcb717dba6154c8e292112166d5a4c3dedadab2ba3bc9a9fd4d432
9b142ff240fb8521a18c4dcf8451edc736330e7edd14bb7fac74c5c42cf6f8500000
00000000004017f4061479175e111278744f9edf2a79f0c045250b920e91c463d7e5
fcea26e4bd63612dee1a98881bb4d6e78b64dbbf58a9373d2de39ed1fe7012d0cbfa
7018dc700f090dda7744f4b589ae223e287a6a6fd3cde1be2078f8ddd9f98107c14b
928f26fabce675adb9d54ed89a1382317df78d9c81f1660488db4152bcd5fbfcc332
e7285000000000000000401d345c38852ab77a34922dfcdc37e13971ab410eb0537b
f366665bce37a28af809de8fc088175306f4d9db5d25e965a040f63fcf733c76b1af
d65bf76f9ffe82607018a87e5aef261cd8ef021508c3e6d785a21945a8fe24e2d251
f2ea2aff874a726e9b9aa089b7b7996644419695fb6edcd667d01b4a8dea6b9f33be
182a591dcd6c8850000000000000004004e1126360747d971ccd2be5ab424e680334
b22468b0418113f11efc0b10d7d6169ff3d6d5cb2914c3db62ceb9c0993d88c21fd7
8dc13ff8c480e7820e619d2a35300a025184c21f7a238f6dbdb038452bd748bc7a95
1a34e5e57f7bb838ed571f3e59d6ca5cd81cf630ab9830e8e65abe02eda3fb0dccf8
763ade6aff5eeba36140d104200000000000000017a96705627ce7722c70129b3086
814926c18e91810e2ef9a00056e7aa4a09a7343c3d6d58180b7a36e9e0ab59b0008f
59802bb1878ee80168e3db07da32ed6a638
K_main = 0x8a89a7c01ee1d3fd6c595d0d3a4f69d7c57c061f2d70e39469ed519c0
ad362075b1c22b82a52c26dd2320f6913aa1f0374be7d44b253176ffd87fdcfbc69e
208
K_confirmP = 0x2c6cffa8709d5ed98278fb1d618dffed871c053cd9617c376b2a1
72ba24dd52b7dc89b727624a671c0d4d9d44c6268d8239f41425e5828fa53e4fcefd
e4c18be
K_confirmV = 0xe0af19dd45a8fe20f72623f20ce96d44ba6df53dc024ec970e2df
5cebb8a1261806ab500bab9e0e53fe7a8b204780c0f335a72e16729a138f6c72db16
63aaf7c
HMAC(K_confirmP, shareV) = 0x7a44f2f7c68e4502343e018824d85dfcde9ee36
d98e97ec1d154891c79531dd183ba711738f1fad2b661e83159d7bf3ce8700dffabd
e37689ea64d1598d98b21
HMAC(K_confirmV, shareP) = 0xa47f460c061a13de7716aaaa707d9077df6e986
2ba2c4478162c8a588906b46ccfd8ccff30fb59b95ab0e57b335a281f689fc4f5582
718c3e62b15b8e5001401
K_shared = 0xcfe3c79ef8ee8cf26dd0dbd590f1e47cd0baba0764224212c9e4e66
ff573dd2f3e7851ba3d58a9022103f6fa011c1c96602b2f0ddfb7e7860546384bd7c
05766

[Context=b'SPAKE2+-P256-SHA256-CMAC-AES-128 Test Vectors']
[idProver=b'client']
[idVerifier=b'server']
w0 = 0xfde060103a72526b8be9af9be851582aa44615c406254c777e69c2c6fb6a4
ec6
w1 = 0xcec29581ecf80a237df1ff00d7150e41919a4235cdb9b10d3e1aaae9b3db7
9ab
L = 0x044ced7ff0754a4c16728eb9235a387712af1ae3564a7be257c9c1b0ddca85
b3cd3e26ea30e041d929fc709b86ab2f2bce3f63867c526a93dd3710b65a1aa63599
x = 0x87075f67b1bf933df0345ede4567d74269a6c406b3b0107c1fdcb0ceca995b
30
shareP = 0x043c230b8ec315a076221bb91f16e663e45b6fee6c4b65bf95ee936cb
47d042f5e2cb954fb7acf72542fc95f31662e56dbb2224d14032761a7ed8c5cb3370
50dd2
y = 0xadab37f45722d37b043a29120f6ccf3296caf011ac701834314566d38b864f
7f
shareV = 0x04d90ae972e7805e61823329fe88e675eddcd95482d155aa564c7bf90
57dab9ad87f30ab7fe00b6779a3a7c85ec11d983e78fd0dc598df5198728eef47260
3a868
Z = 0x041234f0a6cb8d688aaa0028b74227ffa50961955cfd19698a5ca77402c607
080853228d13c03ac18e99f1fadad76b5cfffff43829ba3b2741abb2af58ef95a345
V = 0x04fe782a21b81f1e3403ce6d38227117b86ed911a7b10f20d517c6b146e327
70427244e90f9491a3f60cc9f5388d595c83d54420f37f7ec8625747b3c179d147c2
TT = 0x2d000000000000005350414b45322b2d503235362d5348413235362d434d4
1432d4145532d313238205465737420566563746f72730600000000000000636c696
56e740600000000000000736572766572410000000000000004886e2f97ace46e55b
a9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f5ff355163e43ce224e0b0
e65ff02ac8e5c7be09419c785e0ca547d55a12e2d20410000000000000004d8bbd6c
639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b4907d60aa6bfa
de45008a636337f5168c64d9bd36034808cd564490b1e656edbe7410000000000000
0043c230b8ec315a076221bb91f16e663e45b6fee6c4b65bf95ee936cb47d042f5e2
cb954fb7acf72542fc95f31662e56dbb2224d14032761a7ed8c5cb337050dd241000
0000000000004d90ae972e7805e61823329fe88e675eddcd95482d155aa564c7bf90
57dab9ad87f30ab7fe00b6779a3a7c85ec11d983e78fd0dc598df5198728eef47260
3a8684100000000000000041234f0a6cb8d688aaa0028b74227ffa50961955cfd196
98a5ca77402c607080853228d13c03ac18e99f1fadad76b5cfffff43829ba3b2741a
bb2af58ef95a345410000000000000004fe782a21b81f1e3403ce6d38227117b86ed
911a7b10f20d517c6b146e32770427244e90f9491a3f60cc9f5388d595c83d54420f
37f7ec8625747b3c179d147c22000000000000000fde060103a72526b8be9af9be85
1582aa44615c406254c777e69c2c6fb6a4ec6
K_main = 0xf6f43706ac09af2c39c5b81b23c07ba4e0ea716a648359ddae05a4d38
be6f306
K_confirmP = 0xa6a9f8296b9decd9217dccbcaead469e
K_confirmV = 0x0fab5579e215c2ac862f1231d6f656ce
CMAC(K_confirmP, shareV) = 0x870e8b23b33d81d7ba2e60eef2efa71a
CMAC(K_confirmV, shareP) = 0x3a6e352db6ed168eefca1a25a635ce3e
K_shared = 0x069a1337f935c08a322ebc514328939ffbe9c72e3a2e25491636afe
c3f83b1db

[Context=b'SPAKE2+-P256-SHA512-CMAC-AES-128 Test Vectors']
[idProver=b'client']
[idVerifier=b'server']
w0 = 0x98369d63627c363eaa3fb17a95a43555d1ee00f24d4f3c06e18184e5894eb
002
w1 = 0x829644923b86253ba37919a8a40ba8dc67161d176c99ac65a598e8acdc0b8
45f
L = 0x04cdc6a89284ed1590302d9641651f74fc767cb85b2c4127ee22cdee40a6a1
68b56e8ef3196f6bd2d509690621a16db3ba75cbff395e8a0b7b48b0fe61df46ed64
x = 0xd888f116b056241dd956b99e5e4328380cd083eb48ac57ec8f47ff6c22b955
66
shareP = 0x04d8de5bcc061291b2692a490c75f3c3520f4fd05bdb941db7b396f2d
cdd183f51483a4e2df92322450a193fac4520ba9fc862bdea8072bb2e7ff054297cf
25451
y = 0xcfca1044d92914e50190e9447f343f5bd3ac80ea4a71fa76bd93b02c1eb1ae
ec
shareV = 0x04d1da76bb56787ff34ce8458d7ebc506997519e10cc072ce5b6e5260
516608244ff3e309b868c270eb445af69a8b41629233d0abce1ce07ea8292e158291
f286d
Z = 0x04b7d60e6effa1bc71b6e43c138e6b457ccba4cf423b9c47ed2e7a3d3d0d8a
84c29e35408c3fbc191901b832390e01011a546678657223fda8bc55401a6510a749
V = 0x049bcd2687b3719c1dc4c0487a72bb351396a6fc360676eab61849db02acee
b9858f88fe740a7fe3d1cd3638f948269b58d0f2630b43c7ace2b1137d08ae3b1e5f
TT = 0x2d000000000000005350414b45322b2d503235362d5348413531322d434d4
1432d4145532d313238205465737420566563746f72730600000000000000636c696
56e740600000000000000736572766572410000000000000004886e2f97ace46e55b
a9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f5ff355163e43ce224e0b0
e65ff02ac8e5c7be09419c785e0ca547d55a12e2d20410000000000000004d8bbd6c
639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b4907d60aa6bfa
de45008a636337f5168c64d9bd36034808cd564490b1e656edbe7410000000000000
004d8de5bcc061291b2692a490c75f3c3520f4fd05bdb941db7b396f2dcdd183f514
83a4e2df92322450a193fac4520ba9fc862bdea8072bb2e7ff054297cf2545141000
0000000000004d1da76bb56787ff34ce8458d7ebc506997519e10cc072ce5b6e5260
516608244ff3e309b868c270eb445af69a8b41629233d0abce1ce07ea8292e158291
f286d410000000000000004b7d60e6effa1bc71b6e43c138e6b457ccba4cf423b9c4
7ed2e7a3d3d0d8a84c29e35408c3fbc191901b832390e01011a546678657223fda8b
c55401a6510a7494100000000000000049bcd2687b3719c1dc4c0487a72bb351396a
6fc360676eab61849db02aceeb9858f88fe740a7fe3d1cd3638f948269b58d0f2630
b43c7ace2b1137d08ae3b1e5f200000000000000098369d63627c363eaa3fb17a95a
43555d1ee00f24d4f3c06e18184e5894eb002
K_main = 0x32b7235352117963914a9a5145ba1eed50ded03de0b9ec1ead9c507f4
6ab16c7694582e7e238269ae1407c109947ff9951907279b1379a2fc41f678c0c1d2
fa5
K_confirmP = 0x9ada35b8e04aee872dd5a0b9fef83e71
K_confirmV = 0x9522a3ed0d751a6643d90d9c4979afad
CMAC(K_confirmP, shareV) = 0x85d57fe6fbca9a8556d5eff677a88ea9
CMAC(K_confirmV, shareP) = 0xc8c42b76190f907e042a343fcf938c96
K_shared = 0xa3eb2e832f7d0fe24a130afb8c6da1fa86249a6da095c1ba2393e4e
57c7b8ccbd0e4a2641a18ed3d92a602ffa057bb60cd4fc9fa90dd100de0318e7a392
d723a
~~~
