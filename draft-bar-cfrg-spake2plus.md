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
  UCAnalysis:
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
The other party only needs a verification value at the time of the protocol execution instead of the password.
The verification value can be computed once, during an offline initialization phase.
The party using the password directly would typically be a client, and acts as a prover,
while the other party would be a server, and acts as verifier.

The protocol is augmented in the sense that it provides some resilience to the compromise or extraction of the verification value.
The design of the protocol forces the adversary to recover the password from the verification value to successfully execute the protocol.
Hence this protocol can be advantageously combined with a salted Password Hashing Function to increase the cost of the recovery and slow down attacks.
The verification value cannot be used directly to successfully run the protocol as a prover,
making this protocol more robust than balanced PAKEs which don't benefit from Password Hashing Functions to the same extent.

This augmented property is especially valuable in scenarios where the execution of the protocol is constrained
and the adversary can not query the salt of the password hash function ahead of the attack.
Constraints may consist in being in physical proximity through a local network or
when initiation of the protocol requires a first authentication factor.

This password-based key exchange protocol appears in {{TDH}} and is proven secure in {{UCAnalysis}}.
It is compatible with any prime-order group and relies only on group operations, making it simple and computationally efficient.
Predetermined parameters for a selection of commonly used groups are also provided.

This document has content split out from a related document specifying SPAKE2 {{!I-D.irtf-cfrg-spake2}}.

# Requirements Notation

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in {{!RFC2119}}.

# Definition of SPAKE2+

## Offline Initialization {#setup}

Let G be a group in which the computational Diffie-Hellman (CDH)
problem is hard. Suppose G has order p\*h where p is a large prime;
h will be called the cofactor. Let I be the unit element in
G, e.g., the point at infinity if G is an elliptic curve group. We denote the
operations in the group additively. We assume there is a representation of
elements of G as byte strings: common choices would be SEC1
uncompressed or compressed {{SEC1}} for elliptic curve groups or big
endian integers of a fixed (per-group) length for prime field DH.
We fix two elements M and N in the prime-order subgroup of G as defined
in the table in this document for common groups, as well as a generator P
of the (large) prime-order subgroup of G. P is specified in the document defining
the group, and so we do not repeat it here.

|| denotes concatenation of strings. We also let len(S) denote the
length of a string in bytes, represented as an eight-byte little-
endian number. Finally, let nil represent an empty string, i.e.,
len(nil) = 0.

KDF is a key-derivation function that takes as input a salt, intermediate
keying material (IKM), info string, and derived key length L to derive a
cryptographic key of length L.
MAC is a Message Authentication Code algorithm that takes a secret key and
message as input to produce an output.
Let Hash be a hash function from arbitrary strings to bit strings of a fixed length. Common choices
for Hash are SHA256 or SHA512 {{!RFC6234}}.
Let PBKDF be a Password-Based Key Derivation Function designed to slow down brute-force attackers.
Brute-force resistance may be obtained through various computation hardness parameters such as memory or CPU cycles,
and are typically configurable.
Scrypt {{!RFC7914}} and Argon2 are common examples of PBKDF functions.
PBKDF and hardness parameter selection are out of scope of this document.
{{Ciphersuites}} specifies variants of KDF, MAC, and Hash
suitable for use with the protocols contained herein.

Let A and B be two parties. A and B may also have digital
representations of the parties' identities such as Media Access Control addresses
or other names (hostnames, usernames, etc). A and B may share additional data
(the context) separate from their identities which they may want to include in
the protocol transcript.
One example of additional data is a list of supported protocol versions if SPAKE2+ were
used in a higher-level protocol which negotiates the use of a particular PAKE. Another
example is the inclusion of PBKDF parameters and the application name.
Including those would ensure that both parties agree upon the same set of supported
protocols and use the same PBKDF parameters and therefore prevent downgrade and
cross-protocol attacks. Specification of precise context values is out of scope for this document.

## Protocol Flow {#flow}

SPAKE2+ is a two round protocol that establishes a shared secret with an
additional round for key confirmation. Prior to invocation, A and B are provisioned with
information such as the input password needed to run the protocol.
A preamble exchange may occur in order to communicate identities, protocol version and PBKDF parameters related to the verification value.
Details of the preamble phase are out of scope of this document.
During the first round, A, the prover, sends a public share pA
to B, the verifier, and B responds with its own public share pB. Both A and B then derive a shared secret
used to produce encryption and authentication keys. The latter are used during the second
round for key confirmation. ({{keys}} details the key derivation and
confirmation steps.) In particular, B sends a key confirmation message cB to A, and A responds
with its own key confirmation message cA. (Note that pB and cB MAY be sent in the same message.)
Both parties MUST NOT consider the protocol complete prior to receipt and validation of these key
confirmation messages.

A sample trace is shown below.

~~~
               A                           B

               |         (Preamble)        |
               |<- - - - - - - - - - - - ->|
               |                           |
               |       (setup protocol)    |
  (compute pA) |             pA            |
               |-------------------------->|
               |             pB            | (compute pB)
               |<--------------------------|
               |                           |
               |       (derive secrets)    | (compute cB)
               |             cB            |
               |<--------------------------|
  (compute cA) |             cA            |
               |-------------------------->|

~~~

## SPAKE2+ {#spake2plus}

Let w0 and w1 be two integers derived by hashing the password pw with the
identities of the two participants, A and B. Specifically, compute
w0s || w1s = PBKDF(len(pw) || pw || len(A) || A || len(B) || B),
and then w0 = w0s mod p and w1 = w1s mod p.
If both identities A and B are absent, then w0s || w1s = PBKDF(pw), i.e.,
the length prefix is omitted as in {{setup}}.
If both identities A and B are unknown at the time of deriving w0 and w1,
w0s and w1s are computed as if both identities were absent. They however
SHOULD be included in the transcript TT if the parties exchange those
prior to or as part of the protocol flow.
The party B stores the verification value pair L=w1\*P and w0.

Note that standards such as NIST.SP.800-56Ar3 suggest taking mod p of a
hash value that is 64 bits longer than that needed to represent p to remove
statistical bias introduced by the modulation. Protocols using this specification must define
the method used to compute w0 and w1: it may be necessary to carry out various
forms of normalization of the password before hashing {{!RFC8265}}.
The hashing algorithm SHOULD be a PBKDF so as to slow down brute-force
attackers.

When executing SPAKE2+, A selects x uniformly at random from the
numbers in the range [0, p), and lets X=x\*P+w0\*M, then transmits pA=X to
B. Upon receipt of X, B computes h\*X and aborts if the result is equal
to I. B then selects y uniformly at random from the numbers in [0, p),
then computes Y=y\*P+w0\*N, and transmits pB=Y to A. Upon receipt of Y,
A computes h\*Y and aborts if the result is equal to I.

A computes Z as h\*x\*(Y-w0\*N), and V as h\*w1\*(Y-w0\*N). B computes Z as
h\*y\*(X-w0\*M) and V as h\*y\*L. Both share Z and V as common values.
It is essential that both Z and V be used in combination with the transcript to
derive the keying material. The protocol transcript encoding is shown below.

~~~
TT = len(Context) || Context ||
  || len(A) || A || len(B) || B
  || len(M) || M || len(N) || N
  || len(X) || X || len(Y) || Y
  || len(Z) || Z || len(V) || V
  || len(w0) || w0
~~~

Context is an application-specific customization string shared between both
parties and SHOULD precede the remaining transcript. It might contain the
name and version number of the higher-level protocol, or simply the name and version
number of the application. The context MAY include additional data such as the
chosen ciphersuite and PBKDF parameters like the iteration count or salt.
The context and its length prefix MAY be omitted.

If an identity is absent, it is omitted from the transcript entirely. For example,
if both A and B are absent, then TT = len(Context) || Context || len(M) || M || len(N) || N || len(X) || X || len(Y) || Y || len(Z) || Z || len(w0) || w0.
Likewise, if only A is absent, TT = len(Context) || Context || len(B) || B || len(M) || M || len(N) || N || len(X) || X || len(Y) || Y || len(Z) || Z || len(w0) || w0.
This must only be done for applications in which identities are implicit. Otherwise,
the protocol risks Unknown Key Share attacks (discussion of Unknown Key Share attacks
in a specific protocol is given in {{?I-D.ietf-mmusic-sdp-uks}}.

Upon completion of this protocol, A and B compute shared secrets Ka, Ke, KcA,
and KcB as specified in {{keys}}. B MUST send A a key confirmation message cB
so both parties agree upon these shared secrets. This confirmation message cB
is computed as a MAC over the received share (pA) using KcB. Specifically, B
computes cB = MAC(KcB, pA), where MAC is also a secure PRF. After receipt and
verification of B's confirmation message, A MUST send B a confirmation message
using a MAC computed equivalently except with the use of pB and KcA. Key
confirmation verification requires recomputation of the MAC and checking
for equality against that which was received.

# Key Schedule and Key Confirmation {#keys}

The protocol transcript TT, as defined in {{spake2plus}},
is unique and secret to A and B. Both parties use TT to
derive shared symmetric secrets Ke and Ka as Ke || Ka = Hash(TT). The length of each
key is equal to half of the digest output, e.g., |Ke| = |Ka| = 128 bits for SHA-256.
If the required key size is less than half the digest output, e.g. when using SHA-512
to derive two 128-bit keys, the digest output MAY be truncated.

Both endpoints use Ka to derive subsequent MAC keys for key confirmation messages.
Specifically, let KcA and KcB be the MAC keys used by A and B, respectively.
A and B compute them as KcA || KcB = KDF(nil, Ka, "ConfirmationKeys")

The length of each of KcA and KcB is equal to half of the KDF
output, e.g., |KcA| = |KcB| = 128 bits for HKDF-SHA256. If half of the KDF
output size exceeds the required key size for the chosen MAC, e.g. when using
HKDF-SHA512 for CMAC-AES-128, the KDF output MAY be truncated.

The resulting key schedule for this protocol, given transcript TT, is as follows.

~~~
TT -> Hash(TT) = Ka || Ke
Ka -> KDF(nil, Ka, "ConfirmationKeys") = KcA || KcB
~~~

A and B output Ke as the shared secret from the protocol. Ka and its derived keys (KcA and KcB)
are not used for anything except key confirmation.

# Ciphersuites {#Ciphersuites}

This section documents SPAKE2+ ciphersuite configurations. A ciphersuite
indicates a group, cryptographic hash algorithm, and pair of KDF and MAC functions, e.g.,
SPAKE2+-P256-SHA256-HKDF-HMAC. This ciphersuite indicates a SPAKE2+ protocol instance over
P-256 that uses SHA256 along with HKDF {{!RFC5869}} and HMAC {{!RFC2104}}
for G, Hash, KDF, and MAC functions, respectively.

| G              | Hash   | KDF    | MAC    |
|:---------------|:------:|:------:|:------:|
| P-256 | SHA256 {{!RFC6234}} | HKDF {{!RFC5869}} | HMAC {{!RFC2104}} |
| P-256 | SHA512 {{!RFC6234}} | HKDF {{!RFC5869}} | HMAC {{!RFC2104}} |
| P-384 | SHA256 {{!RFC6234}} | HKDF {{!RFC5869}} | HMAC {{!RFC2104}} |
| P-384 | SHA512 {{!RFC6234}} | HKDF {{!RFC5869}} | HMAC {{!RFC2104}} |
| P-521 | SHA512 {{!RFC6234}} | HKDF {{!RFC5869}} | HMAC {{!RFC2104}} |
| edwards25519 | SHA256 {{!RFC6234}} | HKDF {{!RFC5869}} | HMAC {{!RFC2104}} |
| edwards448 | SHA512 {{!RFC6234}} | HKDF {{!RFC5869}} | HMAC {{!RFC2104}} |
| P-256 | SHA256 {{!RFC6234}} | HKDF {{!RFC5869}} | CMAC-AES-128 {{!RFC4493}} |
| P-256 | SHA512 {{!RFC6234}} | HKDF {{!RFC5869}} | CMAC-AES-128 {{!RFC4493}} |

The following points represent permissible point generation seeds
for the groups listed in the Table above,
using the algorithm presented in {{pointgen}}.
These bytestrings are compressed points as in {{SEC1}}
for curves from {{SEC1}}.

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

SPAKE2+ appears in {{TDH}} and is proven secure in {{UCAnalysis}}.

Beyond the cofactor multiplication checks to ensure that elements received from
a peer are in the prime order subgroup of G, they also MUST be checked for group
membership as failure to properly validate group elements can lead to attacks.

The choices of random numbers MUST BE uniform. Randomly generated values (e.g., x and y)
MUST NOT be reused; such reuse may permit dictionary attacks on the password.

# Acknowledgements

Thanks to Ben Kaduk and Watson Ladd, from which this specification originally emanated.

--- back

# Algorithm used for Point Generation {#pointgen}

This section describes the algorithm that was used to generate
the points (M) and (N) in the table in {{Ciphersuites}}.

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
the P256-SHA256-HKDF-HMAC/CMAC ciphersuite. (Choice of PBKDF is omitted
and values for w and w0,w1 are provided directly.) All points are
encoded using the uncompressed format, i.e., with a 0x04 octet
prefix, specified in {{SEC1}} A and B identity strings
are provided in the protocol invocation.

~~~
[Context=b'SPAKE2+-P256-SHA256-HKDF-HMAC draft-01']
[A=b'client']
[B=b'server']
w0 = 0x1d122d5b59da10c389f4951b41abc18ed1919a24c04ede960bcf88dbc4c69
946
w1 = 0xf327601d0c6cc3071b449555591dc01531528db7b887264bb4515630a6430
d08
L = 0x0413c6c51ae6fcf717e626f520dd6d60135062220241516c2e522589c08775
a264a6548cb85b9a9d1369517829b8978d0ca5d11059c7d0beeb22c490bdcce4a83d
x = 0x5f6b46fb2ea1910d22faf099d77e1d32b7794d38f69933c55075e50e9158a2
5f
X = 0x043d0aedfe82808e4ef731cab5f4db9db427d95692bb3c5be5698071765c11
3836b81a7f85c6eed46a073a9fc5049e413b0e75d895d0e622aafa4c0614b3094b45
y = 0x10c2a67d006d5b44d9841f878dc049abdec1b324fc7c15b58af45726c15a59
05
Y = 0x040a1e796a0fff35a17a1c5ca8c8efe27143f2046727ec5ec763c83ac557be
04ab05d9f86e3aea08c1718eb26153fb3302ed67b1d65e7fbda8a40a0db2998399ba
Z = 0x04dcda70ec5a997386fd8303c38c94760033a8f4de515534792d1b9cefc10f
7aaa5af8ee2212cec16fc6c391b95659ad13c4f0b529a40ccee7cddd3d8568c76b8f
V = 0x04225ec3195304e09fb49ee8fa0c366cacda2fb2518510f7d51c9dbcd2fb87
fbf25156d66926c14bbd3a889d294433fb15c028e660ba506ca8324b48b1153882dd
TT = 0x26000000000000005350414b45322b2d503235362d5348413235362d484b4
4462d484d41432064726166742d30310600000000000000636c69656e74060000000
0000000736572766572410000000000000004886e2f97ace46e55ba9dd7242579f29
93b64e16ef3dcab95afd497333d8fa12f5ff355163e43ce224e0b0e65ff02ac8e5c7
be09419c785e0ca547d55a12e2d20410000000000000004d8bbd6c639c62937b04d9
97f38c3770719c629d7014d49a24b4f98baa1292b4907d60aa6bfade45008a636337
f5168c64d9bd36034808cd564490b1e656edbe74100000000000000043d0aedfe828
08e4ef731cab5f4db9db427d95692bb3c5be5698071765c113836b81a7f85c6eed46
a073a9fc5049e413b0e75d895d0e622aafa4c0614b3094b454100000000000000040
a1e796a0fff35a17a1c5ca8c8efe27143f2046727ec5ec763c83ac557be04ab05d9f
86e3aea08c1718eb26153fb3302ed67b1d65e7fbda8a40a0db2998399ba410000000
000000004dcda70ec5a997386fd8303c38c94760033a8f4de515534792d1b9cefc10
f7aaa5af8ee2212cec16fc6c391b95659ad13c4f0b529a40ccee7cddd3d8568c76b8
f410000000000000004225ec3195304e09fb49ee8fa0c366cacda2fb2518510f7d51
c9dbcd2fb87fbf25156d66926c14bbd3a889d294433fb15c028e660ba506ca8324b4
8b1153882dd20000000000000001d122d5b59da10c389f4951b41abc18ed1919a24c
04ede960bcf88dbc4c69946
Ka = 0x22896ae5401f95e4e9664614d4638e45
Ke = 0x2727c89bc90ceafd092af9e08194a626
KcA = 0x73786927130e6761ce0f5ac3afd3c9e7
KcB = 0x1bcffeca2ef561c90053bae76d0bdb82
HMAC(KcA, Y) = 0x73a7186533c5de2f8414f4e6bd778aa6a1b648635bee9345e0e
74b5de9ff3ad8
HMAC(KcB, X) = 0xf6eebbcb769ea9f19a2d78833ff99b0f12edfe8e2039eed22ca
06c8ca691029d
CMAC(KcA, Y) = 0x6e84b5d8e76bb9a6bf8284eef19af8e4
CMAC(KcB, X) = 0xd84c858f7e75b2a8caadc5f8b3c747fc

[Context=b'SPAKE2+-P256-SHA256-HKDF-HMAC draft-01']
[A=b'client']
[B=b'']
w0 = 0x1d122d5b59da10c389f4951b41abc18ed1919a24c04ede960bcf88dbc4c69
946
w1 = 0xf327601d0c6cc3071b449555591dc01531528db7b887264bb4515630a6430
d08
L = 0x0413c6c51ae6fcf717e626f520dd6d60135062220241516c2e522589c08775
a264a6548cb85b9a9d1369517829b8978d0ca5d11059c7d0beeb22c490bdcce4a83d
x = 0x74a64f7eea5fdcf8df4a1a87b166ee5afd58eb75d7dd25c60dee4254c2f423
24
X = 0x04eab5486815aab679e34a4a17274b0f93f635e4c5b87e2c3cd4e552682e65
acc0482faf463f2e597687024ebfca8ed27b214c2880c5c66c3392a7525421ef303d
y = 0xda2f5fe8d796447e656ee6479d43b36cc5880eb0d61022f29a7d75143edbaa
cc
Y = 0x040413235d6b2cda331b7990be950c8ab5031c16ac569453740237f41a7ca3
ba7adcfcf69563ee4d96fbe3622bf6886f298f7b0a6c8990abfa3c2f700d692e6dd8
Z = 0x04dec9d765a94b7fa470d8c180a66fd0f83c2577128ed50b6237a31bef3f03
e5d158475da66501d1ede42ad69aa98fa047dc56c70ef00e53b159cc3eae8a5e8b1d
V = 0x0405edeebbf46cf1c7e710d8ae90f09673d48255266ffe040002871448f0f5
43ca649d944e83f5b54311e2d4199f77c4a013e09b5658976833873f4f3eb2aca6f4
TT = 0x26000000000000005350414b45322b2d503235362d5348413235362d484b4
4462d484d41432064726166742d30310600000000000000636c69656e74410000000
000000004886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8
fa12f5ff355163e43ce224e0b0e65ff02ac8e5c7be09419c785e0ca547d55a12e2d2
0410000000000000004d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24
b4f98baa1292b4907d60aa6bfade45008a636337f5168c64d9bd36034808cd564490
b1e656edbe7410000000000000004eab5486815aab679e34a4a17274b0f93f635e4c
5b87e2c3cd4e552682e65acc0482faf463f2e597687024ebfca8ed27b214c2880c5c
66c3392a7525421ef303d4100000000000000040413235d6b2cda331b7990be950c8
ab5031c16ac569453740237f41a7ca3ba7adcfcf69563ee4d96fbe3622bf6886f298
f7b0a6c8990abfa3c2f700d692e6dd8410000000000000004dec9d765a94b7fa470d
8c180a66fd0f83c2577128ed50b6237a31bef3f03e5d158475da66501d1ede42ad69
aa98fa047dc56c70ef00e53b159cc3eae8a5e8b1d41000000000000000405edeebbf
46cf1c7e710d8ae90f09673d48255266ffe040002871448f0f543ca649d944e83f5b
54311e2d4199f77c4a013e09b5658976833873f4f3eb2aca6f420000000000000001
d122d5b59da10c389f4951b41abc18ed1919a24c04ede960bcf88dbc4c69946
Ka = 0x22493b4f78b6229b448c98736fd605b8
Ke = 0x8be2a60c7078b6997f3937fa17e5884a
KcA = 0x32c381223376dd3632e553019ce10dca
KcB = 0x4c78e86fa1a192ed01306a07023f85d1
HMAC(KcA, Y) = 0x440ac2b4789536e480b2223a27c6a1e2c18557a00a21b611421
249de1b4e34ad
HMAC(KcB, X) = 0x2d7e4cc1211d03a337fe639afe58c5170c3691f0d9704f3af90
1c76014f50013
CMAC(KcA, Y) = 0x2ad83751922507d8877a58d0483b72c0
CMAC(KcB, X) = 0x301e6ad5ef44bac5bbe0cbdb60c8f5fd

[Context=b'SPAKE2+-P256-SHA256-HKDF-HMAC draft-01']
[A=b'']
[B=b'server']
w0 = 0x1d122d5b59da10c389f4951b41abc18ed1919a24c04ede960bcf88dbc4c69
946
w1 = 0xf327601d0c6cc3071b449555591dc01531528db7b887264bb4515630a6430
d08
L = 0x0413c6c51ae6fcf717e626f520dd6d60135062220241516c2e522589c08775
a264a6548cb85b9a9d1369517829b8978d0ca5d11059c7d0beeb22c490bdcce4a83d
x = 0x06fd619439aa6b750f23db1d062191cac29ed7d441e9aed49afbcf30d1dd6f
0b
X = 0x04680be9cb39e82c1a739496352155d85a9a8203f568e4c0a3a2d7d779b808
cd0181522844e3d5478777ad4559bb684f16eacc2f379e18fca2bba9b070fcc56050
y = 0x9741527e258c36dcca7cfb936c981b5425ba31943eaefd1a46444c4252f481
d7
Y = 0x042e454c7d6d6f713dedd28c6c26ad5f3c3c396db47a42267c719b375f4f3c
b024e01decda2a999844bb96d7931ea07b5564919109999ff25662bcacf5c52d4a4d
Z = 0x04c6327206afd63a45ff8d99ddaad9fec819d16f9928e591f0f103c2b8bd3b
c84027ec4e4c7379322ba9a4d9edcb1034df34dfc43da4a9aee72f64488777017ebb
V = 0x04311f3d388eaeda6ae6fa7643910f59cdbf6b8408d14262c710e9d480c8ee
245d88ccd75d87e01aae830c92a112c301322d40bc25e7358410714e8d8e415f3a19
TT = 0x26000000000000005350414b45322b2d503235362d5348413235362d484b4
4462d484d41432064726166742d30310600000000000000736572766572410000000
000000004886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8
fa12f5ff355163e43ce224e0b0e65ff02ac8e5c7be09419c785e0ca547d55a12e2d2
0410000000000000004d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24
b4f98baa1292b4907d60aa6bfade45008a636337f5168c64d9bd36034808cd564490
b1e656edbe7410000000000000004680be9cb39e82c1a739496352155d85a9a8203f
568e4c0a3a2d7d779b808cd0181522844e3d5478777ad4559bb684f16eacc2f379e1
8fca2bba9b070fcc560504100000000000000042e454c7d6d6f713dedd28c6c26ad5
f3c3c396db47a42267c719b375f4f3cb024e01decda2a999844bb96d7931ea07b556
4919109999ff25662bcacf5c52d4a4d410000000000000004c6327206afd63a45ff8
d99ddaad9fec819d16f9928e591f0f103c2b8bd3bc84027ec4e4c7379322ba9a4d9e
dcb1034df34dfc43da4a9aee72f64488777017ebb410000000000000004311f3d388
eaeda6ae6fa7643910f59cdbf6b8408d14262c710e9d480c8ee245d88ccd75d87e01
aae830c92a112c301322d40bc25e7358410714e8d8e415f3a1920000000000000001
d122d5b59da10c389f4951b41abc18ed1919a24c04ede960bcf88dbc4c69946
Ka = 0xf4de871a14675709527f987aa8e60451
Ke = 0xc93899f43972002a9a02a832f497ce0e
KcA = 0xb23a96d573d732c76613a7bd70cf7454
KcB = 0x9963f481c01f7818a62981906253c06e
HMAC(KcA, Y) = 0x2ea37faee3281ccb8f3541844fe8f8ad9b78101321bdb096ff6
7a76f0453106f
HMAC(KcB, X) = 0x1d5e9157a448dab6eeeb53b557a431693428cc26b51f22c1167
7679f616cc64b
CMAC(KcA, Y) = 0x4bd69d15f00ffaab8b58d2217a09d1f1
CMAC(KcB, X) = 0xd2a10cf4597b9ed025e1c0f29eb9b03c

[Context=b'SPAKE2+-P256-SHA256-HKDF-HMAC draft-01']
[A=b'']
[B=b'']
w0 = 0x1d122d5b59da10c389f4951b41abc18ed1919a24c04ede960bcf88dbc4c69
946
w1 = 0xf327601d0c6cc3071b449555591dc01531528db7b887264bb4515630a6430
d08
L = 0x0413c6c51ae6fcf717e626f520dd6d60135062220241516c2e522589c08775
a264a6548cb85b9a9d1369517829b8978d0ca5d11059c7d0beeb22c490bdcce4a83d
x = 0xd494294c880709c20ffc64cf12397783ac37c36c53222f16ef9eee54302a90
a7
X = 0x04b2add0e0618524ec9b53cd6c559033e628ea239130c5b37684b09ddd3c84
c00eed555ba85e5267bd001c2879d619d4b1ee069fe29d9273d936cc98d30244a1ab
y = 0x5696fe31a1fe91e75617d679ef268e1324861815364f4dd5c5a5f405a21ded
9d
Y = 0x0479db3a3dbb0d16916707b80971c90c9d19f4edfbc27324696adfb044be8e
b8d4cfbc2f28536fc1f4f138a7219b123cab46d9a617a5077857a9695bc5b012832f
Z = 0x049b6a69d523e818f9ce12d042ccfe835fd5b78ed4b59b42bcea792f7110d7
a4e67d5477f02331a85c5e6fc765c4868383ffcad14269d32a1fe4ebb9ac6c120fa1
V = 0x04d42ff3ad61e87a275a0dce28f2659b170ff1869bd7b350a57ed32f13c5be
255ec24ef3cf4b0a35d0b4f0dd3c6417da937193dd89a128cb1f08580dd096b70de8
TT = 0x26000000000000005350414b45322b2d503235362d5348413235362d484b4
4462d484d41432064726166742d3031410000000000000004886e2f97ace46e55ba9
dd7242579f2993b64e16ef3dcab95afd497333d8fa12f5ff355163e43ce224e0b0e6
5ff02ac8e5c7be09419c785e0ca547d55a12e2d20410000000000000004d8bbd6c63
9c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b4907d60aa6bfade
45008a636337f5168c64d9bd36034808cd564490b1e656edbe741000000000000000
4b2add0e0618524ec9b53cd6c559033e628ea239130c5b37684b09ddd3c84c00eed5
55ba85e5267bd001c2879d619d4b1ee069fe29d9273d936cc98d30244a1ab4100000
0000000000479db3a3dbb0d16916707b80971c90c9d19f4edfbc27324696adfb044b
e8eb8d4cfbc2f28536fc1f4f138a7219b123cab46d9a617a5077857a9695bc5b0128
32f4100000000000000049b6a69d523e818f9ce12d042ccfe835fd5b78ed4b59b42b
cea792f7110d7a4e67d5477f02331a85c5e6fc765c4868383ffcad14269d32a1fe4e
bb9ac6c120fa1410000000000000004d42ff3ad61e87a275a0dce28f2659b170ff18
69bd7b350a57ed32f13c5be255ec24ef3cf4b0a35d0b4f0dd3c6417da937193dd89a
128cb1f08580dd096b70de820000000000000001d122d5b59da10c389f4951b41abc
18ed1919a24c04ede960bcf88dbc4c69946
Ka = 0xe36bb51465b984b813e130a855f73e66
Ke = 0xcdf16b3830f107900b43ed32f4136d25
KcA = 0xabd264c8b7eacdcc24e2746377d81592
KcB = 0x266cd21228d3f184cf84495beae21a58
HMAC(KcA, Y) = 0x54d0e59863cb2ebd6e82cb13bb5e8ae00b224166f17cf7d0166
50c4acc88a5f0
HMAC(KcB, X) = 0xb4137d139eeb1149b23f8fc3e85c0554cec6eab2b1593fbc242
dc91efdf86b2f
CMAC(KcA, Y) = 0x240394f3b57760367522cedb32569da2
CMAC(KcB, X) = 0xc1396d4ade8ef4d27c2ac62465cedcb6
~~~
