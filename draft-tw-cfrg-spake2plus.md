---
title: SPAKE2+, an Augmented PAKE
abbrev: spake2plus
docname: draft-bar-cfrg-spake2plus-latest
date:
category: info

ipr: trust200902
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

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
  RFC2119:
  TDH:
    title: The Twin-Diffie Hellman Problem and Applications
    seriesinfo: EUROCRYPT 2008.  Volume 4965 of Lecture notes in Computer Science, pages 127-145.  Springer-Verlag, Berlin, Germany.
    date: 2008
    authors:
        -
            ins: D. Cash
        -
            ins: E. Kiltz
        -
            ins: V. Shoup
  SEC1:
    title: Elliptic Curve Cryptography, Standards for Efficient Cryptography Group, ver. 2
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
The design of the protocol forces the adversary to recover the password from the verification value to successful execute the protocol.
Hence this protocol can be advantageously combined with a salted Password Hashing Function to increase the cost of the recovery and slow down attacks.
The verification value cannot be used directly to successfully run the protocol as a prover,
making this protocol more robust than balanced PAKEs which don't benefit from Password Hashing Functions to the same extend.

This augmented property is especially valuable in scenarios where the execution of the protocol is constrained
and the adversary can not query the salt of the password hash function ahead of the attack.
Constraints may consist in being in physical proximity through a local network or
when initiation of the protocol requires a first authentication factor.

This password-based key exchange protocol is compatible with any group.
It only relies on group operations making it simple and computationally efficient. It also has a security proof.
Predetermined parameters for a selection of commonly used groups are also provided.

This document has content split out from a related document specifying SPAKE2 {{!I-D.irtf-cfrg-spake2}}.

# Requirements Notation

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in {{RFC2119}}.

# Definition of SPAKE2+

## Offline Initialization {#setup}

Let G be a group in which the computational Diffie-Hellman (CDH)
problem is hard. Suppose G has order p*h where p is a large prime;
h will be called the cofactor. Let I be the unit element in
G, e.g., the point at infinity if G is an elliptic curve group. We denote the
operations in the group additively. We assume there is a representation of
elements of G as byte strings: common choices would be SEC1
uncompressed or compressed {{!SEC1}} for elliptic curve groups or big
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
PBKDF and hardness parameters selection for the PBKDF are out of scope of this document.
{{Ciphersuites}} specifies variants of KDF, MAC, and Hash
suitable for use with the protocols contained herein.

Let A and B be two parties. A and B may also have digital
representations of the parties' identities such as Media Access Control addresses
or other names (hostnames, usernames, etc). A and B may share Additional
Authenticated Data (AAD) of length at most 2^16 - 1 bits that is separate
from their identities which they may want to include in the protocol execution.
One example of AAD is a list of supported protocol versions if SPAKE2+ were
used in a higher-level protocol which negotiates the use of a particular PAKE. Including
this list would ensure that both parties agree upon the same set of supported protocols
and therefore prevent downgrade attacks.

## Protocol Flow {#flow}

SPAKE2+ is a two round protocol that establishes a shared secret with an
additional round for key confirmation. Prior to invocation, A and B are provisioned with
information such as the input password needed to run the protocol.
A preamble exchange may occur in order to communicate identities, protocol version and PBKDF parameters related to the verification value.
Details of the preamble phase is out of scope of this document.
During the first round, A, the prover, sends a public share pA
to B, the verifier, and B responds with its own public share pB. Both A and B then derive a shared secret
used to produce encryption and authentication keys. The latter are used during the second
round for key confirmation. ({{keys}} details the key derivation and
confirmation steps.) In particular, B sends a key confirmation message cB to A, and A responds
with its own key confirmation message cA. (Note that pB and cB MAY be sent in the same message.)
Both parties MUST NOT consider the protocol complete prior to receipt and validation of these key
confirmation messages.

This sample trace is shown below.

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

This protocol appears in {{?TDH}}. Let w0
and w1 be two integers derived by hashing the password pw with the identities
of the two participants, A and B. Specifically,
w0s || w1s = PBKDF(len(pw) || pw || len(A) || A || len(B) || B),
and then computing w0 = w0s mod p and w1 = w1s mod p.
If both identities A and B are absent, then w0s || w1s = PBKDF(pw), i.e.,
the length prefix is omitted as in {{setup}}.
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
B. Upon receipt of X, A computes h\*X and aborts if the result is equal
to I. B then selects y uniformly at random from the numbers in [0, p),
then computes Y=y\*P+w0\*N, and transmits pB=Y to A.

A computes Z as h\*x\*(Y-w0\*N), and V as h\*w1\*(Y-w0\*N). B computes Z as h\*y\*(X-
w0\*M) and V as h\*y\*L. Both share Z and V as common values. It is essential
that both Z and V be used in combination with the transcript to
derive the keying material. The protocol transcript encoding is shown below.

~~~
TT = len(A) || A || len(B) || B || len(X) || X
  || len(Y) || Y || len(Z) || Z || len(V) || V
  || len(w0) || w0
~~~

If an identity is absent, it is omitted from the transcript entirely. For example,
if both A and B are absent, then TT = len(X) || X || len(Y) || Y || len(Z) || Z || len(w0) || w0.
Likewise, if only A is absent, TT = len(B) || B || len(X) || X || len(Y) || Y || len(Z) || Z || len(w0) || w0.
This must only be done for applications in which identities are implicit. Otherwise,
the protocol risks Unknown Key Share attacks (discussion of Unknown Key Share attacks
in a specific protocol is given in {{?I-D.ietf-mmusic-sdp-uks}}.

Upon completion of this protocol, A and B compute shared secrets Ke, KcA, and KcB as
specified in {{keys}}. B MUST send A a key confirmation message Fb
so both parties agree upon these shared secrets. This confirmation message Fb
is computed as a MAC over the received share (pA) using KcB. Specifically, B
computes Fb = MAC(KcB, pA). After receipt and verification of B's confirmation
message, A MUST send B a confirmation message using a MAC computed equivalently
except with the use of pB and KcA. Key confirmation verification requires computing
F and checking for equality against that which was received.

# Key Schedule and Key Confirmation {#keys}

The protocol transcript TT, as defined in {{spake2plus}},
is unique and secret to A and B. Both parties use TT to
derive shared symmetric secrets Ke and Ka as Ke || Ka = Hash(TT). The length of each
key is equal to half of the digest output, e.g., |Ke| = |Ka| = 128 bits for SHA-256.

Both endpoints use Ka to derive subsequent MAC keys for key confirmation messages.
Specifically, let KcA and KcB be the MAC keys used by A and B, respectively.
A and B compute them as KcA || KcB = KDF(nil, Ka, "ConfirmationKeys" || AAD), where AAD
is the associated data each given to each endpoint, or nil (empty string)
if none was provided.
AAD may also include a string identifying the protocol, ciphersuite and all its parameters,
including the definition of the group, and the element M and N. It may be omitted.

The length of each of KcA and KcB is equal to half of the KDF
output, e.g., |KcA| = |KcB| = 128 bits for HKDF with SHA256.

The resulting key schedule for this protocol, given transcript TT and additional associated data AAD, is as follows.

~~~
TT  -> Hash(TT) = Ka || Ke
AAD -> KDF(nil, Ka, "ConfirmationKeys" || AAD) = KcA || KcB
~~~

A and B output Ke as the shared secret from the protocol. Ka and its derived keys (KcA and KcB)
are not used for anything except key confirmation.

# Ciphersuites {#Ciphersuites}

This section documents SPAKE2+ ciphersuite configurations. A ciphersuite
indicates a group, cryptographic hash algorithm, and pair of KDF and MAC functions, e.g.,
SPAKE2+-P256-SHA256-HKDF-HMAC. This ciphersuite indicates a SPAKE2+ protocol instance over
P-256 that uses SHA256 along with HKDF {{!RFC5869}} and HMAC {{!RFC2104}}
for G, Hash, KDF, and MAC functions, respectively.

The following points represent permissible point generation seeds
for the groups listed in the Table <xref target="spake2_ciphersuites"/>,
using the algorithm presented in {{pointgen}}.
These bytestrings are compressed points as in {{!SEC1}}
for curves from {{!SEC1}}.

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

SPAKE2+ appears in {{?TDH}} along with a path to a proof that
server compromise does not lead to password compromise under the DH assumption
(though the corresponding model excludes pre-computation attacks).

Elements received from a peer MUST be checked for group membership:
failure to properly validate group elements can lead to attacks. Beyond the cofactor
multiplication checks to ensure that these elements are in the prime order subgroup
of G, it is essential that endpoints verify received points are members of G.

The choices of random numbers MUST BE uniform. Randomly generated values (e.g., x and y)
MUST NOT be reused; such reuse may permit dictionary attacks on the password.

# Acknowledgements

Thanks to Ben Kaduk and Watson Ladd, from which this specification originally emanated.

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
(section 2.3.4 of {{!SEC1}}),
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
the P256-SHA256-HKDF-HMAC ciphersuite. (Choice of PBKDF is omitted
and values for w and w0,w1 are provided directly.) All points are
encoded using the uncompressed format, i.e., with a 0x04 octet
prefix, specified in <xref target="SEC1"/> A and B identity strings
are provided in the protocol invocation.

--- back

