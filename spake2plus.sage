# sage -pip install pycryptodome
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256, HMAC, CMAC

from struct import *

# P-256 constants and helper functions
px = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
py = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5

p256 = 2^256 - 2^224 + 2^192 + 2^96 - 1
b256 = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b

FF = GF(p256)
EC = EllipticCurve([FF(p256 - 3), FF(b256)])
P = EC(FF(px), FF(py))

# seed: 1.2.840.10045.3.1.7 point generation seed (M)
mx = 0x886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f
my = 0x5ff355163e43ce224e0b0e65ff02ac8e5c7be09419c785e0ca547d55a12e2d20

# seed: 1.2.840.10045.3.1.7 point generation seed (N)
nx = 0xd8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49
ny = 0x07d60aa6bfade45008a636337f5168c64d9bd36034808cd564490b1e656edbe7

M = EC(FF(mx), FF(my))
N = EC(FF(nx), FF(ny))

def wrap_print(arg, *args):
    line_length = 68
    string = arg + " " + " ".join(args)
    for hunk in (string[0+i:line_length+i] for i in range(0, len(string), line_length)):
        if hunk and len(hunk.strip()) > 0:
            print(hunk)

def print_integer(name, x):
    wrap_print(name + ' = 0x' + format(x, 'x').zfill(64))

def encode_point(point):
    return '04' + format(int(point[0]), 'x').zfill(64) + format(int(point[1]), 'x').zfill(64)

def print_point(name, point):
    wrap_print(name + ' = 0x' + encode_point(point))

def pack_point(point):
    return pack_len(bytes.fromhex(encode_point(point)))

def pack_len(bytes):
    return pack('<Q', len(bytes)) + bytes

def pack_string(s):
    return pack_len(s)

def hkdf(ikm, info):
    return HKDF(ikm, 32, None, SHA256, 1, context=info)

def hmac(k, m):
    h = HMAC.new(k, digestmod=SHA256)
    h.update(m)
    return h.hexdigest()

def cmac(k, m):
    c = CMAC.new(k, ciphermod=AES)
    c.update(m)
    return c.hexdigest()

def derive_keys(TT):
    # K_auth || K_enc = Hash(TT)
    sk = SHA256.new(data=TT).digest()
    K_auth = sk[:16]
    K_enc = sk[16:]
    wrap_print('K_auth = 0x' + K_auth.hex())
    wrap_print('K_enc = 0x' + K_enc.hex())

    # KDF(nil, K_auth, "ConfirmationKeys") = KcA || KcB
    ck = hkdf(K_auth, b'ConfirmationKeys')
    K_confirmP = ck[:16]
    K_confirmV = ck[16:]
    wrap_print('K_confirmP = 0x' + K_confirmP.hex())
    wrap_print('K_confirmV = 0x' + K_confirmV.hex())

    return K_enc, K_confirmP, K_confirmV

def spake2plus(A, B):
    # Print w0 and w1
    print_integer('w0', w0)
    print_integer('w1', w1)

    # B generates L
    L = w1 * P
    print_point('L', L)

    # A generates key share X
    x = int(FF.random_element())
    print_integer('x', x)
    X = int(x) * P + w0 * M
    print_point('shareP', X)

    # B generates key share Y
    y = int(FF.random_element())
    print_integer('y', y)
    Y = int(y) * P + w0 * N
    print_point('shareV', Y)

    # A computes shared keys Z, V
    Z = x * (Y - w0 * N)
    V = w1 * (Y - w0 * N)
    print_point('Z', Z)
    print_point('V', V)

    # B computes shared keys Z, V
    assert Z == y * (X - w0 * M)
    assert V == y * L

    #  TT = len(Context) || Context
    #   || len(idProver) || idProver
    #   || len(idVerifier) || idVerifier
    #   || len(M) || M
    #   || len(N) || N
    #   || len(shareP) || shareP
    #   || len(shareV) || shareV
    #   || len(Z) || Z
    #   || len(V) || V
    #   || len(w0) || w0
    TT = pack_string(Context)
    TT += pack_string(A)
    TT += pack_string(B)
    TT += pack_point(M)
    TT += pack_point(N)
    TT += pack_point(X)
    TT += pack_point(Y)
    TT += pack_point(Z)
    TT += pack_point(V)
    TT += pack_len(bytes.fromhex(format(w0, 'x')))
    wrap_print('TT = 0x' + TT.hex())

    # Derive key schedule
    Ke, K_confirmP, K_confirmV = derive_keys(TT)

    # MAC = HMAC(K_confirmP/K_confirmV, shareV/shareP)
    wrap_print('HMAC(K_confirmP, shareV) = 0x' + hmac(K_confirmP, bytes.fromhex(encode_point(Y))))
    wrap_print('HMAC(K_confirmV, shareP) = 0x' + hmac(K_confirmV, bytes.fromhex(encode_point(X))))

    # MAC = CMAC(K_confirmP/K_confirmV, shareV/shareP)
    wrap_print('CMAC(K_confirmP, shareV) = 0x' + cmac(K_confirmP, bytes.fromhex(encode_point(Y))))
    wrap_print('CMAC(K_confirmV, shareP) = 0x' + cmac(K_confirmV, bytes.fromhex(encode_point(X))))

# Context for domain separation.
Context = b'SPAKE2+-P256-SHA256-HKDF Test Vectors'

# w0s || w1s = PBKDF(len(pw) || pw || len(A) || A || len(B) || B)
# w0 = w0s (mod p) and w1 = w1s (mod p)
w0 = int(FF.random_element())
w1 = int(FF.random_element())

# Set A and B to None if identities are implicit.
prover_identities = [b'client', b'']
verifier_identities = [b'server', b'']

print("~~~")
for prover in prover_identities:
    for verifier in verifier_identities:
        wrap_print('\n[Context=%s]' % (Context))
        wrap_print('[idProver=%s]' % (prover))
        wrap_print('[idVerifier=%s]' % (verifier))
        spake2plus(prover, verifier)
print("~~~")