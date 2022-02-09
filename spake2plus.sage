# sage -pip install pycryptodome
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256, SHA512, HMAC, CMAC

from struct import *
from collections import namedtuple

Curve = namedtuple(
    "BaseCurve",
    "ff nbytes P M N",
)

# P-256 constants
p256 = 2^256 - 2^224 + 2^192 + 2^96 - 1
b256 = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b

FF_256 = GF(p256)
EC_256 = EllipticCurve([FF_256(p256 - 3), FF_256(b256)])
XY_256 = lambda x, y: EC_256(FF_256(x), FF_256(y))

P256 = Curve(
    ff = FF_256,
    nbytes = 32,
    P = XY_256(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
               0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5),
    # seed: 1.2.840.10045.3.1.7 point generation seed (M)
    M = XY_256(0x886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f,
               0x5ff355163e43ce224e0b0e65ff02ac8e5c7be09419c785e0ca547d55a12e2d20),
    # seed: 1.2.840.10045.3.1.7 point generation seed (N)
    N = XY_256(0xd8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49,
               0x07d60aa6bfade45008a636337f5168c64d9bd36034808cd564490b1e656edbe7)
)

# P-384 constants
p384 = 2^384 - 2^128 - 2^96 + 2^32 - 1
b384 = 0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef

FF_384 = GF(p384)
EC_384 = EllipticCurve([FF_384(p384 - 3), FF_384(b384)])
XY_384 = lambda x, y: EC_384(FF_384(x), FF_384(y))

P384 = Curve(
    ff = FF_384,
    nbytes = 48,
    P = XY_384(0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7,
               0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f),
    # seed: 1.3.132.0.34 point generation seed (M)
    M = XY_384(0x0ff0895ae5ebf6187080a82d82b42e2765e3b2f8749c7e05eba366434b363d3dc36f15314739074d2eb8613fceec2853,
               0x97592c55797cdd77c0715cb7df2150220a0119866486af4234f390aad1f6addde5930909adc67a1fc0c99ba3d52dc5dd),
    # seed: 1.3.132.0.34 point generation seed (N)
    N = XY_384(0xc72cf2e390853a1c1c4ad816a62fd15824f56078918f43f922ca21518f9c543bb252c5490214cf9aa3f0baab4b665c10,
               0xc38b7d7f4e7f320317cd717315a797c7e02933aef68b364cbf84ebc619bedbe21ff5c69ea0f1fed5d7e3200418073f40)
)

# P-521 constants
p521 = 2^521 - 1
b521 = 0x051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00

FF_521 = GF(p521)
EC_521 = EllipticCurve([FF_521(p521 - 3), FF_521(b521)])
XY_521 = lambda x, y: EC_521(FF_521(x), FF_521(y))

P521 = Curve(
    ff = FF_521,
    nbytes = 66,
    P = XY_521(0x00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66,
               0x011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650),
    # seed: 1.3.132.0.35 point generation seed (M)
    M = XY_521(0x003f06f38131b2ba2600791e82488e8d20ab889af753a41806c5db18d37d85608cfae06b82e4a72cd744c719193562a653ea1f119eef9356907edc9b56979962d7aa,
               0x01bdd179a3d547610892e9b96dea1eab10bdd7ac5ae0cf75aa0f853bfd185cf782f894301998b11d1898ede2701dca37a2bb50b4f519c3d89a7d054b51fb84912192),
    # seed: 1.3.132.0.35 point generation seed (N)
    N = XY_521(0x00c7924b9ec017f3094562894336a53c50167ba8c5963876880542bc669e494b2532d76c5b53dfb349fdf69154b9e0048c58a42e8ed04cef052a3bc349d95575cd25,
               0x01c62bee650c9287a651bb75c7f39a2006873347b769840d261d17760b107e29f091d556a82a2e4cde0c40b84b95b878db2489ef760206424b3fe7968aa8e0b1f334)
)

def wrap_print(arg, *args):
    line_length = 68
    string = arg + " " + " ".join(args)
    for hunk in (string[0+i:line_length+i] for i in range(0, len(string), line_length)):
        if hunk and len(hunk.strip()) > 0:
            print(hunk)

def print_scalar(ec, name, x):
    wrap_print(name + ' = 0x' + format(x, 'x').zfill(ec.nbytes * 2))

def encode_point(ec, point):
    return '04' + format(int(point[0]), 'x').zfill(ec.nbytes * 2) + format(int(point[1]), 'x').zfill(ec.nbytes * 2)

def print_point(ec, name, point):
    wrap_print(name + ' = 0x' + encode_point(ec, point))

def pack_point(ec, point):
    return pack_len(bytes.fromhex(encode_point(ec, point)))

def pack_len(bytes):
    return pack('<Q', len(bytes)) + bytes

def pack_string(s):
    return pack_len(s)

def hkdf(di, ikm, info, n):
    return HKDF(ikm, di.digest_size, None, di, n, context=info)

def hmac(di, k, m):
    h = HMAC.new(k, digestmod=di)
    h.update(m)
    return h.hexdigest()

def cmac(k, m):
    c = CMAC.new(k, ciphermod=AES)
    c.update(m)
    return c.hexdigest()

def confirm_keys_hkdf(ec, di, K_main, X, Y):
    # K_confirmP || K_confirmV = KDF(nil, K_main, "ConfirmationKeys")
    K_confirmP, K_confirmV = hkdf(di, K_main, b'ConfirmationKeys', 2)
    wrap_print('K_confirmP = 0x' + K_confirmP.hex())
    wrap_print('K_confirmV = 0x' + K_confirmV.hex())

    # MAC = HMAC(K_confirmP/K_confirmV, shareV/shareP)
    wrap_print('HMAC(K_confirmP, shareV) = 0x' + hmac(di, K_confirmP, bytes.fromhex(encode_point(ec, Y))))
    wrap_print('HMAC(K_confirmV, shareP) = 0x' + hmac(di, K_confirmV, bytes.fromhex(encode_point(ec, X))))

def confirm_keys_cmac(ec, di, K_main, X, Y):
    # K_confirmP || K_confirmV = KDF(nil, K_main, "ConfirmationKeys")
    K_confirm = hkdf(di, K_main, b'ConfirmationKeys', 1)
    K_confirmP = K_confirm[0:16]
    K_confirmV = K_confirm[16:32]
    wrap_print('K_confirmP = 0x' + K_confirmP.hex())
    wrap_print('K_confirmV = 0x' + K_confirmV.hex())

    # MAC = CMAC(K_confirmP/K_confirmV, shareV/shareP)
    wrap_print('CMAC(K_confirmP, shareV) = 0x' + cmac(K_confirmP, bytes.fromhex(encode_point(ec, Y))))
    wrap_print('CMAC(K_confirmV, shareP) = 0x' + cmac(K_confirmV, bytes.fromhex(encode_point(ec, X))))

def spake2plus(ec, di, confirm_keys, ctx, idProver, idVerifier):
    # w0s || w1s = PBKDF(len(pw) || pw || len(A) || A || len(B) || B)
    # w0 = w0s (mod p) and w1 = w1s (mod p)
    w0 = int(ec.ff.random_element())
    w1 = int(ec.ff.random_element())

    # Print w0 and w1
    print_scalar(ec, 'w0', w0)
    print_scalar(ec, 'w1', w1)

    # Verifier generates L
    L = w1 * ec.P
    print_point(ec, 'L', L)

    # Prover generates key share X
    x = int(ec.ff.random_element())
    print_scalar(ec, 'x', x)
    X = int(x) * ec.P + w0 * ec.M
    print_point(ec, 'shareP', X)

    # Verifier generates key share Y
    y = int(ec.ff.random_element())
    print_scalar(ec, 'y', y)
    Y = int(y) * ec.P + w0 * ec.N
    print_point(ec, 'shareV', Y)

    # Prover computes shared keys Z, V
    Z = x * (Y - w0 * ec.N)
    V = w1 * (Y - w0 * ec.N)
    print_point(ec, 'Z', Z)
    print_point(ec, 'V', V)

    # Verifier computes shared keys Z, V
    assert Z == y * (X - w0 * ec.M)
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
    TT = pack_string(ctx)
    TT += pack_string(idProver)
    TT += pack_string(idVerifier)
    TT += pack_point(ec, ec.M)
    TT += pack_point(ec, ec.N)
    TT += pack_point(ec, X)
    TT += pack_point(ec, Y)
    TT += pack_point(ec, Z)
    TT += pack_point(ec, V)
    TT += pack_len(bytes.fromhex(format(w0, 'x').zfill(ec.nbytes * 2)))
    wrap_print('TT = 0x' + TT.hex())

    # K_main = Hash(TT)
    K_main = di.new(data=TT).digest()
    wrap_print('K_main = 0x' + K_main.hex())

    # Derive and confirm keys.
    confirm_keys(ec, di, K_main, X, Y)

    # K_shared = KDF(nil, K_main, "SharedKey")
    K_shared = hkdf(di, K_main, b'SharedKey', 1)
    wrap_print('K_shared = 0x' + K_shared.hex())

# Various ciphersuites.
suites = [
    (P256, SHA256, confirm_keys_hkdf, b'SPAKE2+-P256-SHA256-HKDF-SHA256 Test Vectors'),
    (P256, SHA512, confirm_keys_hkdf, b'SPAKE2+-P256-SHA512-HKDF-SHA512 Test Vectors'),
    (P384, SHA256, confirm_keys_hkdf, b'SPAKE2+-P384-SHA256-HKDF-SHA256 Test Vectors'),
    (P384, SHA512, confirm_keys_hkdf, b'SPAKE2+-P384-SHA512-HKDF-SHA512 Test Vectors'),
    (P521, SHA512, confirm_keys_hkdf, b'SPAKE2+-P521-SHA512-HKDF-SHA512 Test Vectors'),
    (P256, SHA256, confirm_keys_cmac, b'SPAKE2+-P256-SHA256-CMAC-AES-128 Test Vectors'),
    (P256, SHA512, confirm_keys_cmac, b'SPAKE2+-P256-SHA512-CMAC-AES-128 Test Vectors'),
]

prover = b'client'
verifier = b'server'

print("~~~")
for (ec, di, mac, ctx) in suites:
    wrap_print('\n[Context=%s]' % (ctx))
    wrap_print('[idProver=%s]' % (prover))
    wrap_print('[idVerifier=%s]' % (verifier))
    spake2plus(ec, di, mac, ctx, prover, verifier)
print("~~~")
