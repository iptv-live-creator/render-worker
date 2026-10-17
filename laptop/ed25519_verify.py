# Pure-Python Ed25519 VERIFY only (RFC 8032 section 6 reference algorithm). No signing, no deps.
import hashlib
p = 2**255 - 19
q = 2**252 + 27742317777372353535851937790883648493
d = -121665 * pow(121666, p - 2, p) % p
I = pow(2, (p - 1) // 4, p)

def _inv(x): return pow(x, p - 2, p)

def _recover_x(y, sign):
    if y >= p: return None
    x2 = (y * y - 1) * _inv(d * y * y + 1) % p
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (p + 3) // 8, p)
    if (x * x - x2) % p != 0: x = x * I % p
    if (x * x - x2) % p != 0: return None
    if (x & 1) != sign: x = p - x
    return x

_gy = 4 * _inv(5) % p
_gx = _recover_x(_gy, 0)
G = (_gx, _gy, 1, _gx * _gy % p)

def _add(P, Q):
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % p
    B = (P[1] + P[0]) * (Q[1] + Q[0]) % p
    C = 2 * P[3] * Q[3] * d % p
    D = 2 * P[2] * Q[2] % p
    E, F, G_, H = B - A, D - C, D + C, B + A
    return (E * F % p, G_ * H % p, F * G_ % p, E * H % p)

def _mul(s, P):
    Q = (0, 1, 1, 0)
    while s > 0:
        if s & 1: Q = _add(Q, P)
        P = _add(P, P)
        s >>= 1
    return Q

def _eq(P, Q):
    if (P[0] * Q[2] - Q[0] * P[2]) % p != 0: return False
    return (P[1] * Q[2] - Q[1] * P[2]) % p == 0

def _decompress(b):
    if len(b) != 32: return None
    y = int.from_bytes(b, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None: return None
    return (x, y, 1, x * y % p)

def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    try:
        if len(public) != 32 or len(signature) != 64: return False
        A = _decompress(public)
        if A is None: return False
        Rs = signature[:32]
        R = _decompress(Rs)
        if R is None: return False
        s = int.from_bytes(signature[32:], "little")
        if s >= q: return False
        h = int.from_bytes(hashlib.sha512(Rs + public + message).digest(), "little") % q
        return _eq(_mul(s, G), _add(R, _mul(h, A)))
    except Exception:
        return False
