from sage.all import *
from collections import namedtuple
from Crypto.Util.number import inverse, bytes_to_long
import hashlib
import random

Point = namedtuple("Point", "x y")
O = 'INFINITY'

p = 9631668579539701602760432524602953084395033948174466686285759025897298205383
gx = 5664314881801362353989790109530444623032842167510027140490832957430741393367
gy = 3735011281298930501441332016708219762942193860515094934964869027614672869355
gx1 = 3829488417236560785272607696709023677752676859512573328792921651640651429215
gy1 = 7947434117984861166834877190207950006170738405923358235762824894524937052000

gx2 = 9587224500151531060103223864145463144550060225196219072827570145340119297428
gy2 = 2527809441042103520997737454058469252175392602635610992457770946515371529908

def linear_congruence(a, b, m):
  if b == 0:
      return 0

  if a < 0:
      a = -a
      b = -b

  b %= m
  while a > m:
      a -= m

  return (m * linear_congruence(m, -b, a) + b) // a
  
def is_on_curve(P):
    if P == O:
        return True
    else:
        return (P.y**2 - (P.x**3 + a*P.x + b)) % p == 0 and 0 <= P.x < p and 0 <= P.y < p

def point_inverse(P):
    if P == O:
        return P
    return Point(P.x, -P.y % p)

def point_addition(P, Q):
    if P == O:
        return Q
    elif Q == O:
        return P
    elif Q == point_inverse(P):
        return O
    else:
        if P == Q:
            s = (3*P.x**2 + a)*inverse(2*P.y, p) % p
        else:
            s = (Q.y - P.y) * inverse((Q.x - P.x), p) % p
    Rx = (s**2 - P.x - Q.x) % p
    Ry = (s*(P.x - Rx) - P.y) % p
    R = Point(Rx, Ry)
    assert is_on_curve(R)
    return R

def point_multiply(P, d):
    bits = bin(d)[2:]
    Q = O
    for bit in bits:
        Q = point_addition(Q, Q)
        if bit == '1':
            Q = point_addition(Q, P)
    assert is_on_curve(Q)
    return Q

def phi(P, alpha, beta):
  return (P.y + ( sqrt(alpha - beta) * (P.x - alpha) )) / (P.y - ( sqrt(alpha - beta) * (P.x - alpha) ))

# 1. Solve Elliptic curve parameter: a, b
# gy**2  ==  (gx**3 + gx*x + y), 
# gy1**2 == (gx1**3 + gx1*x + y)
# -) (gy**2 - gy1**2) - (gx**3 - gx1**3) = (gx-gx1)*x
ca = gx-gx1
cb = (gy**2 - gy1**2) - (gx**3 - gx1**3)
a = linear_congruence(ca,cb,p)
print("a: ", a)

ca = gx - gx1
cb = (gy1**2 * gx) - (gy**2 * gx1) - gx1 * gx * (gx1**2 - gx**2)
b = linear_congruence(ca, cb, p)
print("b: ", b)

res = (4*(a**3) + 27*(b**2)) % p
# assert singular
assert(res == 0)

# 2. Use Singular property to compute alpha, beta
w = PolynomialRing(GF(p), 'w').gen()
f = w**3 + a*w + b
F = f.roots()
print("Roots: ", F)
alpha = F[1][0]
beta = F[0][0]

# 3. Pohlig-Hellman
G = Point(gx, gy)
A = Point(gx1, gy1)
B = Point(gx2, gy2)

order = p-1
f = factor(order)
f = [fi[0] for fi in f]
d = []
ba = phi(G, alpha, beta)
bb = phi(A, alpha, beta)
for fi in f:
    gi = pow(ba, order // fi, p)
    hi = pow(bb, order // fi, p)
    di = bsgs(gi, hi, operation='*', bounds=(0, fi))
    d.append(di)

da = crt(d, f)
print("da: ", da)

#Encryption
k = point_multiply(B, da).x

k = hashlib.sha512(str(k).encode('ascii')).digest()
enc = "1536c5b019bd24ddf9fc50de28828f727190ff121b709a6c63c4f823ec31780ad30d219f07a8c419c7afcdce900b6e89b37b18b6daede22e5445eb98f3ca2e40"
fb = bytes.fromhex(enc)

flag = bytes(k[i] ^ fb[i] for i in range(len(k)))
print("Flag: ", flag)
