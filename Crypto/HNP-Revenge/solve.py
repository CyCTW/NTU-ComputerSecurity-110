from typing import Match
from pwn import *
from hashlib import sha256, md5
from ecdsa import SECP256k1
from Crypto.Util.number import *
from ecdsa.ecdsa import Public_key, Private_key, Signature
from sage.all import *
import math

E = SECP256k1
G, n = E.generator, E.order
H1, H2 = "aaaa", "bbbb"
K = 2**127
print("order: ", n)

def recv_options(r):
  r.recvline() # \n
  r.recvline() # (1
  r.recvline() # (2
  r.recvline() # (3
  
def create_sig(r, d):
  msg = "Kuruwa"
  h = sha256(msg.encode()).digest()

  pubkey = Public_key(G, d*G)
  prikey = Private_key(pubkey, d)
  k = int(md5(b'secret').hexdigest() + md5(long_to_bytes(prikey.secret_multiplier) + h).hexdigest(), 16)

  sig = prikey.sign(bytes_to_long(h), k)

  print(f'sig = ({sig.r}, {sig.s})')
  recv_options(r)
  r.sendline(b"2")
  r.recvuntil(b"username: ")
  r.sendline(b"Kuruwa")
  r.recvuntil(b"r: ")
  r.sendline(str(sig.r).encode())
  r.recvuntil(b"s: ")
  r.sendline(str(sig.s).encode())
  FLAG = r.recvline()
  print(FLAG)
  return FLAG

def send_request(r, data):
  recv_options(r)

  r.sendline(b"1")
  q = r.recvline()
  r.sendline(data.encode())
  q = r.recvline()
  # print("q: ", q)
  return int(q.split()[0][1:-1]), int(q.split()[1][:-1])


def solve_k(s1, s2, r1, r2, n):
  h1 = bytes_to_long(sha256(H1.encode()).digest())
  h2 = bytes_to_long(sha256(H2.encode()).digest())
  s = int(md5(b'secret').hexdigest(), 16) << 128
  t = -1*inverse_mod(s1, n)*s2*r1*inverse_mod(r2, n)
  u = (inverse_mod(s1, n)*r1*h2*inverse_mod(r2, n)) - (inverse_mod(s1, n)*h1)
  L = matrix(ZZ, [[n, 0, 0], [t, 1, 0], [u+s, -s, K]])
  LLL = L.LLL()
  
  k1 = -1
  for i in range(3):
    if abs(LLL[i][2]) == K:
      k1 = abs(LLL[i][0])+s
      break
  if k1 == -1:
    return 0
  d = (s1*k1-h1)*inverse_mod(r1, n)
  d %= n
  return d

def main():
  r = remote('edu-ctf.csie.org', 42074)
  # receive Public key
  q = r.recvline()
  Pa = int(q.split()[2][1:-1])
  Pb = int(q.split()[3][:-1])
  # print(Pa, Pb)

  r1, s1 = send_request(r, H1)
  r2, s2 = send_request(r, H2)
  # 1. solve parameter k using Lattice
  d = solve_k(s1, s2, r1, r2, n)
  if d == 0:
    return ""
  # print("d: ", d)
  # print("n: ", n)
  
  # 2. use d to compute signature of "Kuruwa"
  flag = create_sig(r, d)
  r.close()
  return str(flag)

cnt = 0
while(cnt < 50):
  flag = main()
  if flag.find("FLAG") != -1:
    break
  cnt+=1





