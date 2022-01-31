#!/bin/env python3 -u
import os
from pwn import *

from sage.all import *
from sage.matrix.berlekamp_massey import berlekamp_massey

def main(r):
  cur = 1.2
  b = []
  # 1. Get the 128 bit output of the LFSR
  for i in range(128):
    r.recvuntil(b"> ") # >
    r.sendline(b"1")
    res = float(r.recvline()[:].decode())
    # print(f"idx: {i}, res: {res}")
    if cur < res:
      # right
      b.append(GF(2)(1))
    else:
      # wrong
      b.append(GF(2)(0))
    cur = res

  P = berlekamp_massey(b)
  print("P: ", P)
  C = companion_matrix(P, format='bottom')
  idx = 128 - 64
  for i in range(500):
    next = C * vector(b[idx:idx + 64])
    num = next[63]

    r.recvuntil(b"> ") # >
    r.sendline(str(num).encode())
    res = float(r.recvline()[:].decode())
    # print("guess: ", num)
    # print("result: ", res)
    if res > 2.4:
      print("Success")
      a = r.recvrepeat(5000)
      print(a)
      return 1

    idx += 1
    b.append(num)

# try 10 times, not every time we can get 128 bit.
for _ in range(10):
  r = remote('edu-ctf.csie.org', 42069)

  try:
    main(r)
    r.close()
    break
  except EOFError:
    r.close()
    continue
  