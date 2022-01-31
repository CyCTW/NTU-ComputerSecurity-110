from pwn import *
r = remote('34.90.151.171', 1337)
cur = 0
mp = {}
cnt = 0
i = 0
# for i in range(100):
while i < 100:
  a = r.recvuntil(f"doctor {cur}\n".encode()) # >
  print(a)
  if cnt == 49 and cur in mp:
    real = mp[cur]
    # guess as many as possible
    r.sendline(f'{real}'.encode())   
    res = r.recvline()[:-1]
    num = int(res.split()[-1])
    i -= 1
    print(res)
  else:
    r.sendline(f'{i}'.encode())
    res = r.recvline()[:-1]
    num = int(res.split()[-1])
    print(i)
    # store doctor no.: vaccan no.
    mp[num] = i
    print(res)
  cnt += 1
  i += 1
  if num == cur:
    # find!
    a = r.recvline()
    print(a)
    cur += 1
    cnt = 0
print("len: ", len(mp))
print("Fina all elements!")



# find all elements, crack this
for i in range(cur, 100):
  a = r.recvuntil(f"doctor {cur}\n".encode()) # >
  print(a)
  real = mp[cur]
  print("Real: ", real)
  r.sendline(f'{real}'.encode())   
  res = r.recvline()[:-1]
  num = int(res.split()[-1])
  print(res)
  if num == cur:
    cur += 1
  if cur == 100:
    for j in range(10):
      a = r.recvline()
      print(a)

# 98, 16, 79, 32, 85
# niteCTF{Pr0b4b1l1tY_c4n_5aVe_L1v3s}

# Choose your door, doctor 0
# 18
# Vaccine for doctor: 0
# You live to see another day. Or do you ? :)
