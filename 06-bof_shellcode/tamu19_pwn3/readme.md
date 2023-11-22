# pwn3
Kiểm tra file binary:
```bash
┌──(grass㉿kali)-(~/pwn/insomiac/06-bof_shellcode/tamu19_pwn3)
└─$ file pwn3 
pwn3: ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=6ea573b4a0896b428db719747b139e6458d440a0, not stripped

┌──(grass㉿kali)-(~/pwn/insomiac/06-bof_shellcode/tamu19_pwn3)
└─$ pwn checksec pwn3 
[*] '/home/grass/pwn/insomiac/06-bof_shellcode/tamu19_pwn3/pwn3'
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX unknown - GNU_STACK missing
    PIE:      PIE enabled
    Stack:    Executable
    RWX:      Has RWX segments

┌──(grass㉿kali)-(~/pwn/insomiac/06-bof_shellcode/tamu19_pwn3)
└─$ ./pwn3 
Take this, you might need it on your journey 0xff8d6c4e!
aaaaaaaaaaa

```
Bài này có sử dụng PIE
Không sử dụng NX và không có stack canary nên có thể chèn shellcode vào bên trong stack.
Ta cũng biết được đây là file 32 bit

Decompile hàm main với ida:
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  setvbuf(stdout, 2, 0, 0);
  echo(&argc);
  return 0;
}
```
Không có gì ở đây cả, tiếp tục với hàm echo():
```c
int echo()
{
  char v1[294]; // [esp+Eh] [ebp-12Ah] BYREF

  printf("Take this, you might need it on your journey %p!\n", v1);
  return gets(v1);
}
```
Ta thấy trong hàm echo() ở đây xuất hiện gets(). Đây cũng là lỗ hổng của chương trình này vì gets() không kiểm tra số lượng kí tự ta cần nhập vào và từ đó có thể dẫn đến overflow.

Ta cũng thấy được hàm echo in ra luôn địa chỉ của v1. Do đó ta đã có thể bỏ qua bước tìm địa chỉ này.

Sử dụng gdb để tìm offset của $eip:
```bash
┌──(grass㉿kali)-(~/pwn/insomiac/06-bof_shellcode/tamu19_pwn3)
└─$ gdb-gef  ./pwn3 
Reading symbols from ./pwn3...
(No debugging symbols found in ./pwn3)
Error while writing index for `/home/grass/pwn/insomiac/06-bof_shellcode/tamu19_pwn3/pwn3': No debugging symbols
GEF for linux ready, type `gef' to start, `gef config' to configure
89 commands loaded and 5 functions added for GDB 13.2 in 0.00ms using Python engine 3.11
gef➤  disass echo
Dump of assembler code for function echo:
   0x0000059d <+0>:	push   ebp
   0x0000059e <+1>:	mov    ebp,esp
   0x000005a0 <+3>:	push   ebx
   0x000005a1 <+4>:	sub    esp,0x134
   0x000005a7 <+10>:	call   0x4a0 <__x86.get_pc_thunk.bx>
   0x000005ac <+15>:	add    ebx,0x1a20
   0x000005b2 <+21>:	sub    esp,0x8
   0x000005b5 <+24>:	lea    eax,[ebp-0x12a]
   0x000005bb <+30>:	push   eax
   0x000005bc <+31>:	lea    eax,[ebx-0x191c]
   0x000005c2 <+37>:	push   eax
   0x000005c3 <+38>:	call   0x410 <printf@plt>
   0x000005c8 <+43>:	add    esp,0x10
   0x000005cb <+46>:	sub    esp,0xc
   0x000005ce <+49>:	lea    eax,[ebp-0x12a]
   0x000005d4 <+55>:	push   eax
   0x000005d5 <+56>:	call   0x420 <gets@plt>
   0x000005da <+61>:	add    esp,0x10
   0x000005dd <+64>:	nop
   0x000005de <+65>:	mov    ebx,DWORD PTR [ebp-0x4]
   0x000005e1 <+68>:	leave
   0x000005e2 <+69>:	ret
End of assembler dump.
gef➤  b *echo+61
Breakpoint 1 at 0x5da
gef➤  r
...
gef➤  i f
Stack level 0, frame at 0xffffcf30:
 eip = 0x565555da in echo; saved eip = 0x5655561a
 called by frame at 0xffffcf50
 Arglist at 0xffffcf28, args: 
 Locals at 0xffffcf28, Previous frame's sp is 0xffffcf30
 Saved registers:
  ebx at 0xffffcf24, ebp at 0xffffcf28, eip at 0xffffcf2c
gef➤  search-pattern bumblebee
[+] Searching 'bumblebee' in memory
[+] In '[heap]'(0x56558000-0x5657a000), permission=rw-
  0x565581a0 - 0x565581ab  →   "bumblebee\n" 
[+] In '[stack]'(0xfffdd000-0xffffe000), permission=rwx
  0xffffcdfe - 0xffffce07  →   "bumblebee" 
gef➤  
```

Như vậy offset giữa input của chúng ta và ret address là:

```bash
┌──(grass㉿kali)-(~/pwn/insomiac/06-bof_shellcode/tamu19_pwn3)
└─$ python3
Python 3.11.6 (main, Oct  8 2023, 05:06:43) [GCC 13.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> hex(0xffffcf2c - 0xffffcdfe)
'0x12e'
```

Kết quả này khá hợp lí vì mảng của chúng ta có tới 294 phần tử, và có tới 2 giá trị saved register ở giữa input của chúng ta và ret address. Mà `294+4+4=0x12e`

Từ đó ta có chương trình exploit ở đây.