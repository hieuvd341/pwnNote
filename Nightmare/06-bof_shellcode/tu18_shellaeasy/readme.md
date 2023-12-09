# shellaeasy
- Kiểm tra file binary
```bash
┌──(grass㉿kali)-(~/pwn/insomiac/06-bof_shellcode/tu18_shellaeasy)
└─$ file shella-easy 
shella-easy: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=38de2077277362023aadd2209673b21577463b66, not stripped
┌──(grass㉿kali)-(~/pwn/insomiac/06-bof_shellcode/tu18_shellaeasy)
└─$ pwn checksec shella-easy 
[*] '/home/grass/pwn/insomiac/06-bof_shellcode/tu18_shellaeasy/shella-easy'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX unknown - GNU_STACK missing
    PIE:      No PIE (0x8048000)
    Stack:    Executable
    RWX:      Has RWX segments
┌──(grass㉿kali)-(~/pwn/insomiac/06-bof_shellcode/tu18_shellaeasy)
└─$ ./shella-easy 
Yeah I'll have a 0xff8d2130 with a side of fries thanks
huh
```

decompile chương trình này với ida, hàm main trông như sau:
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4[64]; // [esp+0h] [ebp-48h] BYREF
  int v5; // [esp+40h] [ebp-8h]

  setvbuf(stdout, 0, 2, 20);
  setvbuf(stdin, 0, 2, 20);
  v5 = 0xCAFEBABE;
  printf("Yeah I'll have a %p with a side of fries thanks\n", v4);
  gets(v4);
  if ( v5 != 0xDEADBEEF )
    exit(0);
  return 0;
}
```

Ta thấy bài này tiếp tục in ra giá trị của input để giúp chúng ta khỏi khổ sở với ASLR.
Dựa theo hàm main đã decompile được, ta cần ghi đè sao cho v5 có giá trị `0xDEADBEEF` để chương trình không bị exit, và thực hiện truyênf shellcode vào bên trong stack.

Tương tự như bài trước, ta cần tìm offset của v5 và ret addr với gdb
```bash
┌──(grass㉿kali)-(~/pwn/insomiac/06-bof_shellcode/tu18_shellaeasy)
└─$ gdb-gef ./shella-easy
gef➤  disass main
gef➤  b *0x0804853e
Breakpoint 1 at 0x804853e
gef➤  r
Yeah I'll have a 0xffffcee0 with a side of fries thanks
bumblebee
gef➤  i f
Stack level 0, frame at 0xffffcf30:
 eip = 0x804853e in main; saved eip = 0xf7c237c5
 Arglist at 0xffffcf28, args: 
 Locals at 0xffffcf28, Previous frame's sp is 0xffffcf30
 Saved registers:
  ebx at 0xffffcf24, ebp at 0xffffcf28, eip at 0xffffcf2c
gef➤  search-pattern bumblebee
[+] Searching 'bumblebee' in memory
[+] In '[stack]'(0xfffdd000-0xffffe000), permission=rwx
  0xffffcee0 - 0xffffcee9  →   "bumblebee" 
gef➤  search-pattern 0xCAFEBABE
[+] Searching '\xBE\xBA\xFE\xCA' in memory
[+] In '/home/grass/pwn/insomiac/06-bof_shellcode/tu18_shellaeasy/shella-easy'(0x8048000-0x8049000), permission=r-x
  0x804851e - 0x804852e  →   "\xBE\xBA\xFE\xCA[...]" 
[+] In '/home/grass/pwn/insomiac/06-bof_shellcode/tu18_shellaeasy/shella-easy'(0x8049000-0x804a000), permission=r--
  0x804951e - 0x804952e  →   "\xBE\xBA\xFE\xCA[...]" 
[+] In '[stack]'(0xfffdd000-0xffffe000), permission=rwx
  0xffffcf20 - 0xffffcf30  →   "\xBE\xBA\xFE\xCA[...]" 
```

Dựa vào những gì đã thu đượcccc, ta có thể suy đoán:
- Địa chỉ của v5 nằm ở `0xffffcf20`
- ret address sau khi gọi `gets()` nằm ở `0xffffcf2c`
- Và v4 của chúng ta ở `0xffffcee0`
Suy ra: 
- Offset của `v5` so với `v4` là: 
```bash
>>> hex(0xffffcf20 - 0xffffcee0)
'0x40'
```
- Offset của ret address  với `v5` là
```bash
>>> hex(0xffffcf2c-0xffffcf20)
'0xc'
```
Từ đó ta có chương trình exploit
