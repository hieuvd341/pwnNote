# pilot
- Đầu tiên nhìn xem file binary có gì
```bash
┌──(grass㉿kali)-(~/pwn/insomiac/06-bof_shellcode/csaw17_pilot)
└─$ file pilot
pilot: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=6ed26a43b94fd3ff1dd15964e4106df72c01dc6c, stripped

┌──(grass㉿kali)-(~/pwn/insomiac/06-bof_shellcode/csaw17_pilot)
└─$ pwn checksec pilot 
[*] '/home/grass/pwn/insomiac/06-bof_shellcode/csaw17_pilot/pilot'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX unknown - GNU_STACK missing
    PIE:      No PIE (0x400000)
    Stack:    Executable
    RWX:      Has RWX segments
```

Ta thấy file này được biên dịch không sử dụng NX. Do vậy ta có thể thực hiện chèn shellcode vào stack và chạy shellcode này.
Ta cũng thấy được ta đang phải làm việc với file ELF 64 bit. Chạy thử chương trình này, ta được:

Hmmmm, 1 đống text. Hơn nữa ở dòng này còn có ``, trông có vẻ như là một vùng nhớ bên trong stack. 
Chương trình sau đó yêu cầu ta nhập vào input. Đầu tiên ta xem decompile của hàm này có gì
```c

undefined8 FUN_004009a6(void)

{
  basic_ostream *this;
  basic_ostream<char,std--char_traits<char>> *this_00;
  ssize_t sVar1;
  undefined8 uVar2;
  undefined input [32];
  
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stdin,(char *)0x0,2,0);
  this = operator<<<std--char_traits<char>>((basic_ostream *)cout,"[*]Welcome DropShip Pilot...");
  operator<<((basic_ostream<char,std--char_traits<char>> *)this,endl<char,std--char_traits<char>>);
  this = operator<<<std--char_traits<char>>((basic_ostream *)cout,"[*]I am your assitant A.I....");
  operator<<((basic_ostream<char,std--char_traits<char>> *)this,endl<char,std--char_traits<char>>);
  this = operator<<<std--char_traits<char>>
                   ((basic_ostream *)cout,"[*]I will be guiding you through the tutorial....");
  operator<<((basic_ostream<char,std--char_traits<char>> *)this,endl<char,std--char_traits<char>>);
  this = operator<<<std--char_traits<char>>
                   ((basic_ostream *)cout,
                    "[*]As a first step, lets learn how to land at the designated location....");
  operator<<((basic_ostream<char,std--char_traits<char>> *)this,endl<char,std--char_traits<char>>);
  this = operator<<<std--char_traits<char>>
                   ((basic_ostream *)cout,
                                        
                    "[*]Your mission is to lead the dropship to the right location and executesequence of instructions to save Marines & Medics..."
                   );
  operator<<((basic_ostream<char,std--char_traits<char>> *)this,endl<char,std--char_traits<char>>);
  this = operator<<<std--char_traits<char>>((basic_ostream *)cout,"[*]Good Luck Pilot!....");
  operator<<((basic_ostream<char,std--char_traits<char>> *)this,endl<char,std--char_traits<char>>);
  this = operator<<<std--char_traits<char>>((basic_ostream *)cout,"[*]Location:");
  this_00 = (basic_ostream<char,std--char_traits<char>> *)
            operator<<((basic_ostream<char,std--char_traits<char>> *)this,input);
  operator<<(this_00,endl<char,std--char_traits<char>>);
  operator<<<std--char_traits<char>>((basic_ostream *)cout,"[*]Command:");
  sVar1 = read(0,input,0x40);
  if (sVar1 < 5) {
    this = operator<<<std--char_traits<char>>((basic_ostream *)cout,"[*]There are no commands....");
    operator<<((basic_ostream<char,std--char_traits<char>> *)this,endl<char,std--char_traits<char>>)
    ;
    this = operator<<<std--char_traits<char>>((basic_ostream *)cout,"[*]Mission Failed....");
    operator<<((basic_ostream<char,std--char_traits<char>> *)this,endl<char,std--char_traits<char>>)
    ;
    uVar2 = 0xffffffff;
  }
  else {
    uVar2 = 0;
  }
  return uVar2;
}
```

Trong hàm này có 2 phần mà ta cần để ý tới. 
Phần đầu tiên là:
```c
  sVar1 = read(0,input,0x40);
```

Ta thấy hàm này scan 0x40 bytes vào input. Nhưng mảng input lại chỉ có thể chứa được 32 bytes. Ta có overflow ở đây.
Điểm tiếp theo cần chú ý là cái địa chỉ mà chương trình in ra:
```c
  this = operator<<<std--char_traits<char>>((basic_ostream *)cout,"[*]Location:");
  this_00 = (basic_ostream<char,std--char_traits<char>> *)
            operator<<((basic_ostream<char,std--char_traits<char>> *)this,input);
  operator<<(this_00,endl<char,std--char_traits<char>>);
```
Đây chính là địa chỉ của input của chúng ta trong stack.

Xem stack bên trong Ghidra:
```c
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined FUN_004009a6()
             undefined         AL:1           <RETURN>
             undefined[32]     Stack[-0x28]   input                                   XREF[2]:     00400aa4(*), 
                                                                                                   00400acf(*)  
                             FUN_004009a6                                    XREF[4]:     entry:004008cd(*), 
                                                                                          entry:004008cd(*), 00400de0, 
                                                                                          00400e80(*)  
        004009a6 55              PUSH       RBP
```

ta thấy không có địa chỉ nào xen vào giữa input và ret. Có vẻ là ghi đè được rồi.
Việc của chúng ta bây giờ là tìm cần tốn bao nhiêu bytes để ghi đè được ret. 
Sử dụng gef để debug chương trình, đặt breakpoint ở ngay sau hàm nhập
```bash
gef➤  b *0x400ae5
Breakpoint 1 at 0x400ae5
gef➤  r
Starting program: /home/grass/pwn/insomiac/06-bof_shellcode/csaw17_pilot/pilot 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[*]Welcome DropShip Pilot...
[*]I am your assitant A.I....
[*]I will be guiding you through the tutorial....
[*]As a first step, lets learn how to land at the designated location....
[*]Your mission is to lead the dropship to the right location and execute sequence of instructions to save Marines & Medics...
[*]Good Luck Pilot!....
[*]Location:0x7fffffffdd30
[*]Command:bumblebee

gef➤  search-pattern bumblebee
[+] Searching 'bumblebee' in memory
[+] In '[stack]'(0x7ffffffde000-0x7ffffffff000), permission=rwx
  0x7fffffffdd30 - 0x7fffffffdd3b  →   "bumblebee\n" 

gef➤  i f
Stack level 0, frame at 0x7fffffffdd60:
 rip = 0x400ae5; saved rip = 0x7ffff7a456ca
 called by frame at 0x7fffffffde00
 Arglist at 0x7fffffffdd28, args: 
 Locals at 0x7fffffffdd28, Previous frame's sp is 0x7fffffffdd60
 Saved registers:
  rbp at 0x7fffffffdd50, rip at 0x7fffffffdd58
```
Ta thấy offset giữa input và return address là:
```
0x7fffffffdd58 - 0x7fffffffdd30 = 0x28
```
vậy chúng ta phải ghi đè ret address địa chỉ của shellcode.  Ở đây địa chỉ được chọn chính là địa chỉ mà ta đã leak ra được
