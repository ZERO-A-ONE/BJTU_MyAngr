# 动态链接

因为程序分为静态链接跟动态链接，因为好多库函数在程序中并不一定都用到，所以在处理动态链接程序的时候，elf文件会采取一种叫做延迟绑定（lazy  binding）的技术，也就是当我们位于动态链接库的函数被调用的时候，编译器才会真正确定这个函数在进程中的位置,下面我们通过一个程序来展示这个过程  

```c
#include <stdio.h>
int main()
{
    puts("Hello Pwn\n");
    return 0;
}
```

其中，这个**puts**是调用的**libc**这个动态链接库导出的一个函数。编译它，看看**puts**是怎么被调用的 

```c
.plt:080482E0 ; int puts(const char *s)
.plt:080482E0 _puts           proc near               ; CODE XREF: main+19↓p
.plt:080482E0
.plt:080482E0 s               = dword ptr  4
.plt:080482E0
.plt:080482E0                 jmp     ds:off_804A00Cc
.plt:080482E0 _puts           endp
.plt:080482E0
```

 **puts**会**call**到**off_804A00Cc**这里，这里就是“**jmp** [**GOT**表地址]”的这样一条指令， 跟一下，看看这个**off_804A00C**在第一次调用时是什么东西 

```c
Breakpoint *0x08048424
pwndbg> si
0x080482e0 in puts@plt ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
─────────────────────────────────[ REGISTERS ]──────────────────────────────────
 EAX  0xf7fb4dbc (environ) —▸ 0xffffd10c —▸ 0xffffd2ff ◂— 'XDG_VTNR=7'
 EBX  0x0
 ECX  0xffffd070 ◂— 0x1
 EDX  0xffffd094 ◂— 0x0
 EDI  0xf7fb3000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1b1db0
 ESI  0xf7fb3000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1b1db0
 EBP  0xffffd058 ◂— 0x0
 ESP  0xffffd03c —▸ 0x8048429 ◂— add    esp, 0x10
 EIP  0x80482e0 (puts@plt) ◂— jmp    dword ptr [0x804a00c]
───────────────────────────────────[ DISASM ]───────────────────────────────────
 ► 0x80482e0  <puts@plt>                  jmp    dword ptr [0x804a00c]
 
   0x80482e6  <puts@plt+6>                push   0
   0x80482eb  <puts@plt+11>               jmp    0x80482d0
    ↓
   0x80482d0                              push   dword ptr [0x804a004]
   0x80482d6                              jmp    dword ptr [0x804a008] <0xf7fee000>
    ↓
   0xf7fee000 <_dl_runtime_resolve>       push   eax
   0xf7fee001 <_dl_runtime_resolve+1>     push   ecx
   0xf7fee002 <_dl_runtime_resolve+2>     push   edx
   0xf7fee003 <_dl_runtime_resolve+3>     mov    edx, dword ptr [esp + 0x10]
   0xf7fee007 <_dl_runtime_resolve+7>     mov    eax, dword ptr [esp + 0xc]
   0xf7fee00b <_dl_runtime_resolve+11>    call   _dl_fixup <0xf7fe77e0>
───────────────────────────────────[ STACK ]────────────────────────────────────
00:0000│ esp  0xffffd03c —▸ 0x8048429 ◂— add    esp, 0x10
01:0004│      0xffffd040 —▸ 0x80484c0 ◂— dec    eax /* 'Hello Pwn\n' */
02:0008│      0xffffd044 —▸ 0xffffd104 —▸ 0xffffd2de ◂— '/home/syc/Downloads/retdll/a.out'
03:000c│      0xffffd048 —▸ 0xffffd10c —▸ 0xffffd2ff ◂— 'XDG_VTNR=7'
04:0010│      0xffffd04c —▸ 0x8048461 ◂— lea    eax, [ebx - 0xf8]
05:0014│      0xffffd050 —▸ 0xf7fb33dc (__exit_funcs) —▸ 0xf7fb41e0 (initial) ◂— 0x0
06:0018│      0xffffd054 —▸ 0xffffd070 ◂— 0x1
07:001c│ ebp  0xffffd058 ◂— 0x0
─────────────────────────────────[ BACKTRACE ]──────────────────────────────────
 ► f 0  80482e0 puts@plt
   f 1  8048429
   f 2 f7e19637 __libc_start_main+247
────────────────────────────────────────────────────────────────────────────────
```

可以发现，是**0x80482e6**这个地址，并不直接是**libc**的**puts**函数的地址。这是因为**linux**在程序加载时使用了延迟绑定(**lazyload**)，只有等到这个函数被调用了，才去把这个函数在**libc**的地址放到**GOT**表中。接下来，会再**push**一个**0**，再**push**一个**dword ptr  [0x804a004]**，最后跳到**libc**的**_dl_runtime_resolve**（`call   _dl_fixup`）去执行。这个函数的目的，是根据2个参数获取到导出函数（这里是**puts**）的地址，然后放到相应的**GOT**表，并且调用它。而这个函数的地址也是从**GOT**表取并且jmp [xxx]过去的，但是这个函数不会延迟绑定，因为所有函数都是用它做的延迟绑定

 了解一下elf各段之间的关系 ，才能更好的理解前面从PLT到GOT的过程

```c
syc@ubuntu:~/Downloads/retdll$ readelf -S a.out
There are 29 section headers, starting at offset 0x114c:

Section Headers:
  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            00000000 000000 000000 00      0   0  0
  [ 1] .interp           PROGBITS        08048154 000154 000013 00   A  0   0  1
  [ 2] .note.ABI-tag     NOTE            08048168 000168 000020 00   A  0   0  4
  [ 3] .note.gnu.build-i NOTE            08048188 000188 000024 00   A  0   0  4
  [ 4] .gnu.hash         GNU_HASH        080481ac 0001ac 000020 04   A  5   0  4
  [ 5] .dynsym           DYNSYM          080481cc 0001cc 000050 10   A  6   1  4
  [ 6] .dynstr           STRTAB          0804821c 00021c 00004a 00   A  0   0  1
  [ 7] .gnu.version      VERSYM          08048266 000266 00000a 02   A  5   0  2
  [ 8] .gnu.version_r    VERNEED         08048270 000270 000020 00   A  6   1  4
  [ 9] .rel.dyn          REL             08048290 000290 000008 08   A  5   0  4
  [10] .rel.plt          REL             08048298 000298 000010 08  AI  5  24  4
  [11] .init             PROGBITS        080482a8 0002a8 000023 00  AX  0   0  4
  [12] .plt              PROGBITS        080482d0 0002d0 000030 04  AX  0   0 16
  [13] .plt.got          PROGBITS        08048300 000300 000008 00  AX  0   0  8
  [14] .text             PROGBITS        08048310 000310 000192 00  AX  0   0 16
  [15] .fini             PROGBITS        080484a4 0004a4 000014 00  AX  0   0  4
  [16] .rodata           PROGBITS        080484b8 0004b8 000013 00   A  0   0  4
  [17] .eh_frame_hdr     PROGBITS        080484cc 0004cc 00002c 00   A  0   0  4
  [18] .eh_frame         PROGBITS        080484f8 0004f8 0000cc 00   A  0   0  4
  [19] .init_array       INIT_ARRAY      08049f08 000f08 000004 00  WA  0   0  4
  [20] .fini_array       FINI_ARRAY      08049f0c 000f0c 000004 00  WA  0   0  4
  [21] .jcr              PROGBITS        08049f10 000f10 000004 00  WA  0   0  4
  [22] .dynamic          DYNAMIC         08049f14 000f14 0000e8 08  WA  6   0  4
  [23] .got              PROGBITS        08049ffc 000ffc 000004 04  WA  0   0  4
  [24] .got.plt          PROGBITS        0804a000 001000 000014 04  WA  0   0  4
  [25] .data             PROGBITS        0804a014 001014 000008 00  WA  0   0  4
  [26] .bss              NOBITS          0804a01c 00101c 000004 00  WA  0   0  1
  [27] .comment          PROGBITS        00000000 00101c 000035 01  MS  0   0  1
  [28] .shstrtab         STRTAB          00000000 001051 0000fa 00      0   0  1
```

我们一般只关注几个比较重要的 section 

|   .dynsym    |    动态链接符号表    |
| :----------: | :------------------: |
| **.dynstr**  | **动态链接的字符串** |
| **.rel.dyn** |    **变量重定位**    |
| **.rel.plt** |    **函数重定位**    |
|   **.got**   |  **全局变量偏移表**  |
| **.got.plt** |  **全局函数偏移表**  |

## .dynamic

包含了一些关于动态链接的关键信息，在里这它长这样，事实上这个section所有程序都差不多 

```c
syc@ubuntu:~/Downloads/retdll$ readelf -d a.out

Dynamic section at offset 0xf14 contains 24 entries:
  Tag        Type                         Name/Value
 0x00000001 (NEEDED)                     Shared library: [libc.so.6]
 0x0000000c (INIT)                       0x80482a8
 0x0000000d (FINI)                       0x80484a4
 0x00000019 (INIT_ARRAY)                 0x8049f08
 0x0000001b (INIT_ARRAYSZ)               4 (bytes)
 0x0000001a (FINI_ARRAY)                 0x8049f0c
 0x0000001c (FINI_ARRAYSZ)               4 (bytes)
 0x6ffffef5 (GNU_HASH)                   0x80481ac
 0x00000005 (STRTAB)                     0x804821c
 0x00000006 (SYMTAB)                     0x80481cc
 0x0000000a (STRSZ)                      74 (bytes)
 0x0000000b (SYMENT)                     16 (bytes)
 0x00000015 (DEBUG)                      0x0
 0x00000003 (PLTGOT)                     0x804a000
 0x00000002 (PLTRELSZ)                   16 (bytes)
 0x00000014 (PLTREL)                     REL
 0x00000017 (JMPREL)                     0x8048298
 0x00000011 (REL)                        0x8048290
 0x00000012 (RELSZ)                      8 (bytes)
 0x00000013 (RELENT)                     8 (bytes)
 0x6ffffffe (VERNEED)                    0x8048270
 0x6fffffff (VERNEEDNUM)                 1
 0x6ffffff0 (VERSYM)                     0x8048266
 0x00000000 (NULL)                       0x0
```

然后**.dynamic**每个元素的结构体是这样的， 一个 **Elf_Dyn** 是一个键值对，其中 **d_tag** 是键，**d_value** 是值 

```c
typedef struct {
    Elf32_Sword d_tag;
    union {
        Elf32_Word d_val;
        Elf32_Addr d_ptr;
    } d_un;
} Elf32_Dyn;
```

这个**section**的用处就是他包含了很多动态链接所需的关键信息，我们现在只关心`DT_STRTAB`, `DT_SYMTAB`, `DT_JMPREL`这三项，这三个东西分别包含了指向`.dynstr`, `.dynsym`, `.rel.plt`这3个section的指针

### DT_JMPREL(.rel.plt)

 可以看到`puts`符号位于**.rel.plt**的第一个，也就是偏移为**0×0**的地方，这里的`r_offset`（偏移量）就是**.got.plt**的地址 

```c
syc@ubuntu:~/Downloads/retdll$ readelf -r a.out

Relocation section '.rel.dyn' at offset 0x290 contains 1 entries:
 Offset     Info    Type            Sym.Value  Sym. Name
08049ffc  00000206 R_386_GLOB_DAT    00000000   __gmon_start__

Relocation section '.rel.plt' at offset 0x298 contains 2 entries:
 Offset     Info    Type            Sym.Value  Sym. Name
0804a00c  00000107 R_386_JUMP_SLOT   00000000   puts@GLIBC_2.0
0804a010  00000307 R_386_JUMP_SLOT   00000000   __libc_start_main@GLIBC_2.0

```

这里是重定位表（不过跟windows那个重定位表概念不同），也是一个结构体数组，每个项对应一个导入函数。结构体定义如下： 

```c
typedef struct
{
  Elf32_Addr    r_offset; //指向GOT表的指针
  Elf32_Word    r_info;
  //一些关于导入符号的信息，我们只关心从第二个字节开始的值((val)>>8)，忽略那个07
  //1和3是这个导入函数的符号在.dynsym中的下标，
  //如果往回看的话你会发现1和3刚好和.dynsym的puts和__libc_start_main对应
} Elf32_Rel;
```

### DT_STRTAB(.dynstr)

```c
LOAD:0804821C ; ELF String Table
LOAD:0804821C byte_804821C    db 0                    ; DATA XREF: LOAD:080481DC↑o
LOAD:0804821C                                         ; LOAD:080481EC↑o ...
LOAD:0804821D aLibcSo6        db 'libc.so.6',0
LOAD:08048227 aIoStdinUsed    db '_IO_stdin_used',0   ; DATA XREF: LOAD:0804820C↑o
LOAD:08048236 aPuts           db 'puts',0             ; DATA XREF: LOAD:080481DC↑o
LOAD:0804823B aLibcStartMain  db '__libc_start_main',0
```

 一个字符串表，**index**为**0**的地方永远是**0**，然后后面是动态链接所需的字符串，**0**结尾，包括导入函数名，比方说这里很明显有个**puts**。到时候，相关数据结构引用一个字符串时，用的是相对这个section头的偏移，比方说，在这里，就是字符串相对**0x804821C**的偏移 

### DT_SYMTAB(.dynsym)

```c
syc@ubuntu:~/Downloads/retdll$  readelf -s a.out

Symbol table '.dynsym' contains 5 entries:
   Num:    Value  Size Type    Bind   Vis      Ndx Name
     0: 00000000     0 NOTYPE  LOCAL  DEFAULT  UND 
     1: 00000000     0 FUNC    GLOBAL DEFAULT  UND puts@GLIBC_2.0 (2)
     2: 00000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
     3: 00000000     0 FUNC    GLOBAL DEFAULT  UND __libc_start_main@GLIBC_2.0 (2)
     4: 080484bc     4 OBJECT  GLOBAL DEFAULT   16 _IO_stdin_used
```

 这个东西，是一个符号表（结构体数组），里面记录了各种符号的信息，每个结构体对应一个符号。我们这里只关心函数符号，比方说上面的**puts**。结构体定义如下 

```c
typedef struct
{
  Elf32_Word    st_name; //符号名，是相对.dynstr起始的偏移，这种引用字符串的方式在前面说过了
  Elf32_Addr    st_value;
  Elf32_Word    st_size;
  unsigned char st_info; //对于导入函数符号而言，它是0x12
  unsigned char st_other;
  Elf32_Section st_shndx;
}Elf32_Sym; //对于导入函数符号而言，其他字段都是0
#define ELF32_R_SYM(info) ((info)>>8)
#define ELF32_R_TYPE(info) ((unsigned char)(info))
#define ELF32_R_INFO(sym, type) (((sym)<<8)+(unsigned char)(type))
```

## 解析符号

 假设**.dynsym**的地址为**080481cc**，又因为**puts**函数对应的**num**为**1** ，则程序会去**0x080481cc+0x10*1**寻找**st_name**即**puts**字符串在**.dynstr**中的偏移 

```c
gef➤  x/4wx 0x080481cc+0x10*1
0x80481dc:    0x0000001a    0x00000000    0x00000000    0x00000012
```

解释一下这一串地址`0x080481cc+0x10*1`的意义

> - 0x080481cc 对应.dynsym的地址
> - 0×10 ： 每一条symbol信息的大小在SYMENT中体现，为16 bytes （可以用readelf -d fun命令查看）
> - 1 ： num值为1

可以看到0x080481dc对应的第一个值为0x1a， 再利用如下命令即可找到puts符号 

```
gef➤  x/s 0x0804821c+0x1a
0x8048236:    "puts"
```

0x0804821c+0x1a 解析

> - 0x0804821c 对应于.dynstr的地址
> - 0x1a 对应刚才得到的偏移

# 函数执行流程分析

用gdb运行这个程序，并在puts函数处下断点 

```c
► 0x80482e0  <puts@plt>                  jmp    dword ptr [0x804a00c]
 
   0x80482e6  <puts@plt+6>                push   0
   0x80482eb  <puts@plt+11>               jmp    0x80482d0
```

执行到我们下的断点处发现，会跳转到`0x804a00c`这个地址 

```c
pwndbg> x/wx 0x804a00c
0x804a00c:	0x080482e6
```

0x0804a00c这个地址处存储的内容为<puts@plt+6>的地址，因为这个程序第一次运行所以got表中没有保存read函数的地址，所以程序又跳转会<puts@plt+6>，所以紧接着会执行 

```c
0x80482e6  <puts@plt+6>                push   0
0x80482eb  <puts@plt+11>               jmp    0x80482d0
```

先将0×0压栈（0×0 表示相对.rel.plt的偏移，通过上面分析我们可以知道，read符号在.rel.plt中的位置为第一个，所以偏移为0），又跳转到0x80482d0，看一下该地处的内容 

```c
pwndbg> x/2i 0x080482d0
   0x80482d0:	push   DWORD PTR ds:0x804a004
   0x80482d6:	jmp    DWORD PTR ds:0x804a008
```

会将**0x804a004**压栈，然后跳转到**0x804a008**处。

- **0x804a004**处对应一个指向内部数据结构的指针，类型是 **link_map**，在动态装载器内部使用，包含了进行符号解析需要的当前 **ELF** 对象的信息。在它的 **l_info** 域中保存了 .**dynamic** 段中大多数条目的指针构成的一个数组，我们后面会利用它。 **link_map**的指针，这个结构是干什么的，我们不关心，但是有一点要知道，它包含了.**dynamic**的指针，通过这个**link_map**，**_dl_runtime_resolve**函数可以访问到.**dynamic**这个**section** 
- **0x0804a008** 处为函数 **dl_runtime_resolve**(**link_map**,**rel_offset**)

```
pwndbg> x/4wx 0xf7fee000
0xf7fee000 <_dl_runtime_resolve>:	0x8b525150	0x8b102454	0xe80c2444	0xffff97d0
```

 0xe80c2444是**.dynamic**的指针，与前面图中一致

 我们看一下dl_runtime_resolve()函数的实现 

```c
pwndbg> x/20i 0xf7fee000
   0xf7fee000 <_dl_runtime_resolve>:	push   eax
   0xf7fee001 <_dl_runtime_resolve+1>:	push   ecx
   0xf7fee002 <_dl_runtime_resolve+2>:	push   edx
   0xf7fee003 <_dl_runtime_resolve+3>:	mov    edx,DWORD PTR [esp+0x10]
   0xf7fee007 <_dl_runtime_resolve+7>:	mov    eax,DWORD PTR [esp+0xc]
   0xf7fee00b <_dl_runtime_resolve+11>:	call   0xf7fe77e0 <_dl_fixup>
   0xf7fee010 <_dl_runtime_resolve+16>:	pop    edx
   0xf7fee011 <_dl_runtime_resolve+17>:	mov    ecx,DWORD PTR [esp]
   0xf7fee014 <_dl_runtime_resolve+20>:	mov    DWORD PTR [esp],eax
   0xf7fee017 <_dl_runtime_resolve+23>:	mov    eax,DWORD PTR [esp+0x4]
   0xf7fee01b <_dl_runtime_resolve+27>:	ret    0xc
   0xf7fee01e:	xchg   ax,ax
   0xf7fee020 <_dl_runtime_profile>:	push   esp
   0xf7fee021 <_dl_runtime_profile+1>:	add    DWORD PTR [esp],0x8
   0xf7fee025 <_dl_runtime_profile+5>:	push   ebp
   0xf7fee026 <_dl_runtime_profile+6>:	push   eax
   0xf7fee027 <_dl_runtime_profile+7>:	push   ecx
   0xf7fee028 <_dl_runtime_profile+8>:	push   edx
   0xf7fee029 <_dl_runtime_profile+9>:	mov    ecx,esp
   0xf7fee02b <_dl_runtime_profile+11>:	sub    esp,0x8
```

在**0xf7fee00b**地址处调用了 **_dl_fixup()**函数，并且采用寄存器传参，**dl_fixup()**是在**dl-runtime.c**中实现的， **_dl_fixup**函数传入的两个参数一个是**rdi**寄存器中存储的**link_map**，**rsi**是**GOT**表中关于**PLT**重定位的索引值，后面要根据该索引值写入新的地址 

```
_dl_fixup (struct link_map *l, ElfW(Word) reloc_arg)
｛
    const PLTREL *const reloc = (const void *) (D_PTR (l, l_info[DT_JMPREL]) + reloc_offset);
    const ElfW(Sym) *sym = &symtab[ELFW(R_SYM) (reloc->r_info)];
    assert (ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT);
    result = _dl_lookup_symbol_x (strtab + sym->st_name, l, &sym, l->l_scope,version, ELF_RTYPE_CLASS_PLT, flags, NULL);
    value = DL_FIXUP_MAKE_VALUE (result, sym ? (LOOKUP_VALUE_ADDRESS (result) + sym->st_value) : 0);
    return elf_machine_fixup_plt (l, result, reloc, rel_addr, value);
｝
```

逐行解释

```
_dl_fixup (struct link_map *l, ElfW(Word) reloc_arg)
```

这里面 **link_map**还是一开始传进来的**link_map**,但一开始传进来的**rel_offset**改为用**reloc_arg**表示：`reloc_arg=reloffset`

```
    const PLTREL *const reloc = (const void *) (D_PTR (l, l_info[DT_JMPREL]) + reloc_offset);
```

用来计算重定位入口**reloc**，**JMPREL**即**.rel.plt**地址，**reloc_offset**即**reloc_arg**

```
    const ElfW(Sym) *sym = &symtab[ELFW(R_SYM) (reloc->r_info)];
```

找到在.**dynsym**中对应的条目，**[ELFW(R_SYM) (reloc->r_info)]**就是为了找到对应的**num[?]**

```
    assert (ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT);
```

检查**reloc->r_info**的最低位是不是**R_386_JUMP_SLOT=7**

```
 result = _dl_lookup_symbol_x (strtab + sym->st_name, l, &sym, l->l_scope,version, ELF_RTYPE_CLASS_PLT, flags, NULL);
```

根据**st_name**对应的偏移，去**.dynstr(STRTAB)**中查找对应的字符串，**result**为**libc**基地址(不知道是怎么找到**result**的，反正知道就好了。。。)

```
value = DL_FIXUP_MAKE_VALUE (result, sym ? (LOOKUP_VALUE_ADDRESS (result) + sym->st_value) : 0);
```

**value**为函数的实际地址，在**libc**基地址的基础上加上函数在**libc**中的偏移

```
    return elf_machine_fixup_plt (l, result, reloc, rel_addr, value);
```

将函数地址写到**got**表对应位置

简单来说_dl_runtime_resolve就是会

1. 用**link_map**访问.**dynamic**，取出.**dynstr**, .**dynsym**, **.rel.plt**的指针
2. **.rel.plt + 第二个参数**求出当前函数的重定位表项**Elf32_Rel**的指针，记作**rel**
3. **rel->r_info >> 8**作为.**dynsym**的下标，求出当前函数的符号表项**Elf32_Sym**的指针，记作**sym**
4. **.dynstr + sym->st_name**得出符号名字符串指针
5. 在动态链接库查找这个函数的地址，并且把地址赋值给***rel->r_offset**，即**GOT**表
6. 调用这个函数

![](https://github-1251836300.cos.ap-guangzhou.myqcloud.com/%E5%8A%A8%E6%80%81%E9%93%BE%E6%8E%A5/image003.jpg)

> ##### 从一个ELF动态链接库文件中，根据已知的函数名称，找到相应的函数起始地址，那么过程是这样的，先从前面的ELF 的ehdr中找到文件的偏移e_phoff处，在这其中找到为PT_DYNAMIC  的d_tag的phdr，从这个地址开始处找到DT_DYNAMIC的节，最后从其中找到这样一个Elf32_Sym结构，它的st_name所指的字符串与给定的名称相符，就用st_value便是了

# 深入理解

```cc
   0xf7fee000 <_dl_runtime_resolve>       push   eax
   0xf7fee001 <_dl_runtime_resolve+1>     push   ecx
   0xf7fee002 <_dl_runtime_resolve+2>     push   edx
   0xf7fee003 <_dl_runtime_resolve+3>     mov    edx, dword ptr [esp + 0x10]
   0xf7fee007 <_dl_runtime_resolve+7>     mov    eax, dword ptr [esp + 0xc]
 ► 0xf7fee00b <_dl_runtime_resolve+11>    call   _dl_fixup <0xf7fe77e0>
        arg[0]: 0xffffd094 ◂— 0x0
        arg[1]: 0xffffd070 ◂— 0x1
```

调用函数过程中已经压入了两个参数：第一个是动态链接库的**struct link_map*** 指针，另一个是**rel**的索引值， 这里是给下面的fixup函数以寄存器传递参数 

真正的解析在**do_lookup**中实现了，我这里还是它的实现伪代码:

```cc
Elf32_Addr  do_lookup(struct link_map* lmap,char* symname)
{
	struct link_map* search_lmap=NULL;
	Elf32_Sym* symtab;
	Elf32_Sym* sym;
	char* strtab;
	char* find_name;
	int symindx;   
	Elf32_Word hash=elf_hash_name(symname);
	for_each_search_lmap_in_search_list(lmap,search_lmap)
	{
		symtab=search_lmap->l_info[DT_SYMTAB].d_un.d_ptr;
		strtab=search_lmap->l_info[DT_STRTAB].d_un.d_ptr;
		for (symindx=search_lmap->l_buckets[hash % search_lmap->l_nbuckets];
		symindx!=0;symindx=search_lmap->l_chain[symindx])
		{
			sym=&symtab[symindx];
			find_name=strtab+sym->st_name;
			if (strcmp(find_name,symname)==0)
				return sym->st_value+search_lmap->l_addr;
		}
	return 0;
	}
}
```

![](https://github-1251836300.cos.ap-guangzhou.myqcloud.com/%E5%8A%A8%E6%80%81%E9%93%BE%E6%8E%A5/image004.jpg)

# 流程图

函数第一次被调用过程

![img](https://github-1251836300.cos.ap-guangzhou.myqcloud.com/%E6%96%B0%E6%89%8B%E5%90%91%E2%80%94%E2%80%94%E6%B5%85%E8%B0%88PLT%E5%92%8CGOT/5970003-bcf9343191848103.png)

第一步由函数调用跳入到**PLT**表中，然后第二步**PLT**表跳到**GOT**表中，可以看到第三步由**GOT**表回跳到**PLT**表中，这时候进行压栈，把代表函数的**ID**压栈，接着第四步跳转到公共的**PLT**表项中，第5步进入到**GOT**表中，然后**_dl_runtime_resolve**对动态函数进行地址解析和重定位，第七步把动态函数真实的地址写入到**GOT**表项中，然后执行函数并返回。

函数之后被调用过程

![img](https://github-1251836300.cos.ap-guangzhou.myqcloud.com/%E6%96%B0%E6%89%8B%E5%90%91%E2%80%94%E2%80%94%E6%B5%85%E8%B0%88PLT%E5%92%8CGOT/5970003-9baedd55881a39dd.png)

可以看到，第一步还是由函数调用跳入到**PLT**表，但是第二步跳入到**GOT**表中时，由于这个时候该表项已经是动态函数的真实地址了，所以可以直接执行然后返回。

对于动态函数的调用，第一次要经过地址解析和回写到**GOT**表项中，第二次直接调用即可

# ret2dl-resolve 利用

主要是看 **.dynamic**能否可写 

## 改写.dynamic的DT_STRTAB

这个只有在**checksec**时**No RELRO**可行，即**.dynamic**可写。因为**ret2dl-resolve**会从**.dynamic**里面拿.**dynstr**字符串表的指针，然后加上**offset**取得函数名并且在动态链接库中搜索这个函数名，然后调用。而假如说我们能够**改写**这个指针到一块我们能够操纵的内存空间，当**resolve**的时候，就能**resolve**成我们所指定的任意库函数。比方说，原本是一个**free**函数，我们就把原本是**free**字符串的那个偏移位置设为**system**字符串，**第一次**调用`free("bin/sh")`（因为只有第一次才会resolve），就等于调用了`system("/bin/sh")`

## 操纵第二个参数，使其指向我们所构造的Elf32_Rel

如果`.dynamic`不可写，那么以上方法就没用了，所以有第二种利用方法。要知道，前面的`_dl_runtime_resolve`在第二步时

> ```
> .rel.plt + 第二个参数`求出当前函数的重定位表项`Elf32_Rel`的指针，记作`rel
> ```

这个时候，`_dl_runtime_resolve`并没有检查`.rel.plt + 第二个参数`后是否造成越界访问，所以我们能给一个很大的`.rel.plt`的offset（64位的话就是下标），然后使得加上去之后的地址指向我们所能操纵的一块内存空间，比方说`.bss`。

然后第三步

> ```
> rel->r_info >> 8`作为`.dynsym`的下标，求出当前函数的符号表项`Elf32_Sym`的指针，记作`sym
> ```

 所以在我们所伪造的`Elf32_Rel`，需要放一个`r_info`字段，大概长这样就行`0xXXXXXX07`，其中XXXXXX是相对`.dynsym`表的下标，注意不是偏移，所以是偏移除以`Elf32_Sym`的大小，即除以`0x10`（32位下）。然后这里同样也没有进行越界访问的检查，所以可以用类似的方法，伪造出这个`Elf32_Sym`。至于为什么是07，因为这是一个导入函数，而导入函数一般都是07，所以写成07就好。

然后第四步

> `.dynstr + sym->st_name`得出符号名字符串指针

同样类似，没有进行越界访问检查，所以这个字符串也能够伪造。

所以，最终的利用思路，大概是

```c
0x80482d0				push dword ptr [0x804a004]
0x80482d6				jmp  dword ptr [0x804a008]
```

构造ROP，跳转到resolve的PLT，`push link_map`的位置，就是上图所示的这个地方。此时，栈中必须要有已经伪造好的指向伪造的`Elf32_Rel`的偏移，然后是返回地址（`system`的话无所谓），再然后是参数（如果是`system`函数的话就要是指向`"/bin/sh\x00"`的指针）