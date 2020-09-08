# Pwn 知识点清单

## 前言

nuoye大佬带不动我了，让我先补补基础:

## Pwntools

[pwntools 文档](http://docs.pwntools.com/en/stable/)

### 安装

```
sudo pip install pwntools
```

### 利用

> 以下只是常用命令

导入pwntools模块

```
from pwn import *
```

Log等级

```
context.log_level = "debug" # 打印调试信息
context.log_level = "error" # 打印错误信息, 此时很多回显就看不到了
```

以log形式输出信息

```
log.info('Hello, World') 
# 输出
# [*] Hello, World
```

在tmux中以分屏的形式启动gdb

```
context.terminal = ['tmux', 'splitw', '-h'] # 横向
context.terminal = ['tmux', 'splitw', '-v'] # 纵向
```

启动程序

```
p = process("./pwn") # 本地
p = remote(ip, port) # e.g. p = remote("10.10.10.10", 23946) 远程交互
```

绑定libc

```
p=process([‘./bin’],env={‘LOAD_PRELOAD’:’./libc-2.23.so’})
```

gdb调试

```
gdb.attach(p, "b read") # "b read"为gdb开启后执行的命令
```

发送信息

```
p.send(data) # 不带回车
p.sendline(data) # 带回车
p.sendafter(delim, data, timeout = default) #  recvuntil（delim，timeout = timeout）和send（data）的组合。
p.sendlineafter(delim, data, timeout = default) #  recvuntil（delim，timeout = timeout）和sendline（data）的组合。
```

接受信息

```
p.recv(number) # 接收number个字节的信息， number可省略
p.recvline() # 接收一行信息
p.recvuntil(msg) # 接受信息直到msg出现
```

启动交互

```
p.interactive()
```

## 防护措施

### ASLR

#### 概念

`ASLR (Address Space Layout Randomization ) `, 地址空间配置随机加载, 简称`地址随机化`, 是一种针对缓冲区溢出的安全保护技术，通过对堆、栈、共享库映射等线性区布局的随机化，通过增加攻击者预测目的地址的难度，防止攻击者直接定位攻击代码位置，达到阻止溢出攻击的目的的一种技术。

#### 关闭

为了方便我们调试，可以在自己的系统上关闭ASLR来确认偏移等等

```
sudo sysctl -w kernel.randomize_va_space=0
```

#### 绕过

**程序信息泄露**: 目前广泛应用在操作系统的地址随机化多为粗粒度的实现方式，同一模块中的所有代码与数据的相对偏移固定。只需要通过信息泄露漏洞将某个模块中的任一代码指针或者数据指针泄露，即可通过计算得到此模块中任意代码或数据的地址

### Canary

[Canary](https://lantern.cool/2020/05/19/note-pwn-canary/)

#### 绕过

程序信息泄露

### NX

`NX(Non-eXecute)`位是一种针对 shellcode 执行攻击的保护措施，意在更有效地识别数据区和代码区。通过在内存页的标识中增加”执行”位，可以表示该内存页是否执行，若程序代码的 EIP 执行至不可运行的内存页，则 CPU 将直接拒绝执行”指令”造成程序崩溃。

在 Linux 中，当装载器把程序装载进内存空间后，将程序的`.text`段标记为可执行，而其余的数据段(`.data,.bss等`)以及栈、堆均不可执行。当攻击者在堆栈上部署自己的 `shellcode` 并触发时，只会直接造成程序的崩溃。

#### 绕过

代码重用攻击，使用现有代码构造自身所需控制流。

### PIE

`PIE(Position-Independent Executable, 位置无关可执行文件)`技术与 ASLR 技术类似，ASLR 将程序运行时的堆栈以及共享库的加载地址随机化，而 PIE 技术则在编译时将程序编译为**位置无关**，即程序运行时各个段加载的虚拟地址也是在装载时才确定。

#### 绕过

- **程序信息泄露**: 同 ASLR, 通过信息泄露漏洞将某个模块中的任一代码指针或者数据指针泄露，即可通过计算得到此模块中任意代码或数据的地址
- **部分写入**: PIE 存在一个缺陷，那就是 PIE 的随机化只能影响到单个内存页。通常来说，一个内存页大小为 0x1000，所以最后的3位16进制数是不会变化的，我们就可以通过程序信息泄露或部分写入来绕过 PIE。

### RELRO

`RELRO(RELocation Read-Only, 重定位只读)`，此技术主要针对 GOT 改写的攻击方式。分为部分 **RELRO(Partial RELRO)** 与完全 **RELRO(Full RELRO)** 两种

- **部分 RELRO**: 在程序装入后，将其中一段(如`.dynamic`)标记为只读，防止程序的一些重定位信息被修改
- **完全 RELRO**: 在部分 RELRO 的基础上, 在 程序装入时, 直接解析完所有符号并填入对应的值, 此时所有的 GOT 表项都已初始化, 且不装入 `link_map` 与`_dl_runtime_resolve` 的地址(二者都是程 序动态装载的重要结构和函数)。

#### 绕过

改写 glibc 中其他函数指针

## Stack

### Stack Overflow

### ROP

#### ret2text

#### ret2shellcode

#### ret2syscall

#### ret2libc

#### ret2csu

#### ret2reg

### SROP

- Defcon 2015 Qualifier fuckup

### BROP

- HCTF 2016 出题人跑路了(pwn 50)

### stack pivot

- EKOPARTY CTF 2016 fuckzing-exploit-200(基于栈的stack pivot)
  HACKIM CTF 2015 -Exploitation 5(基于堆的stack pivot)

### frame faking

### ret2dl_resolve

- 了解动态链接的过程：
  《程序员的自我修养》
  http://blog.chinaunix.net/uid-2477416-id-3053007.html
- 伪造动态链接的相关数据结构如linkmap、relplt：
  http://rk700.github.io/2015/08/09/return-to-dl-resolve/
  http://angelboy.logdown.com/posts/283218-return-to-dl-resolve
  http://www.inforsec.org/wp/?p=389
- **Codegate CTF Finals 2015 yocto(fake relplt) http://o0xmuhe.me/2016/10/25/yocto-writeup**
- HITCON QUALS CTF 2015 readable(fake linkmap), Hack.lu’s 2015 OREO

### Stack smash

覆盖canary保护输出的字符地址

### Partial Overwrite

- HCTF 2016 fheap(基于堆溢出的Partial overwrite)
- 溢出位数不够
  - XMAN 2016 广外女生-pwn， Codegate CTF Finals 2015,chess

## Heap

### 查libc版本

[libc database search](https://libc.blukat.me/): 根据低12位及对应的函数名来查找 libc 版本

[Libc Searcher](https://github.com/lieanu/LibcSearcher)： 原理跟上面一样，不过是 python 写的小工具

### 堆管理机制

- `多数Linux发行版`: [glibc内存管理ptmalloc源代码分析.pdf](https://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=&ved=2ahUKEwjc27HshfDqAhU1w4sBHTlWA3sQFjAAegQIAxAB&url=https://paper.seebug.org/papers/Archive/refs/heap/glibc%E5%86%85%E5%AD%98%E7%AE%A1%E7%90%86ptmalloc%E6%BA%90%E4%BB%A3%E7%A0%81%E5%88%86%E6%9E%90.pdf&usg=AOvVaw2QkZp_edTDs5MkI7y-zVGA)
- `Android/Firfox`： jemalloc
- `Windows:` 微软自己实现了一套内存管理机制， 迄今没有公开
- `Linux内核`: slab、slub、slob分配器

### 堆漏洞利用思想

1. 控制堆内存管理的相关数据结构: 如arena、bins、chunk
2. 控制堆内存中的用户数据: 覆盖变量指针、函数指针、数据等

一般情况下都是为了构造任意内存读写以及控制流劫持

### 堆漏洞的防护方法

- 保护堆内存管理

  - Heap Canary
  - 数据结构加密
  - 在堆管理代码中加入安全检查

- 通防

  - ASLR

  - DEP

    ```
    数据执行保护(DEP)（Data Execution Prevention） 是一套软硬件技术，能够在内存上执行额外检查以帮助防止在系统上运行恶意代码。在 Microsoft Windows XP Service Pack 2及以上版本的Windows中，由硬件和软件一起强制实施 DEP。
    ```

### 堆漏洞利用技术与技巧

#### Heap Overflow

- Heap Overflow

#### Use After Free

- [first fit and UAF](https://lantern.cool/2020/05/22/note-pwn-first-fit-And-UAF/)
- DEFCON CTF Qualifier 2014:shitsco、BCTF 2016:router、HCTF 2016 5-days(较难)

#### double free

- [double free](https://lantern.cool/2020/05/25/note-pwn-double-free/)
- [0CTF 2016 freenote](https://lantern.cool/2020/07/27/wp-item-0ctf-2016-freenote/), [HCTF 2016 fheap](https://lantern.cool/2020/07/28/wp-item-HCTF-2016-fheap/), HCTF 2016 5-days(较难)**

#### Heap Overwrite

- Heap Overwrite
- XMAN 2016 fengshui(紫荆花 pwn)，SSC安全大会百度展厅 heapcanary，攻防世界 babyfengshui

#### Fastbin attack

- Fastbin attack
- alictf 2016 fb，alictf 2016 starcraft，0ctf 2016 zerostorage(较难), alictf 2016 starcraft，0ctf 2016 zerostorage(较难), 0ctf 2016 zerostorage(较难)

##### Global_max_fast

- `2.23`版本位于`0x3c67f8`处, 修改后可将fastbin范围扩大，更容易使用fastbin相关攻击。

#### Fastbin dup consolidate

- Fastbin dup consolidate

#### Large bin attack

- Large bin attack

#### Unsorted bin attack

- Unsorted bin attack
- 0ctf2016 Zerostorage

#### Overwrite Topchunk

- House of Force
- BCTF 2016 bcloud, BCTF 2016 ruin(arm结构)

#### Unlink

- Modern Unlink Attack
- Classical Unlink Attack(现glibc中有检查，不可用)
- Hitcon 2014 qualifier, MMA CTF 2016 Dairy，PlaidCTF 2014 200 ezhp

#### Off by one & Off by bull

[Glibc_Adventures-The_Forgotten_Chunks.pdf](https://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=&ved=2ahUKEwiDu_Lc_u_qAhXGGaYKHeMCCTAQFjAAegQIBBAB&url=https://go.contextis.com/rs/140-OCV-459/images/Glibc_Adventures-The_Forgotten_Chunks.pdf&usg=AOvVaw0lgQoKkgRucjSg_rC4bojF)

- **off by one**: MMA CTF 2016 Dairy
- **off by null**: plaid CTF 2015 datastore，XMAN 2016 Final love_letter

#### Chunk extend

- Chunk extend

#### Chunk shrink

- Chunk shrink

#### House of

##### House of spirit

- House of spirit
- I-ctf2016-pwn200

##### House of Einherjar

- ##### House of Force

- 

##### House of Lore

- ##### House of Orange

- 

##### House of Rabbit

- ##### House of Roman

- 

##### House-of-Corrosion

- #### Heap spray(堆喷)

- pwnhub.cn calc

#### Heap fengshui(堆风水/堆排布)

- Heap fengshui

#### 

#### Exploit mmap chunk

- Hitcon 2014 qualifier stkof
- 0ops培训资料 [Linux heap internal.pdf](https://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=&ved=2ahUKEwjojPetgPDqAhWJMd4KHUHDBicQFjAAegQIBRAB&url=https://raw.githubusercontent.com/veritas501/attachment_in_blog/ff24f5a79f4854157e8ce50b6810d1508d14ea9f/Linux%20Heap%20Internals/Linux%20Heap%20Internals.pdf&usg=AOvVaw3Uq6oCNYH8sJNFqSYrZSDi)

#### 改写more core

- HCTF 2016 5-days

#### House of Orange : 改写_IO_list_all

- Hitcon 2016House of orange

## IO

- 相关结构

## Kernel

[源码地址](https://elixir.bootlin.com/linux)

### 解压内核镜像

[extract-vmlinux](https://github.com/torvalds/linux/blob/master/scripts/extract-vmlinux)

### 环境配置

[Linux Kernel 环境配置](https://lantern.cool/2020/07/14/note-pwn-linux-kernel-environment/)

### Basics

[Linux Kernel Basics](https://lantern.cool/2020/07/13/note-pwn-linux-kernel-basics/)

### UAF

[Linux Kernel UAF](https://lantern.cool/2020/07/14/note-pwn-linux-kernel-UAF/)

### ROP

[Linux Kernel ROP](https://lantern.cool/2020/07/20/note-pwn-linux-kernel-rop/)

### Ret2usr

[Linux Kernel ret2usr](https://lantern.cool/2020/07/21/note-pwn-linux-kernel-ret2usr/)

### bypass-smep

Linux Kernel bypass-smep

### Double Fetch

## 格式化字符串

- 格式化字符串
- MMACTF 2016 greeting，HCTF 2016 fheap，RuCTF 2016 weather

## 条件竞争漏洞

- 安恒杯 武汉大学邀请赛 fackfuzz, stupid shell

## 代码逻辑漏洞

- UCTF 2016 note

## 类型漏洞

- CVE-2015-3077

## 缓冲区未初始化

- 栈未初始化时，栈中数据为上次函数调用留下的栈帧
- 堆未初始化时，堆中数据为上次使用该堆块所留下的数据
- UCTF 2016 note， 华山杯2016决赛 SU_PWN，33C3 CTF PWN

## 参考

[pwn中各种利用技巧1](https://nuoye-blog.github.io/2020/05/09/77b152fd/)
[pwn中各种利用技巧2](https://nuoye-blog.github.io/2020/05/09/eeb80347/)
[Atum大佬的CTF PWN选手养成](https://www.ichunqiu.com/course/57493)
[Glibc 堆利用的若干方法](http://jcs.iie.ac.cn/xxaqxb/ch/reader/create_pdf.aspx?file_no=20180101&flag=1&year_id=2018&quarter_id=1)