## PWNTOOLS个人手册

项目主页：http://pwntools.com/

项目地址：https://github.com/Gallopsled/pwntools

## 安装

```
＃更新包
sudo apt-get update
＃安装必要的组件
sudo apt-get install -y python2.7 python -pip python-dev git libssl-dev libffi-dev build-essential
＃升级Python的包管理器
pip install --upgrade pip
＃安装pwntools 
sudo pip install --upgrade pwntools
```

## 模块列表

```
- pwnlib.adb — Android Debug Bridge
- pwnlib.asm — Assembler functions
- pwnlib.encoders — Encoding Shellcode
- pwnlib.elf — ELF Executables and Libraries
- pwnlib.exception — Pwnlib exceptions
- pwnlib.flag — CTF Flag Management
- pwnlib.fmtstr — Format string bug exploitation tools
- pwnlib.gdb — Working with GDB
- pwnlib.log — Logging stuff
- pwnlib.protocols — Wire Protocols
- pwnlib.rop — Return Oriented Programming
- pwnlib.runner — Running Shellcode
- pwnlib.shellcraft — Shellcode generation
- pwnlib.shellcraft.<architecture>
- pwnlib.term — Terminal handling
- pwnlib.timeout — Timeout handling
- pwnlib.tubes — Talking to the World!
- pwnlib.tubes.<process|serialtube|SSH>
- pwnlib.update — Updating Pwntools
- pwnlib.useragents — A database of useragent strings
- pwnlib.util.cyclic — Generation of unique sequences
- pwnlib.util.fiddling — Utilities bit fiddling
- pwnlib.util.net — Networking interfaces
- pwnlib.util.packing — Packing and unpacking of strings
```

## 使用

```
from pwn import *
```

## 模块介绍

**常用模块如下：**

- asm : 汇编与反汇编，支持x86/x64/arm/mips/powerpc等基本上所有的主流平台
- dynelf : 用于远程符号泄漏，需要提供leak方法
- elf : 对elf文件进行操作
- gdb : 配合gdb进行调试
- memleak : 用于内存泄漏
- shellcraft : shellcode的生成器
- tubes : 包括tubes.sock, tubes.process, tubes.ssh, tubes.serialtube，分别适用于不同场景的PIPE
- utils : 一些实用的小功能，例如CRC计算，cyclic pattern等

### 链接

```
本地 ：sh = porcess("./level0")
远程：sh = remote("127.0.0.1",10001)
关闭连接：sh.close()  
```

pwn库中最常用的部分之一是，它允许您轻松地连接到Web服务并执行操作。pwntools的[入门文档](https://docs.pwntools.com/en/stable/intro.html)中包含的一个示例是连接到overthewire的 bandit CTF实验室。Overthewire是一款在线信息安全CTF通关网站，你可以在线Hacking,并为任何刚接触Linux / CLI 等的初级人员提供了手把手教学。
我们可以利用pwn库创建到主机的SSH连接，并对其运行任意命令。每个bandit级别的目标是找到进入下一级别的密码。例如：利用pwntools，您可以开发一个脚本来将SSH连接到目标主机，并运行一系列自动信息收集探针，以确定如何以最佳方式对其进行攻击。
一个不错的例子

```
# Connect to the target
shell = ssh('bandit0', 'bandit.labs.overthewire.org', password='bandit0', port=2220)
# Create an initial process
sh = shell.run('sh')
# Send the process arguments
sh.sendline('ls -la')
# Receive output from the executed command
sh.recvline(timeout=5)
...
...
# Obtain the first flag (password for bandit1)
sh.sendline('cat readme')
# Print the flag
sh.recvline(timeout=5)
```

### IO模块

```
sh.send(data)  发送数据
sh.sendline(data)  发送一行数据，相当于在数据后面加\n
sh.recv(numb = 2048, timeout = dufault)  接受数据，numb指定接收的字节，timeout指定超时
sh.recvline(keepends=True)  接受一行数据，keepends为是否保留行尾的\n
sh.recvuntil("Hello,World\n",drop=fasle)  接受数据直到我们设置的标志出现
sh.recvall()  一直接收直到EOF
sh.recvrepeat(timeout = default)  持续接受直到EOF或timeout
sh.interactive()  直接进行交互，相当于回到shell的模式，在取得shell之后使用
```

### 汇编和反汇编

汇编：

```
>>> asm('nop')
'\x90'
>>> asm('nop', arch='arm')
'\x00\xf0 \xe3'
```

可以使用context来指定cpu类型以及操作系统。context是pwntools用来设置环境的功能。在很多时候，由于二进制文件的情况不同，我们可能需要进行一些环境设置才能够正常运行exp，比如有一些需要进行汇编，但是32的汇编和64的汇编不同，如果不设置context会导致一些问题。

```
>>> context.arch      = 'i386'
>>> context.os        = 'linux'
>>> context.endian    = 'little'
>>> context.word_size = 32
```

一般来说我们设置context只需要简单的一句话:

```
context(os='linux', arch='amd64', log_level='debug')
```

使用disasm进行反汇编

```
>>> print disasm('6a0258cd80ebf9'.decode('hex'))
   0:   6a 02                   push   0x2
   2:   58                      pop    eax
   3:   cd 80                   int    0x80
   5:   eb f9                   jmp    0x0
```

注意，asm需要binutils中的as工具辅助，如果是不同于本机平台的其他平台的汇编，例如在我的x86机器上进行mips的汇编就会出现as工具未找到的情况，这时候需要安装其他平台的cross-binutils

### shellcode生成器

```
>>> print shellcraft.i386.nop().strip('\n')
    nop
>>> print shellcraft.i386.linux.sh()
    /* push '/bin///sh\x00' */
    push 0x68
    push 0x732f2f2f
    push 0x6e69622f
...
```

结合asm可以可以得到最终的pyaload

```
from pwn import *
context(os='linux',arch='amd64')
shellcode = asm(shellcraft.sh())

或者

from pwn import *
shellcode = asm(shellcraft.amd64.linux.sh())
```

除了直接执行sh之外，还可以进行其它的一些常用操作例如提权、反向连接等等

#### ELF文件操作

```
>>> e = ELF('/bin/cat')
>>> print hex(e.address)  # 文件装载的基地址
0x400000
>>> print hex(e.symbols['write']) # 函数地址
0x401680
>>> print hex(e.got['write']) # GOT表的地址
0x60b070
>>> print hex(e.plt['write']) # PLT的地址
0x401680
>>> print hex(e.search('/bin/sh').next())# 字符串/bin/sh的地址
```

### 整数pack与数据unpack

pack：p32，p64
unpack：u32，u64

```
from pwn import *
elf = ELF('./level0')
sys_addr = elf.symbols['system']
payload = 'a' * (0x80 + 0x8) + p64(sys_addr)
...
```

还可以调整大端序和小端序

```
# Create some variable with an address
addr = 0xabcdef12
# 32-bit: Big Endian
p32(addr, endian="big"
# 32-bit: Little Endian
p32(addr, endian="big"
# 32-bit: Default is Little Endian
p32(addr)
# 64-bit: Big Endian
p64(addr, endian="big")
# 64-bit: Little Endian
p64(addr, endian="small")
# 64-bit: Default is Little Endian
p64(addr)
```

### ROP链生成器

```
elf = ELF('ropasaurusrex')
rop = ROP(elf)
rop.read(0, elf.bss(0x80))
rop.dump()
# ['0x0000:        0x80482fc (read)',
#  '0x0004:       0xdeadbeef',
#  '0x0008:              0x0',
#  '0x000c:        0x80496a8']
str(rop)
# '\xfc\x82\x04\x08\xef\xbe\xad\xde\x00\x00\x00\x00\xa8\x96\x04\x08'
```

使用ROP(elf)来产生一个rop的对象，这时rop链还是空的，需要在其中添加函数。

因为ROP对象实现了**getattr**的功能，可以直接通过func call的形式来添加函数，rop.read(0, elf.bss(0x80))实际相当于rop.call('read', (0, elf.bss(0x80)))。
 通过多次添加函数调用，最后使用str将整个rop chain dump出来就可以了。

- call(resolvable, arguments=()) : 添加一个调用，resolvable可以是一个符号，也可以是一个int型地址，注意后面的参数必须是元组否则会报错，即使只有一个参数也要写成元组的形式(在后面加上一个逗号)
- chain() : 返回当前的字节序列，即payload
- dump() : 直观地展示出当前的rop chain
- raw() : 在rop chain中加上一个整数或字符串
- search(move=0, regs=None, order=’size’) : 按特定条件搜索gadget
- unresolve(value) : 给出一个地址，反解析出符号

### 数据输出

如果需要输出一些信息,最好使用pwntools自带的,因为和pwntools本来的格式吻合,看起来也比较舒服,用法:

```
some_str = "hello, world"
log.info(some_str)
```

其中的info代表是log等级，也可以使用其他log等级