# GDB自动化脚本编写笔记一

作为UNIX/Linux下使用广泛的调试器，gdb不仅提供了丰富的命令，还引入了对脚本的支持：一种是对已存在的脚本语言支持，比如python，用户可以直接书写python脚本，由gdb调用python解释器执行；另一种是命令脚本，用户可以在脚本中书写gdb已经提供的或者自定义的gdb命令，再由gdb执行

我们通常都是在交互模式下使用 GDB 的，即手动输入各种 GDB 命令。其实 GDB 也支持执行预先写好的调试脚本，进行自动化的调试。调试脚本由一系列的 GDB 命令组成，GDB 会顺序执行调试脚本中的命令

## 引子

下面是一个带bug的二分查找实现：

```c
#include <iostream>
using std::cout;
using std::endl;

int binary_search(int *ary, unsigned int ceiling, int target)
{
    unsigned int floor = 0;
    while (ceiling > floor) {
        unsigned int pivot = (ceiling + floor) / 2;
        if (ary[pivot] < target)
            floor = pivot + 1;
        else if (ary[pivot] > target)
            ceiling = pivot - 1;
        else
            return pivot;
    }
    return -1;
}

int main()
{
    int a[] = {1, 2, 4, 5, 6};
    cout << binary_search(a, 5, 7) << endl; // -1
    cout << binary_search(a, 5, 6) << endl; // 4
    cout << binary_search(a, 5, 5) << endl; // 期望3，实际运行结果是-1
    return 0;
}
```

你打算调试下`binary_search(a, 5, 5)`这个组合。若如果用print大法，就在`binary_search`中插入几个print，运行后扫一眼，看看`target=5`的时候运行流是怎样的

debugger大法看似会复杂一点，如果在`binary_search`中插断点，那么前两次调用只能连按`c`跳过。其实没那么复杂，gdb允许用户设置条件断点。你可以这么设置：

```c
b binary_search if target == 5
```

现在就只有第三次调用会触发断点

问题看上去跟`floor`和`ceiling`值的变化有关。要想观察它们的值，可以`p floor`和`p ceiling`。不过有个简单的方法，你可以对它们设置watch断点：`wa floor if target == 5`。当`floor`的值变化时，就会触发断点

对于我们的示例程序来说，靠脑补也能算出这两个值的变化，专门设置断点似乎小题大做。不过在调试真正的程序时，watch断点非常实用，尤其当你对相关代码不熟悉时。使用watch断点可以更好地帮助你理解程序流程，有时甚至会有意外惊喜。另外结合debugger运行时修改值的能力，你可以在值变化的下一刻设置目标值，观察走不同路径会不会出现类似的问题。如果有需要的话，还可以给某个内存地址设断点：`wa *0x7fffffffda40`

除了watch之外，gdb还有一类catch断点，可以用来捕获异常/系统调用/信号。因为用途不大（我从没实际用过），就不介绍了，感兴趣的话在gdb里面`help catch`看看

## commands

编写调试脚本时必须要处理好断点的问题。在交互模式下，程序执行至脚本时，GDB 会等待用户输入下一步的命令。如何在脚本中定义断点触发时进行的操作？这需要一种类似回调函数的机制

GDB 中使用 **Breakpoint Command Lists** 的机制来实现这一点，可以给某个断点挂上待触发的命令。用户可以定义，当程序停在某个 breakpoint (或 watchpoint, catchpoint) 时，执行由 `command-list` 定义的一系列命令。其语法为：

```c
commands [list…]
… command-list …
end
```

例如，我想在每次进入 `foo` 函数且其参数 `x` > 0 时打印 `x` 的值：

```c
break foo if x>0
commands
silent
printf "x is %d\n",x
continue
end
```

这里有几点要注意的：

- Breakpoint command list 中的第一个命令通常是 `silent`。这会让断点触发是打印的消息尽量精简。如果 `command … end` 中没有 `printf` 之类的打印语句，断点触发时甚至不会产生任何输出
- Breakpoint command list 中的最后一个命令通常是 `continue`。这样程序不会在断点处停下，自动化调试脚本可以继续执行

GDB 运行自动化调试脚本的方式为：

```c
gdb [program] -batch -x [commands_file] > log
```

其中 `-batch` 参数将 GDB 运行为脚本模式（不进入交互环境），`-x` 参数 (也可以写为 `-command`) 指定调试脚本文件

## define

举个例子，继续上面的二分查找操作`b binary_search if target == 5`之后，输入：

```
comm
i locals
i args
end
```

按照之前的格式也可以是

```
b binary_search if target == 5
commands
silent
i locals
i args
continue
end
```

这样当上面的断点被触发时，`i locals`和`i args`命令会被触发，列出当前上下文内的变量。这个功能挺废的，因为你完全可以在断点被触发后才敲入这几个命令

要不是有`define`，`commands`就真成摆设了。接下来我们要介绍`commands`的好基友、最强大的gdb命令之一，`define`命令

一如unix世界里面的许多程序一样，gdb内部实现了一门DSL（领域特定语言）。用户可以通过这门DSL来编写自定义的宏，甚至编写调试用的自动化脚本。我们可以用`define`命令编写自定义的宏

继续上面的例子，你可以自定义一个命令代替`b xxx comm ...`：

```c
(gdb) define br_info
Type commands for definition of "br_info".
End with a line saying just "end".
>b $arg0
>comm
>i locals
>i args
>end
(gdb) br_info binary_search if target == 5
```

当`if target == 5`条件满足时，`br_info binary_search`会被执行。`br_info`展开成为一系列命令，并用`binary_search`替换掉`$arg0`。一行顶过去五行

其实`define`也就是自定义命令，格式是：

```
define commandName  
    statement  
    ......  
end  
```

其中`statement`可以是任意gdb命令。此外自定义命令还支持最多10个输入参数：`$arg0`，`$arg1` …… `$arg9`，并且还用`$argc`来标明一共传入了多少参数

则上面的命令可以写为脚本

```c
define br_info
	b $arg0
	commands
	silent
	i locals
	i args
	continue
	end
```

除了在会话内创建自定义宏外，我们还可以用gdb的DSL编写宏文件，并导入到gdb中

举个有实际意义的例子。由于源代码的改变，我们需要更新断点的位置。通常的做法是删掉原来的断点，并新设一个。让我们现学现用，用宏把这两步合成一步：

```c
# gdb_macro
define mv
    if $argc == 2 # argc即总参数个数
        delete $arg0 # arg0即第一个参数
        # 注意新创建的断点编号和被删除断点的编号不同
        break $arg1 # arg1即第二个参数
    else
        print "输入参数数目不对，help mv以获得用法"
    end
end

# (gdb) help mv 会输出以下帮助文档
document mv
Move breakpoint.
Usage: mv old_breakpoint_num new_breakpoint
Example:
    (gdb) mv 1 binary_search -- move breakpoint 1 to `b binary_search`

end
# vi:set ft=gdb ts=4 sw=4 et
```

使用方法：

```
(gdb) b binary_search
Breakpoint 1 at 0x40083b: file binary_search.cpp, line 7.
(gdb) source ~/gdb_macro
(gdb) help mv
Move breakpoint.
Usage: mv old_breakpoint_num new_breakpoint
Example:
    (gdb) mv 1 binary_search -- move breakpoint 1 to `b binary_search`

(gdb) mv 1 binary_search.cpp:18
Breakpoint 2 at 0x4008ab: file binary_search.cpp, line 18.
```

在gdb中执行脚本要使用source命令，例如：“source xxx.gdb”

还可以进一步，把`source ~/gdb_macro`也省掉。你可以创建gdb配置文件`~/.gdbinit`，让gdb启动时自动执行里面的指令。如果把自己常用的宏写在该文件中，就能直接在gdb里面使用了，用起来如内置命令一般顺滑

## document

除此以外，还可以为自定义命令写帮助文档，也就是执行`help`命令时打印出的信息：

```
document myassign
    assign the second parameter value to the first parameter
end
```

## 会话/历史/命令文件

通常我们只有在程序出问题才会启动gdb，开始调试工作，调试完毕后退出。不过，让gdb一直开着未尝不是更好的做法。每个gdb老司机都懂得，gdb在`r`的时候会加载当前程序的最新版本。也即是说，就算不退出gdb，每次运行的也会是当前最新的版本。不退出当前调试会话有两个好处：

1. 调试上下文可以得到保留。不用每次运行都重新设一轮断点
2. 一旦core dump了，可以显示core dump的位置，无需带着core重新启动一次

在开发C/C++项目，我一般是这样的工作流程：一个窗口开着编辑器，编译也在这个窗口执行；另一个窗口开着gdb，这个窗口同时也用来运行程序。一旦要调试了（或者，又segment fault了），随手就可以开始干活

当然了，劳作一天之后，总需要关电脑回家。这时候只能退出gdb。不想明天一早再把断点设上一遍？gdb提供了保留断点的功能。输入`save br .gdb_bp`，gdb会把本次会话的断点存在`.gdb_bp`中。明天早上一回来，启动gdb的时候，加上`-x .gdb_bp`，让gdb把`.gdb_bp`当做命令文件逐条重新执行，一切又回到昨晚

## 调试脚本

提到用`-x`指定命令文件来回放断点。那时的命令文件也算是一种用gdb的DSL编写的调试脚本。由于调试是件交互性的活，需要事先写好调试脚本的场景不多。即使如此，除了让gdb自动设置断点，依然有不少场景下可以用上调试脚本。其中之一，就是让gdb自动采集特定函数调用的上下文数据。我把这种方法称为“拖网法”，因为它就像拖网捕鱼一样，把逮到的东西都一股脑带上来

设想如下的情景：某个项目出现内存泄露的迹象。事先分配好的内存池用着用着就满了，一再地吞噬系统的内存。内存管理是自己实现的，所以无法用valgrind来分析。鉴于内存管理部分代码最近几个版本都没有改动过，猜测是业务逻辑代码里面有谁借了内存又不还。现在你需要把它揪出来。一个办法是给内存的分配和释放加上日志，再编译，然后重新运行程序，谋求复现内存泄露的场景。不过更快的办法是，敲上这一段代码：

（假设分配内存的接口是`my_malloc(char *p, size_t size)`，释放内存的接口是`free(char *p)`）

```
# /tmp/malloc_free
# 设置输出不要分屏
set pagination off
b my_malloc
comm
silent
printf "malloc 0x%x %lu\n", p, size
bt
c
end

b my_free
comm
silent
printf "free 0x%x\n", p
bt
c
end
c
```

直接让gdb执行它：

```
sudo gdb -q -p $(pidof $your_project) -x /tmp/malloc_free > log
```

运行一段时间后kill掉gdb，打开log看看里面的内容：

```
$ less log
Attaching to process 8738
Reading symbols from ...done.
Reading symbols from /lib/x86_64-linux-gnu/libc.so.6...Reading symbols from /usr/
lib/debug//lib/x86_64-linux-gnu/libc-2.19.so...done.
done.
Loaded symbols for /lib/x86_64-linux-gnu/libc.so.6
......
malloc 0x0 82
#0  my_malloc (p=0x0, size=82) at memory.cpp:8
#1  0x0000000000400657 in write_buffer (p=0x0, size=82) at memory.cpp:17
#2  0x00000000004006b6 in main () at memory.cpp:25
malloc 0x852c39c0 13
#0  my_malloc (p=0x7ffd852c39c0 "\001", size=13) at memory.cpp:8
#1  0x0000000000400657 in write_buffer (p=0x7ffd852c39c0 "\001", size=13) at memory.cpp:17
#2  0x00000000004006b6 in main () at memory.cpp:25
free 0x400780
#0  my_free (p=0x400780 <__libc_csu_init> "AWA\211\377AVI\211\366AUI\211\325ATL\215%x\006 ") at memory.cpp:14
#1  0x0000000000400632 in read_buffer (p=0x400780 <__libc_csu_init> "AWA\211\377AVI\211\366AUI\211\325ATL\215%x\006 ") at memory.cpp:16
#2  0x00000000004006fe in main () at memory.cpp:28
free 0x0
......
```

现在我们可以写个脚本对下帐。每次解析到`malloc`时，在对应指针的名下记下一项借出。解析到`free`时，表示销掉对应最近一次借出的还款。把全部输出解析完后，困扰已久的坏账情况就将水落石出，欠钱不还的老赖也将无可遁形。这种“拖网法”真的是简单粗暴又有效

我们还可以用这种“拖网法”获取指定函数的调用者比例、调用参数的分布范围等等。注意，不要在生产环境撒网，毕竟这么做对性能有显著影响。而且要做统计的话，也有更好的方法可以选

## 实战

题目：reverse-box

来源：mma-ctf-2nd-2016

- #### IDA分析代码

```c
int __cdecl main(int a1, char **a2) //a2即为二维数组
{
  size_t i; // [esp+18h] [ebp-10Ch]
  int v4; // [esp+1Ch] [ebp-108h]
  unsigned int v5; // [esp+11Ch] [ebp-8h]

  v5 = __readgsdword(0x14u);
  if ( a1 <= 1 )
  {
    printf("usage: %s flag\n", *a2);//a2[0]存输入的数据
    exit(1);
  }
  sub_804858D(&v4);
  for ( i = 0; i < strlen(a2[1]); ++i )
    printf("%02x", *((unsigned __int8 *)&v4 + a2[1][i]));
  putchar(10);
  return 0;
}
```

可以发现关键功能函数**sub_804858D**

```c
int __cdecl sub_804858D(_BYTE *a1)
{
  unsigned int v1; // eax
  int v2; // edx
  char v3; // al
  char v4; // ST1B_1
  char v5; // al
  int result; // eax
  unsigned __int8 v7; // [esp+1Ah] [ebp-Eh]
  char v8; // [esp+1Bh] [ebp-Dh]
  char v9; // [esp+1Bh] [ebp-Dh]
  int v10; // [esp+1Ch] [ebp-Ch]

  v1 = time(0);
  srand(v1);
  do
    v10 = (unsigned __int8)rand();
  while ( !v10 );
  *a1 = v10;
  v7 = 1;
  v8 = 1;
  do
  {
    v2 = v7 ^ 2 * v7;
    if ( (v7 & 0x80u) == 0 )
      v3 = 0;
    else
      v3 = 27;
    v7 = v2 ^ v3;
    v4 = 4 * (2 * v8 ^ v8) ^ 2 * v8 ^ v8;
    v9 = 16 * v4 ^ v4;
    if ( v9 >= 0 )
      v5 = 0;
    else
      v5 = 9;
    v8 = v9 ^ v5;
    result = (unsigned __int8)__ROR1__(v8, 4) ^ (unsigned __int8)__ROR1__(v8, 5) ^ (unsigned __int8)__ROR1__(v8, 6) ^ (unsigned __int8)__ROR1__(v8, 7) ^ (unsigned __int8)(v8 ^ *a1);
    a1[v7] = result;
  }
  while ( v7 != 1 );
  return result;
}
```

根绝srand、rand、time函数大概可以猜测即为生成一张随机数表，就可以使用GDB脚本爆出盒子

- 注意看此函数的汇编代码，在取随机数种子的位置：

```
.text:080485A7                 call    _rand
.text:080485AC                 and     eax, 0FFh
.text:080485B1                 mov     [ebp+var_C], eax
```

- 程序的流程很简单，就是先以时间做种子，取随机数生成一张表，然后输入作为表的索引，输出对应表中的十六进制数据
- 题目给出的目标输出为：**95eeaf95ef94234999582f722f492f72b19a7aaf72e6e776b57aee722fe77ab5ad9aaeb156729676ae7a236d99b1df4a**
- 实际上就是要求输入是多少

下面是GDB脚本

```c
set $i=0
set $total=256
while($i<$total)
　　b *0x080485B1	#mov     [ebp+var_C], eax 即程序取随机函数后的地址 方便修改种子数
　　b *0x8048704 #movzx   eax, al，即程序最终结果的地址
　　run T	#开始跑程序
　　set $eax=$i #使得种子数等于爆破值i
　　set $i=$i+1 #i=i+1
　　continue #使得程序继续调试
　　if ($eax==0x95) #当等于正确答案时打印表
　　　　print $i, $i	#打印出正确的种子数
　　　　x/256xb $esp+0x1c #打印盒子表
　　　　set $i=256	#使得i=256退出循环
　　end
　　stop
end
```

跑出来的结果

```
$1 = 215
0xffffcf6c:	0xd6	0xc9	0xc2	0xce	0x47	0xde	0xda	0x70
0xffffcf74:	0x85	0xb4	0xd2	0x9e	0x4b	0x62	0x1e	0xc3
0xffffcf7c:	0x7f	0x37	0x7c	0xc8	0x4f	0xec	0xf2	0x45
0xffffcf84:	0x18	0x61	0x17	0x1a	0x29	0x11	0xc7	0x75
0xffffcf8c:	0x02	0x48	0x26	0x93	0x83	0x8a	0x42	0x79
0xffffcf94:	0x81	0x10	0x50	0x44	0xc4	0x6d	0x84	0xa0
0xffffcf9c:	0xb1	0x72	0x96	0x76	0xad	0x23	0xb0	0x2f
0xffffcfa4:	0xb2	0xa7	0x35	0x57	0x5e	0x92	0x07	0xc0
0xffffcfac:	0xbc	0x36	0x99	0xaf	0xae	0xdb	0xef	0x15
0xffffcfb4:	0xe7	0x8e	0x63	0x06	0x9c	0x56	0x9a	0x31
0xffffcfbc:	0xe6	0x64	0xb5	0x58	0x95	0x49	0x04	0xee
0xffffcfc4:	0xdf	0x7e	0x0b	0x8c	0xff	0xf9	0xed	0x7a
0xffffcfcc:	0x65	0x5a	0x1f	0x4e	0xf6	0xf8	0x86	0x30
0xffffcfd4:	0xf0	0x4c	0xb7	0xca	0xe5	0x89	0x2a	0x1d
0xffffcfdc:	0xe4	0x16	0xf5	0x3a	0x27	0x28	0x8d	0x40
0xffffcfe4:	0x09	0x03	0x6f	0x94	0xa5	0x4a	0x46	0x67
0xffffcfec:	0x78	0xb9	0xa6	0x59	0xea	0x22	0xf1	0xa2
0xffffcff4:	0x71	0x12	0xcb	0x88	0xd1	0xe8	0xac	0xc6
0xffffcffc:	0xd5	0x34	0xfa	0x69	0x97	0x9f	0x25	0x3d
0xffffd004:	0xf3	0x5b	0x0d	0xa1	0x6b	0xeb	0xbe	0x6e
0xffffd00c:	0x55	0x87	0x8f	0xbf	0xfc	0xb3	0x91	0xe9
0xffffd014:	0x77	0x66	0x19	0xd7	0x24	0x20	0x51	0xcc
0xffffd01c:	0x52	0x7d	0x82	0xd8	0x38	0x60	0xfb	0x1c
0xffffd024:	0xd9	0xe3	0x41	0x5f	0xd0	0xcf	0x1b	0xbd
0xffffd02c:	0x0f	0xcd	0x90	0x9b	0xa9	0x13	0x01	0x73
0xffffd034:	0x5d	0x68	0xc1	0xaa	0xfe	0x08	0x3e	0x3f
0xffffd03c:	0xc5	0x8b	0x00	0xd3	0xfd	0xb6	0x43	0xbb
0xffffd044:	0xd4	0x80	0xe2	0x0c	0x33	0x74	0xa8	0x2b
0xffffd04c:	0x54	0x4d	0x2d	0xa4	0xdc	0x6c	0x3b	0x21
0xffffd054:	0x2e	0xab	0x32	0x5c	0x7b	0xe0	0x9d	0x6a
0xffffd05c:	0x39	0x14	0x3c	0xb8	0x0a	0x53	0xf7	0xdd
0xffffd064:	0xf4	0x2c	0x98	0xba	0x05	0xe1	0x0e	0xa3
```

最后的解密脚本

```python
correct='95eeaf95ef94234999582f722f492f72b19a7aaf72e6e776b57aee722fe77ab5ad9aaeb156729676ae7a236d99b1df4a'
box=[\
0xd6,0xc9,0xc2,0xce,0x47,0xde,0xda,0x70,\
0x85,0xb4,0xd2,0x9e,0x4b,0x62,0x1e,0xc3,\
0x7f,0x37,0x7c,0xc8,0x4f,0xec,0xf2,0x45,\
0x18,0x61,0x17,0x1a,0x29,0x11,0xc7,0x75,\
0x02,0x48,0x26,0x93,0x83,0x8a,0x42,0x79,\
0x81,0x10,0x50,0x44,0xc4,0x6d,0x84,0xa0,\
0xb1,0x72,0x96,0x76,0xad,0x23,0xb0,0x2f,\
0xb2,0xa7,0x35,0x57,0x5e,0x92,0x07,0xc0,\
0xbc,0x36,0x99,0xaf,0xae,0xdb,0xef,0x15,\
0xe7,0x8e,0x63,0x06,0x9c,0x56,0x9a,0x31,\
0xe6,0x64,0xb5,0x58,0x95,0x49,0x04,0xee,\
0xdf,0x7e,0x0b,0x8c,0xff,0xf9,0xed,0x7a,\
0x65,0x5a,0x1f,0x4e,0xf6,0xf8,0x86,0x30,\
0xf0,0x4c,0xb7,0xca,0xe5,0x89,0x2a,0x1d,\
0xe4,0x16,0xf5,0x3a,0x27,0x28,0x8d,0x40,\
0x09,0x03,0x6f,0x94,0xa5,0x4a,0x46,0x67,\
0x78,0xb9,0xa6,0x59,0xea,0x22,0xf1,0xa2,\
0x71,0x12,0xcb,0x88,0xd1,0xe8,0xac,0xc6,\
0xd5,0x34,0xfa,0x69,0x97,0x9f,0x25,0x3d,\
0xf3,0x5b,0x0d,0xa1,0x6b,0xeb,0xbe,0x6e,\
0x55,0x87,0x8f,0xbf,0xfc,0xb3,0x91,0xe9,\
0x77,0x66,0x19,0xd7,0x24,0x20,0x51,0xcc,\
0x52,0x7d,0x82,0xd8,0x38,0x60,0xfb,0x1c,\
0xd9,0xe3,0x41,0x5f,0xd0,0xcf,0x1b,0xbd,\
0x0f,0xcd,0x90,0x9b,0xa9,0x13,0x01,0x73,\
0x5d,0x68,0xc1,0xaa,0xfe,0x08,0x3e,0x3f,\
0xc5,0x8b,0x00,0xd3,0xfd,0xb6,0x43,0xbb,\
0xd4,0x80,0xe2,0x0c,0x33,0x74,0xa8,0x2b,\
0x54,0x4d,0x2d,0xa4,0xdc,0x6c,0x3b,0x21,\
0x2e,0xab,0x32,0x5c,0x7b,0xe0,0x9d,0x6a,\
0x39,0x14,0x3c,0xb8,0x0a,0x53,0xf7,0xdd,\
0xf4,0x2c,0x98,0xba,0x05,0xe1,0x0e,0xa3\
]
flag=''
for i in range(len(correct)//2):
    idx=box.index(int(correct[2*i:2*i+2],16))
    flag+=chr(idx)
print flag
```

## 参考资料

【1】[GDB 自动化操作的技术](https://segmentfault.com/a/1190000005367875)

【2】[用 Python 拓展 GDB（一）](https://segmentfault.com/a/1190000005718889)

【3】[GDB 自动化调试](https://nettee.github.io/posts/2018/GDB-automated-debugging/)

【4】[GDB User Manual](https://sourceware.org/gdb/current/onlinedocs/gdb/)