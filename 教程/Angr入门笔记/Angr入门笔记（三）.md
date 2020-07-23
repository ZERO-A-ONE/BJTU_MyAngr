# Angr入门笔记（三） 

- 当你拿到一个binary……
  - file
  - strings
  - ltrace/strace
  - gdb/OD
  - IDA

### 1.1 静态分析

- 静态分析——IDA
  - 优点
    - 程序覆盖
    - 可以找到多条执行路径
  - 缺点
    - How
    - 从哪开始
    - 怎么交互

### 1.2 动态分析

- 动态分析——gdb/OD
  - 优点
    - 可以查看内存寄存器的值
    - 结果准确
  - 缺点
    - 程序覆盖有限
    - 如何模拟真实环境

### 1.3 符号执行

- 符号执行就是在运行程序时，用符号来替代真实值。符号执行相较于真实值执行的优点在于，当使用真实值执行程序时，我们能够遍历的程序路径只有一条, 而使用符号进行执行时，由于符号是可变的，我们就可以利用这一特性，尽可能的将程序的每一条路径遍历，这样的话，必定存在至少一条能够输出正确结果的分支, 每一条分支的结果都可以表示为一个离散关系式,使用约束求解引擎即可分析出正确结果

### 2.1 Angr简介

- Angr是一个多架构的二进制分析平台，具备对二进制文件的动态符号执行能力和多种静态分析能力
- 装载二进制文件到分析平台
- 转换二进制文件为中间语言（intermediate representation）（IR）
- 转换IR为语义描述（即它做什么而不是它是什么）
- 执行真正的分析，这包括：
  - 部分或者全部的静态分析
  - 对程序状态空间的符号探索
  - 对上述的情况的一些混合

### 2.2 装载二进制文件

​	Angr的二进制装载组件是CLE，它负责装载二进制对象（以及它依赖的任何库）和把这个对象以易于操作的方式交给Angr的其他组件。使用Angr装载一个二进制文件（比如说，“/bin/true”），你需要这样做：

```python
import angr
b = angr.Project("/bin/true")
#这是二进制文件的入口点
print b.entry
#这些是二进制文件内存空间中的最小地址和最大地址
print b.loader.min_addr(), b.loader.max_addr()
#这些是文件的全名
print b.filename
```

### 2.3 中间语言

​	由于Angr需要处理很多不同的架构，所以它必须选择一种中间语言（IR）来进行它的分析。我们使用Valgrind的中间语言，VEX来完成这方面的内容。VEX中间语言抽象了几种不同架构间的区别，允许在他们之上进行统一的分析

例如：

`0x8000: dec eax`

转换为：

```
t0 = GET:I32(8)
t1 = Sub(t0,1)
PUT(8) = t1
PUT(68) = 0x8001
```

### 2.4 简单的脚本DEMO

无参数EXP示例：

```python
import angr
proj = angr.Project("./r100",auto_load_libs=False)
state = proj.factory.entry_state()
simgr = proj.factory.simgr(state)
simgr.explore(find=0x400844,avoid=0x400855) 
print simgr.found[0].posix.dumps(0)
```

有参数EXP示例：

```python
import angr
import claripy
proj = angr.Project("./ais3_crackme",auto_load_libs=False)
#BVS = Bit Vectors
argv1 = claripy.BVS('argv1',50*32) #50个32比特的字符，int类型4字节32个比特，char类型1字节8比特，以此类推
state = proj。factory.entry_state(args=['./ais3_crackme',argv1])
simgr = proj.factory.simgr(state)
simg.explore(find=0x400602,avoid=0x40060E)
#solver将BVS转换为ascii字符串
print simgr.found[0].solver.eval(argv1)
#cast_to参数选择转换类型，此处直接转换为字符串
print simgr.found[0].solver.eval(argv1，cast_to=str)
```

### 3.1 Z3简介

- Z3 is a theorem prover from Miscrosoft Reserch
- Z3 is a Stisfiablility Modulo Theories (SMT) solver
- https://github.com/Z3Prover/z3

应用示例：

```
EAX = 0x31337
EBX = (EAX/ECX)^ECX+5*EAX+ECX/3
if EBX = 2
ECX?
```

### 3.2 SMT可满足性模运算

- 之前学习利用Angr符号执行去寻找通路，它是类似于求解一个方程组的自动化过程，那么算式将会返回一个唯一的通道给我们。但是当判断条件不止一个，只遍历了一个判断条件就可能存在多种解答情况，例如x + y = 4，x和y的取值就不唯一了，可以是（0，4）（1，3）……我们就可以称x + y = 4是一个可满足性的特征
- 与可满足布尔型不同，SMT描述的不是一个确定的值（可理解为一个对象的实例）。他是对一个问题求解的特征描述（可理解为类）也就是这些答案结合需要满足的特征。所以一般的SMT会利用一个或一组这样的特征式来求解，再在他们的集合中找到交集

### 3.3 Z3 Demo

- x + y = 6
- 2x = 3y + 6
- How to slove it by z3?

示例EXP：

```python
from z3 import *
#Real实数类型
x = Real('x')
y = Real('y')
#Slover求解器
s = Solver()
#添加约束条件
s.add(x+y==6)
s.add(2*x===(3*y)+6)
#检查约束条件是否有交集，若为sat则为有交集
s.check()
#获取结果
m = s.model()
print m
```

### 3.4 Z3 Types

- BitVec：至特定大小的数据类型
- `BitVec("x",32)`对应C语言的int，因为int类型4字节共32比特
- `BitVec("x",8)`对应C语言中的char，因为char类型1字节共8比特

- Int
- Real
- Bool
- Array

一些需要注意的事情：

- z3中没有signed/unsigned类型
- 使用<，<=，>，>=，/，%，>> 操作signed类型变量
- 使用ULT，ULE，UGT，UDIV，Uremand，LShR操作unsigned类型变量
- 将BitVec的大小设成运算过程中最大的那个

### 3.5 CTF Demo

```python
from z3 import*
input = [BitVec('input_%d' % i,8) for i in range(32)] #char input[32]
s = Solver()
s.add(...)
if s.check()! = sat:
    print 'unsat'
else:
    m = s.model()
    print m
    print repr("".join([chr(m[input[i]].as_long()) for i in range(32)]))
```

示例EXP1：

```python
from z3 import *
xl = Real('xl')
xld = Real('xld')
xw = Real('xw')
xwg = Real('xwg')
s = Slover()
s.add(xl-xld==2)
s.add(xwg-xw==2)
s.add(xwg-xk==5)
s.check()
s.add(xld+xw-40==15)
s.check()
m = s.model()
print m
```

示例EXP2：

```python
from z3 import *
state = 42
def dish(d)
	global state
    state = ((state + d) * 3294782) ^ 3159238819
input = [BitVec('input_d%' % i,32) for i in range(32)]
s = Solver()
for idx in range(32):
    dish(input[idx])
s.add(state == 0xde11c105)
for i in range(32):
    s.add(input[i]>=0,input[i]<=0xff)
if s.check() != sat:
    print 'unsat'
else:
    m = s.model()
    print m
    print repr("".join([chr(m[input[i]].as_long()) for i in range(32)]))
```

