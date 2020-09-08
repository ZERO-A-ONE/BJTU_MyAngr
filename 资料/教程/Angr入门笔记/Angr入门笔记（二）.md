# Angr入门笔记（二）

使用 angr 的大概步骤：

- 创建 project
- 设置 state
- 新建 符号量 : BVS (bitvector symbolic ) 或 BVV (bitvector value)
- 把符号量设置到内存或者其他地方
- 设置 Simulation Managers ， 进行路径探索的对象
- 运行，探索满足路径需要的值
- 约束求解，获取执行结果

## 基本使用流程

- 载入二进制程序，auto_load_libs 是设置是否自动加载外部动态链接
  - `proj = angr.Project('./ctf_game',auto_load_libs = False)`
- 然后获取当前的入口状态
  - `state = proj.factory.entry_state()`
- 在获取到当前的入口状态后，模拟执行
  - `simg = proj.factory.simgr(state)`
- 模拟执行后产生多种状态，我们要选择最终要到达的（`find`），过滤掉不需要的(`avoid`)
  - `simg.explore(find = 0x400844, avoid = 0x400855)`
- 获取最终的状态结果
  - `simgr.found[0].posix.dumps(0) // dump(0)表示从标准输入中获取字符串`

## 详细解释

现在以一个简单的脚本为例子：

```python
import angr
import sys

def main(argv):
  # Create an Angr project.
  # If you want to be able to point to the binary from the command line, you can
  # use argv[1] as the parameter. Then, you can run the script from the command
  # line as follows:
  # python ./scaffold00.py [binary]
  # (!)
  path_to_binary = ???  # :string
  project = angr.Project(path_to_binary)

  # Tell Angr where to start executing (should it start from the main()
  # function or somewhere else?) For now, use the entry_state function
  # to instruct Angr to start from the main() function.
  initial_state = project.factory.entry_state()

  # Create a simulation manager initialized with the starting state. It provides
  # a number of useful tools to search and execute the binary.
  simulation = project.factory.simgr(initial_state)

  # Explore the binary to attempt to find the address that prints "Good Job."
  # You will have to find the address you want to find and insert it here. 
  # This function will keep executing until it either finds a solution or it 
  # has explored every possible path through the executable.
  # (!)
  print_good_address = ???  # :integer (probably in hexadecimal)
  simulation.explore(find=print_good_address)

  # Check that we have found a solution. The simulation.explore() method will
  # set simulation.found to a list of the states that it could find that reach
  # the instruction we asked it to search for. Remember, in Python, if a list
  # is empty, it will be evaluated as false, otherwise true.
  if simulation.found:
    # The explore method stops after it finds a single state that arrives at the
    # target address.
    solution_state = simulation.found[0]

    # Print the string that Angr wrote to stdin to follow solution_state. This 
    # is our solution.
    print solution_state.posix.dumps(sys.stdin.fileno())
  else:
    # If Angr could not find a path that reaches print_good_address, throw an
    # error. Perhaps you mistyped the print_good_address?
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
```

在这里逐行分析代码：

```python
import angr
import sys
```

导入angr和sys库，其中sys模块用于提供对解释器相关的操作

- sys.argv
  - 传递到Python脚本的命令行参数列表，第一个元素是程序本身路径
- sys.executable
  - 返回Python解释器在当前系统中的绝对路径
- sys.exit([arg])
  - 程序中间的退出，arg=0为正常退出
- sys.path
  - 返回模块的搜索路径，初始化时使用PYTHONPATH环境变量的值
- sys.platform
  - 返回操作系统平台名称，Linux是linux2，Windows是win32
- sys.stdout.write(str)
  - 输出的时候把换行符\n去掉
- val = sys.stdin.readline()[:-1]
  - 拿到的值去掉\n换行符
- sys.version
  - 获取Python解释程序的版本信息

### Project

```python
path_to_binary = ???
project = angr.Project(path_to_binary)
```

这里`path_to_binary`指定了需要解析的二进制可执行文件，`project = angr.Project(path_to_binary)`载入二进制文件使用 angr.Project 函数，它的第一个参数是待载入文件的路径，后面还有很多的可选参数，例如：

```python
p = angr.Project('./issue', load_options={"auto_load_libs": False})
```

|         名称          |            `描述`            |
| :-------------------: | :--------------------------: |
|   `auto_load_libs`    |    是否自动加载程序的依赖    |
|      `skip_libs`      |         避免加载的库         |
| `except_missing_libs` | 无法解析共享库时是否抛出异常 |
|   `force_load_libs`   |         强制加载的库         |
|       `ld_path`       |   共享库的优先搜索搜寻路径   |

auto_load_libs 设置是否自动载入依赖的库，如果设置为 True 的话会自动载入依赖的库，然后分析到库函数调用时也会进入库函数，这样会增加分析的工作量，也有能会跑挂。载入文件后，就可以通过 project 对象获取信息以及进行后面的操作

> - 如果 auto_load_libs 为 true, 那么程序如果调用到库函数的话就会直接调用真正的库函数 ，如果有的库函数逻辑比较复杂，可能分析程序就出不来了~~。同时 angr 使用 python 实现了很多的库函数（保存在 angr.SIM_PROCEDURES 里面），默认情况下会使用列表内部的函数来替换实际的函数调用，如果不在列表内才会进入到真正的 library
> - 如果 auto_load_libs 为 false ， 程序调用函数时，会直接返回一个 不受约束的符号值

**总而言之Project，创建了一个程序的初始镜像项目**

### state

```python
initial_state = project.factory.entry_state() 
simulation = project.factory.simgr(initial_state) 
```

state 代表程序的一个实例镜像，模拟执行某个时刻的状态。保存运行状态的上下文信息，如内存/寄存器等

在执行开始之前，我们通过设置 state 对象初始化寄存器/内存/栈帧等信息。在结束执行后，会返回 state 对象，可以提取需要的值进行求解。除了使用`.entry_state()` 创建 state 对象, 我们还可以根据需要使用其他构造函数创建 state:

|        名称        |                             描述                             |
| :----------------: | :----------------------------------------------------------: |
|  `.entry_state()`  |       返回程序入口地址的state，通常来说都会使用该状态        |
|   `.blank_state`   | 返回一个未初始化的state，此时需要主动设置入口地址，以及自己想要设置的参数。 |
|   `.call_state`    | When accessing uninitialized data, an unconstrained symbolic value  will be returned.constructs a state ready to execute a given function. |
| `.full_init_state` | 同entry_state(**kwargs) 类似，但是调用在执行到达入口点之前应该调用每个初始化函数 |

**总而言之，我们这里使用`project.factory.entry_state()`告诉符号执行引擎从程序的入口点开始符号执行**

### simulation

Project  对象仅表示程序的初始镜像，而在执行时，我们实际上是对  SimState  对象进行操作，它代表程序的一个实例镜像，模拟执行某个时刻的状态

`SimState`   对象包含程序运行时信息，如内存/寄存器/文件系统数据等。SM(Simulation Managers) 用于管理 state，执行 运行、模拟等操作，通过它我们可以同时控制一组 state 的符号执行。我们可以通过 stash 对一组 state 进行执行、筛选、合并和移动等操作。SM 包含多个 stash（`active/deadended/pruned` 等），大部分操作默认的 stash 为 active 。可以设定参数指定 stash。

**总而言之，这里我们创建了模拟管理器对象，为接下来的调用 explore 方法探索执行路径、求解引擎和执行引擎做铺垫**

```python
print_good_address = ???
simulation.explore(find=print_good_address)
```

通过调用 explore 方法，我们可以探索执行路径，在进行 explore 时，可以设置 find 和 avoid 参数，以便找到符合我们预期的路径。

函数接口如下：

```
def explore(self, stash='active', n=None, find=None, avoid=None, find_stash='found', avoid_stash='avoid', cfg=None, num_find=1, **kwargs):

>>>  proj = angr.Project('examples/CSCI-4968-MBE/challenges/crackme0x00a/crackme0x00a')
>>> simgr = proj.factory.simgr()
>>> simgr.explore(find=lambda s: b"Congrats" in s.posix.dumps(1))
<SimulationManager with 1 active, 1 found>
>>> s = simgr.found[0]  # 获取通过 explore 找到符合条件的状态
>>> flag = s.posix.dumps(0) 
>>> print(flag)
g00dJ0B!
```

#### explore 技术

angr 提供了多种 `explore` 技术，即进行路径探索时所采用的策略，可以在 `angr.exploration_techniques` 条目下中找到。

每个策略都是 `ExplorationTechnique`  对象，根据策略不同，angr 对 `ExplorationTechnique`  中的 `setup、step` 等方法进行覆盖。

通过 `simgr.use_technique(tech)`设定不同的策略。

下面部分列出策略

| 名称          | 描述                                                         |
| ------------- | ------------------------------------------------------------ |
| DFS           | Depth first search. Keeps only one state active at once, putting the rest in the `deferred` stash until it deadends or errors. |
| LengthLimiter | Puts a cap on the maximum length of the path a state goes through. |
| Tracer        | An exploration technique that causes execution to follow a dynamic trace recorded from some other source. |
| Oppologist    | if this technique is enabled and angr encounters an unsupported  instruction, it will concretize all the inputs to that instruction and  emulate the single instruction using the unicorn engine, allowing  execution to continue. |
| Threading     | Adds thread-level parallelism to the stepping process.       |
| Spiller       | When there are too many states active, this technique can dump some of them to disk in order to keep memory consumption low. |

**总而言之，这里我们使用 explore 方法探索执行路径,使用`simgr.explore`进行模拟执行`find`是想要执行分支，`avoid`是不希望执行的分支。**

#### simulation.found

```python
 if simulation.found:
    solution_state = simulation.found[0]

    print solution_state.posix.dumps(sys.stdin.fileno())
  else:
    # If Angr could not find a path that reaches print_good_address, throw an
    # error. Perhaps you mistyped the print_good_address?
    raise Exception('Could not find the solution')
```

此时相关的状态已经保存在了`simgr`当中，我们可以通过`simgr.found`来访问所有符合条件的分支，这里我们为了解题，就选择第一个符合条件的分支即可

这里解释一下`sys.stdin.fileno()`,在UNIX中，按照惯例，三个文件描述符分别表示标准输入、标准输出和标准错误

```python
>>> import sys
>>> sys.stdin.fileno()
0
>>> sys.stdout.fileno()
1
>>> sys.stderr.fileno()
2
```

### 运行结果

最终的EXP：

```python
import angr
proj = angr.Project('./00_angr_find', auto_load_libs=False)
state = proj.factory.entry_state()
simgr = proj.factory.simgr(state)
simgr.explore(find=0x804867D, avoid=0x804866B)
print(simgr.found[0].posix.dumps(0))
```

运行结果：

```shell
(angr) syc@ubuntu:~/Desktop/angr/00$ python3 exp.py
WARNING | 2020-06-29 23:58:50,540 | angr.state_plugins.symbolic_memory | The program is accessing memory or registers with an unspecified value. This could indicate unwanted behavior.
WARNING | 2020-06-29 23:58:50,541 | angr.state_plugins.symbolic_memory | angr will cope with this by generating an unconstrained symbolic variable and continuing. You can resolve this by:
WARNING | 2020-06-29 23:58:50,541 | angr.state_plugins.symbolic_memory | 1) setting a value to the initial state
WARNING | 2020-06-29 23:58:50,541 | angr.state_plugins.symbolic_memory | 2) adding the state option ZERO_FILL_UNCONSTRAINED_{MEMORY,REGISTERS}, to make unknown regions hold null
WARNING | 2020-06-29 23:58:50,541 | angr.state_plugins.symbolic_memory | 3) adding the state option SYMBOL_FILL_UNCONSTRAINED_{MEMORY_REGISTERS}, to suppress these messages.
WARNING | 2020-06-29 23:58:50,542 | angr.state_plugins.symbolic_memory | Filling register edi with 4 unconstrained bytes referenced from 0x80486b1 (__libc_csu_init+0x1 in 00_angr_find (0x80486b1))
WARNING | 2020-06-29 23:58:50,551 | angr.state_plugins.symbolic_memory | Filling register ebx with 4 unconstrained bytes referenced from 0x80486b3 (__libc_csu_init+0x3 in 00_angr_find (0x80486b3))
WARNING | 2020-06-29 23:58:57,052 | angr.state_plugins.symbolic_memory | Filling memory at 0x7ffefffc with 87 unconstrained bytes referenced from 0x8100000 (strcmp+0x0 in extern-address space (0x0))
WARNING | 2020-06-29 23:58:57,053 | angr.state_plugins.symbolic_memory | Filling memory at 0x7ffeff60 with 4 unconstrained bytes referenced from 0x8100000 (strcmp+0x0 in extern-address space (0x0))
b'JXWVXRKX'
```

