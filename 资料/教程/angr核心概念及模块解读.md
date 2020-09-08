# angr 系列教程(一）核心概念及模块解读

## 前言

最近在学习 angr， 发现网上教程大部分都是简单介绍几个顶层接口，或者使用 angr 来解题，比较杂，而且很多接口已经丢弃。所以准备写 angr 系列的教程，同时当作个人学习的记录。

本文主要对 angr一些概念和接口进行介绍，更像是简略版的说明文档。文章略长，可以选择感兴趣的章节阅读。

希望通过这篇教程各位可以对 angr 的使用有整体的认识，快速上手 angr并利用它进行二进制分析和研究。对细节感兴趣的同学就可以查文档和看源码。

安装教程略去，按照文档安装即可。

## 顶层接口

首先简单介绍一下 angr 的几个顶层接口，我们会在下面章节中进一步介绍这些接口。

使用 angr 第一件事就是加载二进制文件，在 angr 中，基本上所有的对象操作都依赖于已有的 Project 。

```bash
>>> import angr
>>> proj = angr.Project('/bin/true')
```

以下是 angr 对 `Project` 类的说明。

> This is the main class of the angr module. It is meant to contain a set of binaries and the relationships between them, and  perform analyses on them.

### 基本属性

载入二进制文件后，我们就可以访问一些基本属性，如文件名、架构、入口地址：

```bash
>>> proj.arch
>>> proj.entry
>>> proj.filename
```

### loader

接下介绍 loader，angr 中的  CLE  模块用于将二进制文件载入虚拟地址空间，而CLE 最主要的接口就是 loader 类。

> The loader loads all the objects and exports an  abstraction of the memory of the process. What you see here is an  address space with loaded and rebased binaries.

可以通过  Project 的 `.loader`的属性查看

```bash
>>> proj.loader
<Loaded true, maps [0x400000:0x5004000]>
```

通过 loader, 我们可以获得二进制文件的共享库、地址空间等信息。

```bash
>>> proj.loader.shared_objects
OrderedDict([('true', <ELF Object true, maps [0x400000:0x60721f]>), ('libc.so.6', <ELF Object libc-2.27.so, maps [0x1000000:0x13f0adf]>), ('ld-linux-x86-64.so.2', <ELF Object ld-2.27.so, maps [0x2000000:0x222916f]>)])
>>> proj.loader.min_addr
>>> proj.loader.max_addr
```

### factory

即  `AngrObjectFactory`，提供重要分析对象的接口，如 `blocks / state / SimulationManager` 等。

#### blocks

即程序基本块，我们可以给定地址，获取对应的基本块，为 Block 对象。

```bash
>>> block = proj.factory.block(proj.entry)
<Block for 0x4017b0, 42 bytes>
```

可以查看 Block 对象的信息或执行操作，以下是接口

```bash
>>> block.
block.BLOCK_MAX_SIZE          block.instruction_addrs       block.serialize_to_cmessage(
block.addr                    block.instructions            block.size
block.arch                    block.parse(                  block.thumb
block.bytes                   block.parse_from_cmessage(    block.vex
block.capstone                block.pp(                     block.vex_nostmt
block.codenode                block.serialize(
```

#### states

Project  对象仅表示程序的初始镜像，而在执行时，我们实际上是对  SimState  对象进行操作，它代表程序的一个实例镜像，模拟执行某个时刻的状态。

```bash
>>> state = proj.factory.entry_state()
<SimState @ 0x401670>
```

`SimState`   对象包含程序运行时信息，如内存/寄存器/文件系统数据等。

我们可以通过 `state.regs` 和  `state.mem` 访问寄存器和内存信息。

```bash
>>> state.regs.rip
<BV64 0x4017b0>
>>> state.regs.rax
<BV64 0x1c>
>>> state.mem[proj.entry].int.resolved
<BV32 0x8949ed31>
```

可以注意到，返回的结果都是 BV 类型，并不是python 中的 int 类型，BV是位向量(bitvector)的简称，实际上就是一串比特序列，angr 使用位向量表示 CPU 数据。

以下展示位向量和 int 的相互转换

```bash
>>> bv = state.solver.BVV(0x1234, 32)       # create a 32-bit-wide bitvector with value 0x1234
<BV32 0x1234>                               # BVV stands for bitvector value
>>> state.solver.eval(bv)                # convert to python int
0x1234
```

我们可以存储位向量到寄存器/内存中，或者直接使用 int 类型，它会被自动转成位向量。

```bash
>>> state.regs.rsi = state.solver.BVV(3, 64)
>>> state.regs.rsi
<BV64 0x3>
>>> state.mem[0x1000].long = 4
>>> state.mem[0x1000].long.resolved
<BV64 0x4>
```

后续我们还会详细介绍位向量的操作。

对于  `state.mem` 接口：

- `mem[ index ]`  指定地址
- `.<type>` 指定类型（如 `char, short, int, long, size_t, uint8_t, uint16_t...` ）
- `.resolved`  将数据输出为位向量。
- `.concrete` 将数据输出为int值。

#### Simulation Managers

> A simulation manager is the primary interface in angr for performing execution, simulation, whatever you want to call it, with  states.

SM(Simulation Managers) 用于管理 state，执行 运行、模拟等操作。

我们使用单个 state 或 state 列表创建 `Simulation Managers`

```bash
>>> simgr = proj.factory.simulation_manager(state)
>>> simgr.active
[<SimState @ 0x4017b0>]
```

单个 SM 可以包含多个 stash(stash 中存放 state) ， 默认的stash 是 `active stash`，它使用我们传入的 `state`进行初始化。

接下来，我们进行简单的执行操作, 调用 step() 方法，这会执行一个基本块。

```
>>> simgr.step()
```

再次查看 `active`，可以看到已经从 `0x4017b0` 变为 `0x1021ab0` . 而初始 state 不会受到影响， 因为执行不会改变 `SimState` 对象。

```bash
>>> simgr.active
[<SimState @ 0x1021ab0>]
>>> simgr.active[0].regs.rip
<BV64 0x1021ab0>
>>> state.regs.rip          
<BV64 0x4017b0>
```

### Analyses

angr 内置了一些分析方法，用于提取程序信息。接口位于 `proj.analyses.` 中

```bash
>>> proj.analyses.
proj.analyses.BackwardSlice(              proj.analyses.Decompiler(                 proj.analyses.VFG(
proj.analyses.BasePointerSaveSimplifier(  proj.analyses.DefUseAnalysis(             proj.analyses.VSA_DDG(
proj.analyses.BinDiff(                    proj.analyses.Disassembly(               proj.analyses.VariableRecovery(
proj.analyses.BinaryOptimizer(            proj.analyses.DominanceFrontier(         proj.analyses.VariableRecoveryFast(       .....
```

### 总结

以上就是顶层接口的说明，通过以上介绍，我们对 angr 有了初步的认识。

通常使用 angr 的步骤大概如下:

1. 创建 project 并设置state
2. 新建符号量/位向量 并在内存或其他地方设置
3. 设置 Simulation Managers 
4. 运行，探索满足需要的路径
5. 约束求解，获取执行结果

接下来，我们对几个核心模块进行介绍。

## loader 加载模块

将二进制文件加载到虚拟的地址空间

通过我们可以 loader 对查看加载对象、符号重定位信息等，同时也可以设置初始的加载选项。

- 已加载的对象
- 符号和重定位
- 加载选项

### 已加载的对象

获取对象，可以通过以下接口获取对应的对象。

- `.all_objects/shared_objects/all_elf_objects/extern_object/kernel_object`

```bash
>>> obj = proj.loader.main_object
<ELF Object true, maps [0x400000:0x60721f]>
>>> obj = proj.loader.all_objects
[<ELF Object true, maps [0x400000:0x60721f]>, <ExternObject Object cle##externs, maps [0x1000000:0x1008000]>, <ELFTLSObject Object cle##tls, maps [0x2000000:0x2015010]>, <KernelObject Object cle##kernel, maps [0x3000000:0x3008000]>]
```

获得加载对象后，直接与这些对象进行交互从中提取元数据，如：

- 获取 ELF 的内存分段和文件分段

```bash
>>> obj.sections                     
<Regions: [<Unnamed | offset 0x0, vaddr 0x400000, size 0x0>, <.interp | offset 0x238, vaddr 0x400238, size 0x1c>, <.note.ABI-tag | offset 0x254, vaddr 0x400254, size 0x20>, <.note.gnu.build-id | offset 0x274, vaddr 0x400274, size 0x24>, <.gnu.hash | offset 0x298, vaddr 0x400298, size 0x64>,...
```

- 获取 PLT 表信息

```bash
>>> obj.plt
{'__uflow': 0x401400,
 'getenv': 0x401410,
 'free': 0x401420,
 'abort': 0x401430,
 '__errno_location': 0x401440,
 'strncmp': 0x401450,
 '_exit': 0x401460,
```

- 显示预链接基址和实际装载的内存基址等地址信息

```bash
>>> obj.linked_base
0x0
>>> 
>>> obj.mapped_base
0x400000
>>> obj.max_addr
0x60721f
```

- ....

### 符号和重定位

使用 CLE 操作二进制的符号信息

#### 查找符号

```bash
>>> malloc = proj.loader.find_symbol('malloc')
<Symbol "malloc" in extern-address space at 0x10002c0>
```

如果要获得对象的 symbol，则使用  `get_symbol`  方法：

```
malloc = proj.loader.main_object.get_symbol('malloc')
```

我们会得到一个 symbol 对象，可以获取获取符号名/所属者/链接地址/相对地址等信息。

```bash
>>> malloc.
malloc.is_common           malloc.is_local            malloc.owner_obj           malloc.resolvedby
malloc.is_export           malloc.is_static           malloc.rebased_addr        malloc.size
malloc.is_extern           malloc.is_weak             malloc.relative_addr       malloc.subtype
malloc.is_forward          malloc.linked_addr         malloc.resolve(            malloc.type
malloc.is_function         malloc.name                malloc.resolve_forwarder(  
malloc.is_import           malloc.owner               malloc.resolved
```

symbol 对象有三种获取其地址的方式：

- `.rebased_addr`: 在全局地址空间的地址。
- `.linked_addr`: 相对于二进制的预链接基址的地址。 
- `.relative_addr`: 相对于对象基址的地址。 

```bash
>>> malloc.rebased_addr
0x10002c0
>>> malloc.linked_addr 
0x2c0     
>>> malloc.relative_addr
0x2c0
```

### 加载选项

#### 基本选项

| 名称                  | `描述`                       |
| --------------------- | ---------------------------- |
| `auto_load_libs`      | 是否自动加载程序的依赖       |
| `skip_libs`           | 避免加载的库                 |
| `except_missing_libs` | 无法解析共享库时是否抛出异常 |
| `force_load_libs`     | 强制加载的库                 |
| `ld_path`             | 共享库的优先搜索搜寻路径     |

在进行一些程序分析时，如果  auto_load_libs 为 True, angr 会同时分析动态链接库，导致耗时非常久，所以可以根据自己需要设置恰当的值。

```bash
>>> proj = angr.Project('/bin/true')
>>> proj.loader.shared_objects
OrderedDict([('true', <ELF Object true, maps [0x400000:0x60721f]>), ('libc.so.6', <ELF Object libc-2.27.so, maps [0x1000000:0x13f0adf]>), ('ld-linux-x86-64.so.2', <ELF Object ld-2.27.so, maps [0x2000000:0x222916f]>)])
>>> proj = angr.Project('/bin/true', load_options={"auto_load_libs": False})
>>> proj.loader.shared_objects
OrderedDict([('true', <ELF Object true, maps [0x400000:0x60721f]>)])
```

#### pre-binary 选项

在加载二进制文件时可以设置特定的参数，使用 `main_opts` 和 `lib_opts` 参数进行设置。

- `backend` - 指定 backend
- `base_addr` - 指定基址
- `entry_point` - 指定入口点
- `arch` - 指定架构

示例如下：

```bash
>>> angr.Project('examples/fauxware/fauxware', main_opts={'backend': 'blob', 'arch': 'i386'}, lib_opts={'libc.so.6': {'backend': 'elf'}})
<Project examples/fauxware/fauxware>
```

### backend

一般情况下，CLE 会自动选择对应的 backend，也可以自己指定。有的 backend 需要 同时指定架构。

以下是各个 backend 以及描述：

| 名称      | 描述                                          |
| --------- | --------------------------------------------- |
| elf       | ELF文件的静态加载器 (基于PyELFTools)          |
| pe        | PE文件静态加载器 (基于PEFile)                 |
| mach-o    | Mach-O文件的静态加载器                        |
| cgc       | CGC (Cyber Grand Challenge)二进制的静态加载器 |
| backedcgc | CGC 二进制的静态加载器，允许指定内存和寄存器  |
| elfcore   | ELF 核心转储的静态加载器                      |
| blob      | 将文件作为平面镜像加载到内存中                |

注：IDA backend 在  angr 8.18.10.25  中已被移除。

## 符号函数摘要集(symbolic funcion summaries)

默认情况下，angr 会使用 `SimProcedures` 中的符号摘要替换库函数，即设置 Hooking，这些 python 函数摘要高效地模拟库函数对状态的影响。可以通过 `angr.procedures`或 `angr.SimProcedures`  查看列表。

`SimProcedures`   是一个两层的字典，第一层表示包名，第二层表示函数名。

```bash
>>> angr.procedures.
angr.procedures.SIM_PROCEDURES  angr.procedures.java_lang       angr.procedures.stubs
angr.procedures.SimProcedures   angr.procedures.java_util       angr.procedures.testing
angr.procedures.advapi32        angr.procedures.libc            angr.procedures.tracer
angr.procedures.cgc             angr.procedures.linux_kernel    angr.procedures.uclibc
angr.procedures.definitions     angr.procedures.linux_loader    angr.procedures.win32
angr.procedures.glibc           angr.procedures.msvcr           .......
>>> angr.procedures.libc.malloc
<module 'angr.procedures.libc.malloc' from '/home/angr/angr-dev/angr/angr/procedures/libc/malloc.py'>
>>> angr.SIM_PROCEDURES['libc']['malloc']
<class 'angr.procedures.libc.malloc.malloc'>
```

可以设置参数  `exclude_sim_procedures_list`  和  `exclude_sim_procedures_func` 指定不想被 `SimProcedure` 替代的符号。

此外，关于 SimProcedure 的不准确性[文档](https://docs.angr.io/advanced-topics/gotchas) 有提到。

#### Hooking

`SimProcedure`  其实就是 Hook 机制，可以通过  `proj.hook(addr,hook)` 设置，其中 hook 是一个 `SimProcedure` 实例。 通过 `.is_hooked / .unhook / .hook_by` 进行管理。

将 `proj.hook(addr)` 作为函数装饰器，可以编写自己的 hook 函数。。

还可以通过  `proj.hook_symbol(name,hook)` hook 函数。

```bash
>>> stub_func = angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained'] # this is a CLASS
>>> proj.hook(0x10000, stub_func())  # hook with an instance of the class
>>> proj.is_hooked(0x10000)            # these functions should be pretty self-explanitory
True
>>> proj.hooked_by(0x10000)
<ReturnUnconstrained>
>>> proj.unhook(0x10000)
>>> @proj.hook(0x20000, length=5)
... def my_hook(state):
...     state.regs.rax = 1
>>> proj.is_hooked(0x20000)
True
```

## states

state 代表程序的一个实例镜像，模拟执行某个时刻的状态。保存运行状态的上下文信息，如内存/寄存器等。

在执行开始之前，我们通过设置 state 对象初始化寄存器/内存/栈帧等信息。在结束执行后，会返回 state 对象，可以提取需要的值进行求解。

#### 基础执行

使用 `state.step()`接口进行简单的执行，该方法会返回一个 `SimSuccessors` 对象，该对象有个  `.successors` 属性 , 是后继状态的列表。

关于执行，在 SM 中同样涉及，通常使用 SM 管理 state 的执行。

#### 状态预设

除了使用`.entry_state()` 创建 state 对象, 我们还可以根据需要使用其他构造函数创建 state:

| 名称               | 描述                                                         |
| ------------------ | ------------------------------------------------------------ |
| `.entry_state()`   | constructs a state ready to execute at the main binary's entry point. |
| `.blank_state`     | constructs a "blank slate" blank state, with most of its data left uninitialized. |
| `.call_state`      | When accessing uninitialized data, an unconstrained symbolic value  will be returned.constructs a state ready to execute a given function. |
| `.full_init_state` | constructs a state that is ready to execute through any initializers that need to be run before the main binary's entry point |

#### 访问寄存器

通过 `state.regs` 对象的属性访问以及修改寄存器的数据

```bash
>>> state.regs.r  
state.regs.r10                state.regs.r13w               state.regs.r9d
state.regs.r10b               state.regs.r14                state.regs.r9w
state.regs.r10d               state.regs.r14b               state.regs.rax
state.regs.r10w               state.regs.r14d               state.regs.rbp
>>> state.regs.rip
<BV64 0x4017b0>
```

#### 访问内存

前面提到可以通过 `state.mem[index]` 访问内存，但对于一段连续内存的操作十分不方便。

因此我们也可以使用 `state.memory`  的  `.load(addr, size) / .store(addr, val)`  接口读写内存, size 以 bytes 为单位。

以下 load 和 store 的函数声明和一些参数解释：

```python
def load(self, addr, size=None, condition=None, fallback=None, add_constraints=None, action=None, endness=None,
             inspect=True, disable_actions=False, ret_on_segv=False):
        """
        Loads size bytes from dst.
        :param addr:             The address to load from. #读取的地址
        :param size:            The size (in bytes) of the load. #大小
        :param condition:       A claripy expression representing a condition for a conditional load.
        :param fallback:        A fallback value if the condition ends up being False. 
        :param add_constraints: Add constraints resulting from the merge (default: True).
        :param action:          A SimActionData to fill out with the constraints.
        :param endness:         The endness to load with. #端序
       ....
def store(self, addr, data, size=None, condition=None, add_constraints=None, endness=None, action=None,
              inspect=True, priv=None, disable_actions=False):
        """
        Stores content into memory.
        :param addr:        A claripy expression representing the address to store at. #内存地址
        :param data:        The data to store (claripy expression or something convertable to a claripy expression).#写入的数据
        :param size:        A claripy expression representing the size of the data to store. #大小
        ...
>>> s = proj.factory.blank_state()
>>> s.memory.store(0x4000, s.solver.BVV(0x0123456789abcdef0123456789abcdef, 128))
>>> s.memory.load(0x4004, 6) # load-size is in bytes
<BV48 0x89abcdef0123>
```

参数 `endness` 用于设置端序。

可选的值如下

```python
LE – 小端序(little endian, least significant byte is stored at lowest address)
BE – 大端序(big endian, most significant byte is stored at lowest address)
ME – 中间序(Middle-endian. Yep.)
>>> import archinfo
>>> s.memory.load(0x4000, 4, endness=archinfo.Endness.LE)
<BV32 0x67453201>
```

#### 状态选项

`SimState` 包含 `.options` 属性，它是所有开启的状态选项的集合。

状态通过  `angr.options.<name>`获得，具体的选项可以查看 [列表](https://docs.angr.io/appendix/options) 。

```python
>>> angr.options.
Display all 143 possibilities? (y or n)
angr.options.ABSTRACT_MEMORY
angr.options.ABSTRACT_SOLVER
angr.options.ACTION_DEPS
angr.options.ALLOW_SEND_FAILURES
angr.options.ALL_FILES_EXIST
angr.options.APPROXIMATE_FIRST
angr.options.APPROXIMATE_GUARDS
....
```

可以直接对 `.options`集合进行操作，添加选项。

在创建  `SimState`  对象时，可以通过关键字参数 `add_options` 和 `remove_options` 设置选项。

```python
>>> s.options.add(angr.options.LAZY_SOLVES)
# Create a new state with lazy solves enabled
>>> s = proj.factory.entry_state(add_options={angr.options.LAZY_SOLVES})
# Create a new state without simplification options enabled
>>> s = proj.factory.entry_state(remove_options=angr.options.simplification)
```

#### 状态插件（state plugin)

除了前面提到的 options， `SimState` 中的内容都是以插件的方式进行存储，这种设计可以模块化，方便维护和拓展。

这些插件称为状态插件（state plugin)，angr 内部实现了多种插件。如 memory / history /  globals / callstack 等。

`memory` 插件前面已经提到(内存访问章节)，下面简单介绍 history 和 callstack 插件。

##### history 插件

该插件记录状态的执行路径，实际上是  `history`   结点的链表，可以通过 `.parent` 来遍历列表。

history 存储的一些值以  `history.recent_NAME`  格式命名，对应的迭代器为 `history.NAME` 。

如以下代码会按顺序输出基本块的地址。

```python
for addr in state.history.bbl_addrs: 
    print hex(addr)
```

如果想快速查看链表的所有结点，可以使用  `.hardcopy`  方法，例`state.history.bbl_addrs.hardcopy`

以下是 `history` 存储的部分值：

| 名称                   | 描述                                                         |
| ---------------------- | ------------------------------------------------------------ |
| `history.descriptions` | a listing of string descriptions of each of the rounds of execution performed on the state. |
| `history.bbl_addrs`    | a listing of the basic block addresses executed by the state. |
| `history.jumpkinds`    | a listing of the disposition of each of the control flow transitions in the state's history, as VEX enum strings. |
| `history.events`       | a semantic listing of "interesting events" which happened during  execution, such as the presence of a symbolic jump condition, the  program popping up a message box, or execution terminating with an exit  code. |
| `history.actions`      | usually empty, but if you add the `angr.options.refs`  options to the state, it will be populated with a log of all the memory, register, and temporary value accesses performed by the program. |

##### 调用栈（callstack）插件

该插件记录执行时栈帧的信息，也是链表格式。可以直接对  `state.callstack` 进行迭代获得每次执行的栈帧信息。直接访问  `state.callstack`  可以获得当前状态的调用栈。

以下是 `callstack` 记录的部分信息：

- `callstack.func_addr` ： the address of the function currently being executed 
- `callstack.call_site_addr`： the address of the basic block which called the current function 
- `callstack.stack_ptr` : he value of the stack pointer from the beginning of the current function 
- `callstack.ret_addr` :  the location that the current function will return to if it returns 

此外，angr 还内置了许多其他的状态插件，比如 heap、gdb、libc、 filesystem等等，位于 `angr/state_plugin` 目录。

除了使用内置状态插件外，我们也可以编写自己的插件，具体查看[文档说明](https://docs.angr.io/extending-angr/state_plugins)

## 模拟管理器（Simulation Managers)

前面已经介绍过 SM，通过它我们可以同时控制一组 state 的符号执行。我们可以通过 stash 对一组 state 进行执行、筛选、合并和移动等操作。

```python
>>> simgr = proj.factory.simulation_manager(state)
<SimulationManager with 1 active>
```

出于方便，我们也可以使用 `.simulation_manager`的简写 `.simgr`，如果不传入 `state`, angr 会使用 `entry_state` 进行初始化。

```python
>>> simgr = proj.factory.simgr()
>>> simgr.active
[<SimState @ 0x4017b0>]
```

SM 包含多个 stash（`active/deadended/pruned` 等），大部分操作默认的 stash 为 active 。可以设定参数指定 stash。

SM 三个重要的接口： `step`, `explore`, and `use_technique`

### 执行

SM 提供两种基本的执行方法：

- step() : 让 stash 中的所有状态都执行一个基本块，默认的 stash 为 active
- run() : 一直执行到结束

### stash 管理

SM 中使用 stash 管理 state。一个 stash 包含多个 state。可以以 SM 属性的格式访问这些 stash, 如 .active。我们也可以根据需要创建新的 stash。

使用 .move 可以进行 stash 间的移动。每一个 stash 都是一个列表，可以通过索引或者迭代访问里面的数据。

```python
>>> simgr.move(from_stash='deadended', to_stash='authenticated', filter_func=lambda s: b'Welcome' in s.posix.dumps(1))
>>> simgr
<SimulationManager with 2 authenticated, 1 deadended>
```

angr 会对 state 进行分类，归到不同的 stash，以下是部分特殊 stash 列表

| 名称          | 描述                                                         |
| ------------- | ------------------------------------------------------------ |
| active        | This stash contains the states that will be stepped by default, unless an alternate stash is specified. |
| deadend       | A state goes to the deadended stash when it cannot continue the  execution for some reason, including no more valid instructions, unsat  state of all of its successors, or an invalid instruction pointer. |
| pruned        | When using `LAZY_SOLVES`, states are not checked for satisfiability unless absolutely necessary. When a state is found to be unsat in the presence of `LAZY_SOLVES`, the state hierarchy is traversed to identify when, in its history, it  initially became unsat. All states that are descendants of that point  (which will also be unsat, since a state cannot become un-unsat) are  pruned and put in this stash. |
| unconstrained | If the `save_unconstrained` option is provided to the  SimulationManager constructor, states that are determined to be  unconstrained (i.e., with the instruction pointer controlled by user  data or some other source of symbolic data) are placed here. |
| unsat         | If the `save_unsat` option is provided to the  SimulationManager constructor, states that are determined to be  unsatisfiable (i.e., they have constraints that are contradictory, like  the input having to be both "AAAA" and "BBBB" at the same time) are  placed here. |

### explore

通过调用 explore 方法，我们可以探索执行路径，在进行 explore 时，可以设置 find 和 avoid 参数，以便找到符合我们预期的路径。

函数接口如下：

```python
def explore(self, stash='active', n=None, find=None, avoid=None, find_stash='found', avoid_stash='avoid', cfg=None,
                num_find=1, **kwargs):
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

关于使用信息请查看 [API文档](http://angr.io/api-doc/angr.html#angr.exploration_techniques.ExplorationTechnique)

## 求解引擎

通过 `state.solver` 访问求解引擎，angr 的求解引擎是 `claripy` 用于求解约束。

### 位向量(bitvector)

位向量是比特序列，既可以表示具体值，也可以是符号变量。

通过 `BVV(value,size)` 和 `BVS( name, size)` 接口创建位向量，也可以用 FPV 和 FPS 来创建浮点值和符号。

```python
>>> one = state.solver.BVV(1, 64)
 <BV64 0x1>
>>> one_hundred = state.solver.BVV(100, 64)
<BV64 0x64>
>>> weird_nine = state.solver.BVV(9, 27)
<BV27 0x9>
>>> one + one_hundred
<BV64 0x65>
>>> one_hundred + 0x100
<BV64 0x164>
>>> one_hundred - one*200
<BV64 0xffffffffffffff9c>
```

如果两个位向量的长度不同无法进行运算的，需要将其扩展。 angr 提供 `zero_extend` 和 `sign_extend` 两种方式对向量进行拓展。

```python
>>> weird_nine.zero_extend(64 - 27)
<BV64 0x9>
>>> one + weird_nine.zero_extend(64 - 27)
<BV64 0xa>
```

创建符号变量：

```python
>>> x = state.solver.BVS("x", 64)
<BV64 x_9_64>
>>> y = state.solver.BVS("y", 64)
<BV64 y_10_64>
```

对其进行算术操作会得到 AST (抽象语法树)，而不是具体的值，AST 可以转化成约束，使用 SMT 求解器求解。

```python
>>> x + one
<BV64 x_9_64 + 0x1>
>>> (x + one) / 2
<BV64 (x_9_64 + 0x1) / 0x2>
>>> x - y
<BV64 x_9_64 - y_10_64>
```

#### 符号约束

将两个相似的 AST 进行比较会得到一个 AST, 这是符号化的布尔类型，使用 `solver.is_true`和 `solver.is_false` 获得真假值。

```python
>>> x == 1
<Bool x_9_64 == 0x1>
>>> x == one
<Bool x_9_64 == 0x1>
>>> x > 2
<Bool x_9_64 > 0x2>
>>> x + y == one_hundred + 5
<Bool (x_9_64 + y_10_64) == 0x69>
```

#### 约束求解

我们可以通过 `.add` 对 state 对象添加约束，并使用 `.eval` 接口求解，得到符号变量的可行解。

```python
>>> state.solver.add(x > y)
>>> state.solver.add(y > 2)
>>> state.solver.add(10 > x)
>>> state.solver.eval(x)
```

因此，我们可以根据输出和限制得到输入值，举个例子：

```python
# get a fresh state without constraints
>>> state = proj.factory.entry_state()
>>> input = state.solver.BVS('input', 64)
>>> operation = (((input + 4) * 3) >> 1) + input
>>> output = 200
>>> state.solver.add(operation == output)
>>> state.solver.eval(input)
0x3333333333333381
```

如果约束冲突，无法求解，则 state 为  `unsatisfiable`  状态，可以通过  `state.satisfiable()`  检查约束是否可解。

#### 更多求解方式

除了朴素的 eval ，angr 提供了多种解析方式 。

| 接口                               | 描述                                                     |
| ---------------------------------- | -------------------------------------------------------- |
| `solver.eval(expression)`          | 将会解出一个可行解                                       |
| `solver.eval_one(expression)`      | 将会给出一个表达式的可行解，若有多个可行解，则抛出异常   |
| `solver.eval_upto(expression, n)`  | 将会给出最多n个可行解，如果不足n个就给出所有的可行解。   |
| `solver.eval_exact(expression, n)` | 将会给出n个可行解，如果解的个数不等于n个，将会抛出异常。 |
| `solver.min(expression)`           | 给出最小可行解                                           |
| `solver.max(expression)`           | 给出最大可行解                                           |

同时可以设置 `extra_constraints` 和 `cast_to`参数对结果进行限制或转换。

## 执行引擎

angr使用一系列引擎（SimEngine的子类）来模拟被执行代码对输入状态产生的影响。源码位于 angr/engines 目录下。

以下是默认的引擎列表

| 名称             | 描述                                                         |
| ---------------- | ------------------------------------------------------------ |
| `failure engine` | kicks in when the previous step took us to some uncontinuable state |
| `syscall engine` | kicks in when the previous step ended in a syscall           |
| `hook engine`    | kicks in when the current address is hooked                  |
| `unicorn engine` | kicks in when the `UNICORN` state option is enabled and there is no symbolic data in the state |
| `VEX engine`     | kicks in as the final fallback.                              |

## 分析

angr 内置了许多程序分析方法。可以在 `angr.analyses` 下查看。

通过 `project.analyses.name` 进行调用，如 `project.analyses.CFGFast()` 。同时我们也可以编写自己的分析方法，具体可以查看 [文档](https://docs.angr.io/extending-angr/analysis_writing) 。

以下表格列出一些常用的方法。

| 名字            | `描述`                                       |
| --------------- | -------------------------------------------- |
| `CFGFast`       | 快速地获取程序控制流图(静态)                 |
| `CFGEmulated`   | 通过动态模拟获取程序控制流图                 |
| `VFG`           | 执行值集分析，生成值流图（Value Flow Graph） |
| `DDG`           | 数据依赖图                                   |
| `DFG`           | 为每个在CFG中出现的基本块构建数据流图        |
| `BackwardSlice` | 后向切片                                     |
| `Identifier`    | 库函数识别                                   |

angr 文档仅对 `CFG、BackwardSlice、function Identifier` 这三种技术进行介绍，如果想使用其他技术，可以查看API / 源码或者向开发者提 issue 。

### CFG

CFGFast  使用静态分析获得 CFG, 速度较快，但是不太准确。 CFGEmulated   使用符号执行获得 CFG， 耗时长，相对准确。

如果不知道该选择哪一种，就先尝试 CFGFast 。

此外，angr 的 CFG 接口是 CFGFast  的简称，如果需要使用 CFGEmulated，请直接使用 CFGEmulated。

使用示例

```python
>>> import angr
>>> p = angr.Project('/bin/true', load_options={'auto_load_libs': False})
>>> cfg = p.analyses.CFGFast()
```

可以使用 [angr-utils](https://github.com/axt/angr-utils)  对 CFG, CG 图进行可视化。

### backward slicing

用于后向切片，为了构建一个  BackwardSlice，我们需要以下信息作为输入：

- CFG（必须）： A control flow graph (CFG) of the program. This CFG must be an accurate CFG (CFGEmulated).

- Target （必须）： Target, which is the final destination that your backward slice terminates at.

- CDG （可选）：A control dependence graph (CDG) derived from the CFG.

  angr has a built-in analysis `CDG` for that purpose.

- DDG （可选） A data dependence graph (DDG) built on top of the CFG.

  angr has a built-in analysis `DDG` for that purpose.

以下是文档的使用示例

```python
>>> import angr
# Load the project
>>> b = angr.Project("examples/fauxware/fauxware", load_options={"auto_load_libs": False})

# Generate a CFG first. In order to generate data dependence graph afterwards, you’ll have to:
# - keep all input states by specifying keep_state=True.
# - store memory, register and temporary values accesses by adding the angr.options.refs option set.
# Feel free to provide more parameters (for example, context_sensitivity_level) for CFG 
# recovery based on your needs.
>>> cfg = b.analyses.CFGEmulated(keep_state=True, 
...                              state_add_options=angr.sim_options.refs, 
...                              context_sensitivity_level=2)

# 生成控制流依赖图
>>> cdg = b.analyses.CDG(cfg)

# 生成数据流依赖图
>>> ddg = b.analyses.DDG(cfg)

# See where we wanna go... let’s go to the exit() call, which is modeled as a 
# SimProcedure.
>>> target_func = cfg.kb.functions.function(name="exit")
# We need the CFGNode instance
>>> target_node = cfg.get_any_node(target_func.addr)

# Let’s get a BackwardSlice out of them!
# `targets` is a list of objects, where each one is either a CodeLocation 
# object, or a tuple of CFGNode instance and a statement ID. Setting statement 
# ID to -1 means the very beginning of that CFGNode. A SimProcedure does not 
# have any statement, so you should always specify -1 for it.
>>> bs = b.analyses.BackwardSlice(cfg, cdg=cdg, ddg=ddg, targets=[ (target_node, -1) ])

# Here is our awesome program slice!
>>> print(bs)
```

### function identifier

用于识别库函数，目前仅针对 CGC 文件。

```python
>>> import angr

# get all the matches
>>> p = angr.Project("../binaries/tests/i386/identifiable")
>>> idfer = p.analyses.Identifier()
# note that .run() yields results so make sure to iterate through them or call list() etc
>>> for addr, symbol in idfer.run():
...     print(hex(addr), symbol)

0x8048e60 memcmp
0x8048ef0 memcpy
0x8048f60 memmove
0x8049030 memset
0x8049320 fdprintf
0x8049a70 sprintf
0x8049f40 strcasecmp
....
```

## 更新说明

因为 angr 在不断更新，很多接口也在变化，网上有些教程有点过时，看不同版本的教程可能会有点乱，这里主要说一下在其他教程中经常出现但是已经发生变更的接口。

- `SimuVEX`  已被移除
- `Surveyors` 已被移除
- 使用 Simulation Manager  代替 Path Group
- 求解引擎的接口是  state.solver  而不是  state.se 
- `CFGAccurate` 更名为 `CFGEmulated.` 

更详细的可以看 [changelog](https://docs.angr.io/appendix/changelog)

## 总结

以上就是本教程的全部内容，通过介绍我们可以对 angr 的主要接口有整体的认识，实际上 angr 还有十分丰富的内容，但是文档不太完整，有问题可以先查下 API （API 文档有些地方没有及时更新可能会有坑），或者自己看源码。

最后推荐一下论文：(State of) The Art of War: Offensive Techniques in Binary Analysis 这是 angr 相关的论文，里面介绍了一些二进制分析的方法，可以了解一下 angr 背后的思想。

后续教程我会深入介绍 angr 的更多使用技巧和实现 =）

## 参考资料

1. https://docs.angr.io/ 
2. http://angr.io/api-doc 
3. https://github.com/angr/angr 
4. https://zhuanlan.zhihu.com/p/51753624