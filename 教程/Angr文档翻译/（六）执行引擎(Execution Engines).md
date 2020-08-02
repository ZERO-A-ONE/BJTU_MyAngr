# 执行引擎(Execution Engines)

## 模拟和指令(Simulation and Instrumentation)

当你用angr进行一次单步执行时，必须有一个东西来切实地将程序执行一步（即一个基本块，下面简称执行一个基本块为step）。angr使用一系列引擎（`SimEngine`的子类）来模拟被执行的代码对输入状态产生的影响。angr的执行内核将按序尝试列表中可用的引擎，并取出第一个能够处理当前step的引擎。下面是按序列出的默认引擎列表：

- failure engine：当前一次step将我们带到一个不可继续执行的状态时，故障引擎启动。
- syscall engine：当前一次step以一个系统调用结束时启动。
- hook engine：当前地址被hook时启动。
- unicorn engine：当`UNICORN`选项被开启并且输入状态中没有符号化的数据时启动。
- VEX engine：作为最终的回调函数被调用。

## SimSuccessors

实际上按顺序尝试上述列表中的执行引擎的代码位于`project.factory.successors(state, **kwargs)`中，这个方法会将接收到的参数传给每一个引擎。它是`state.step()`和`simulation_manager.step()`的核心。它返回一个我们之前已经简要讨论过的`SimSuccessor`对象。`SimSuccessor`的目的是对产生的后继状态进行一个简单的分类，并将这些状态分别存储在不同的属性（列表类型）中，这些属性是：

| 属性                     | 条件                                                         | 指令指针                                                     | 描述                                                         |
| ------------------------ | ------------------------------------------------------------ | ------------------------------------------------------------ | ------------------------------------------------------------ |
| successors               | True（可以是约束为True的符号表达式；译者注：按我理解就是状态的约束条件可满足） | 可以是带符号的指令，但是解的个数必须小于或等于256个；详见`unconstrained_successors`） | 由引擎执行某个状态后产生的普通的、可满足的状态。它的指令指针可以是符号化的（例如，以用户输入为判断条件的跳转指令），因此这个列表中存储的状态可能实际产生多个后继状态 |
| unsat_successors         | False(可以是约束为False的符号表达式；译者注：即符号约束条件不可满足) | 可以是带符号的指令                                           | 不可满足的后继状态。这些状态的约束条件不可能被满足（例如：不可能执行的跳转，或者必须被默认执行的跳转。） |
| flat_successors          | True(可以是约束为True的符号表达式)                           | 具体指令（不带符号）                                         | 正如之前强调的，在`successors`列表中的状态中的指令指针可以是带符号的，这就带来一个问题：在执行一次step时（比如在`SimEngineVEX.process`中向前执行一步），我们假设一个state只能够代表代码中单独一段代码的执行结果，但是如果前一个状态是带符号的，那么执行结果应该如何表示呢？为了解决这个问题，当在`successors`列表中遇到一个带有符号化指令指针的状态时，angr会计算出所有可能的符号状态的具体值（最多256种可能，如果超过这个限制，将会被放入其他属性的列表中），我们称这个计算过程为`flattening`。在`flat_successors`中的每个状态都有着不带符号且互不相同的指令指针。例如，如果在`successors`列表中发现一个状态的指令指针指向`X+5`，且X的约束条件是`X > 0x800000`且`X < 0x800010`，那么我们会将它“flatten”为16个不同的`flat_sucessors`状态，这16个状态包含的指令指针值从`0x800006`一直到`0x800015` |
| unconstrained_successors | True（可以是约束为True的符号表达式）                         | 符号化的指令指针（符号表达式的解的个数多于256个）            | 在上面描述的flattening过程中，如果发现一个状态内的符号表达式组的可行解多于256个，我们就假设这个指令指针的值是一个不受约束的数据（例如，用户输入导致的栈溢出）这个假设通常是不合理的（译者注：wtf？！）。像这样的状态就会被放在`unconstrained_successors`列表中，而不是`successors`列表中 |
| all_successors           | 任何条件                                                     | 可以是符号化的                                               | `successors`+`unsat_successors`+`unconstrained_successors`   |

## 断点

TODO：重写此部分，修正叙述方式。

和其他执行引擎一样，angr支持断点的设置。这就很酷了！一个断点可以这么下：

![img](https:////upload-images.jianshu.io/upload_images/19793687-6f37eb1acf0bbd22.png?imageMogr2/auto-orient/strip|imageView2/2/w/827)

图中第二种下断点方式允许自定义断点触发后的回调函数（需要ipdb库的支持）；第三种方式在触发断点后进入ipython的交互界面。

除了“内存写”断点外，还有许多其他种类的断点。这里是一个断点事件触发列表，你可以设置在这些事件发生前还是发生后触发断点：

| 事件类型               | 事件含义                                                     |
| ---------------------- | ------------------------------------------------------------ |
| mem_read               | 内存正在被读取                                               |
| mem_write              | 内存正在被写                                                 |
| reg_read               | 寄存器正在被读                                               |
| reg_write              | 寄存器正在被写                                               |
| tmp_read               | 一个临时值（立即数？）正在被读                               |
| temp_write             | 一个临时值正在被写                                           |
| expr                   | 一个表达式正在被建立（比如一次数学计算的结果，或者IR中的常量（a constant in the IR）） |
| statement              | 一个IR statement正在被解释执行(translate)                    |
| instruction            | 一个新的（本地native）指令正在被解释执行                     |
| lrsb                   | 一个新的基本块正在被解释执行                                 |
| constraints            | 一个新的约束正在被加入某个状态中                             |
| exit                   | 一个继承状态正由一次执行中产生                               |
| symbolic_variable      | 一个新的符号变量正在被创建                                   |
| call                   | 一个call指令正在被执行                                       |
| address_concretization | 一个符号化的内存值正在被解析                                 |

对于上述不同的事件，可以应用不同的属性（来限制断点触发的条件）：

| 事件类型               | 属性名                                 | 适用的时机            | 属性含义                                                     |
| ---------------------- | -------------------------------------- | --------------------- | ------------------------------------------------------------ |
| mem_read               | mem_read_address                       | BP_BEFOR 或 BP_AFTER  | 正在被读取的内存的地址                                       |
| mem_read               | mem_read_length                        | BP_BEFOR 或 BP_AFTER  | 读取的内存的长度                                             |
| mem_read               | mem_read_expr                          | BP_AFTER              | 地址中的表达式                                               |
| mem_write              | mem_write_address                      | BP_BEFOR 或 BP_AFTER  | 正在被写入的内存地址                                         |
| mem_write              | mem_write_length                       | BP_BEFOR 或 BP_AFTER  | 写入内存的长度                                               |
| mem_write              | mem_write_expr                         | BP_BEFOR 或 BP_AFTER  | 写入内存的表达式                                             |
| reg_read               | reg_read_offset                        | BP_BEFOR 或 BP_AFTER  | 被读取的寄存器的偏移                                         |
| reg_read               | reg_read_length                        | BP_BEFOR 或 BP_AFTER  | 被读取寄存器的值的长度                                       |
| reg_read               | reg_read_expr                          | BP_BEFOR 或 BP_AFTER  | 被读取的寄存器中的表达式                                     |
| reg_write              | reg_write_length                       | BP_BEFOR 或 BP_AFTER  | 被写入寄存器数据的长度                                       |
| reg_write              | reg_write_expr                         | BP_BEFOR 或 BP_AFTER  | 被写入寄存器的表达式                                         |
| tmp_read               | tmp_read_num                           | BP_BEFOR 或 BP_AFTER  | 被读入的临时值的长度                                         |
| tmp_read               | tmp_read_expr                          | BP_AFTER              | 被读入的临时表达式                                           |
| tmp_write              | tmp_write_num                          | BP_BEFOR 或 BP_AFTER  | 被写入临时值的数                                             |
| tmp_write              | tmp_write_expr                         | BP_AFTER              | 被写入临时值的表达式                                         |
| expr                   | expr                                   | BP_AFTER              | 表达式的值                                                   |
| statement              | statement                              | BP_AFTER 或BP_BEFOR   | IR在其所在的基本块中的索引值（即断在当前基本块中的索引值）   |
| instruction            | instruction                            | BP_BEFORE 或 BP_AFTER | 本地指令的地址                                               |
| irsb                   | address                                | BP_BEFORE 或 BP_AFTER | 基本块地址                                                   |
| constraints            | added_constraints                      | BP_BEFORE 或 BP_AFTER | 被加入的约束的列表                                           |
| call                   | function_address                       | BP_BEFORE 或 BP_AFTER | 被调用的函数名                                               |
| exit                   | exit_target                            | BP_BEFORE 或 BP_AFTER | 代表SimExit的目标的表达式                                    |
| exit                   | exit_guard                             | BP_BEFORE 或 BP_AFTER | 代表SimExit的限制的表达式                                    |
| exit                   | jumpkind                               | BP_BEFORE 或 BP_AFTER | 代表SimExit的种类的表达式                                    |
| symbolic_variable      | symbolic_name                          | BP_BEFORE 或 BP_AFTER | 正在被创建的符号变量的名字。解析引擎可能改变这个名字（通过在后面添加唯一的ID和长度）。检查symbolic_expr来得到最终的符号表达式 |
| symbolic_variable      | symbolic_size                          | BP_BEFORE 或 BP_AFTER | 正在被创建的符号变量的长度                                   |
| symbolic_variable      | symbolic_expr                          | BP_AFTER              | 代表新的符号变量的符号表达式                                 |
| address_concretization | address_concretization_strategy        | BP_BEFORE 或 BP_AFTER | 被用于解析地址的SimConcretizationStrategy。断点处理函数可以改变将要被应用于解析当前地址的策略。如果你的断点处理函数被置为None，这个策略就会被忽略 |
| address_concretization | address_concretization_action          | BP_BEFORE 或 BP_AFTER | 用于记录内存操作的SimAction对象                              |
| address_concretization | address_concretization_memory          | BP_BEFORE 或 BP_AFTER | 被操作的SimMemory对象                                        |
| address_concretization | address_concretization_expr            | BP_BEFORE 或 BP_AFTER | 代表正在被解析的地址的AST。断点处理函数可以改变这个来影响正在被解析的地址 |
| address_concretization | address_concretization_add_constraints | BP_BEFORE 或 BP_AFTER | 约束是否应该别加入到这次读取中                               |
| address_concretization | address_concretization_result          | BP_AFTER              | 被解析的地址列表(整型数)。断点处理函数可以覆盖这个来产生不同的解析结果。 |

> 译者注：对于上面好多属性及其说明，译者也是一脸懵逼，只好等以后使用熟练了，理解其含义之后再回来修改了

你可以在合适的断点回调函数中通过通过`state.inspect`来访问这些属性，你甚至可以改变这些值来影响这些属性的后续使用！

![img](https:////upload-images.jianshu.io/upload_images/19793687-e2aca2f929a84732.png?imageMogr2/auto-orient/strip|imageView2/2/w/906)

> 执行结果
>
> ![img](https:////upload-images.jianshu.io/upload_images/19793687-d1fa1f904970cb39.png?imageMogr2/auto-orient/strip|imageView2/2/w/1200)

另外，这些属性都可以作为`inspect.b`的关键字参数来使用，这可以使得断点更加准确

下面的例子将会在程序**可能**(考虑到符号化的地址)往0x1000地址处写之前断下：

![img](https:////upload-images.jianshu.io/upload_images/19793687-2946b9b28ac70cc1.png?imageMogr2/auto-orient/strip|imageView2/2/w/988)

下面的例子将会在程序**只能**往内存0x1000处写数据之前断下：

![img](https:////upload-images.jianshu.io/upload_images/19793687-bb09d9a9a53790ec.png?imageMogr2/auto-orient/strip|imageView2/2/w/1200)

下面的例子将会在指令地址0x8000执行后生效，但是只有0x1000是从内存中读出的表达式的可行解：

![img](https:////upload-images.jianshu.io/upload_images/19793687-73a10d00223c9e47.png?imageMogr2/auto-orient/strip|imageView2/2/w/1148)

流批！实际上，我们甚至可以指定一个函数作为条件：

下面的例子中展示如何用函数表示复杂条件，用这种方式几乎可以做任何事！例子中将会保证断下时RAX的值是0x41414141，而且从地址0x8004开始的基本块在这个state的执行历史中：

![img](https:////upload-images.jianshu.io/upload_images/19793687-f727deb5ba2fccf1.png?imageMogr2/auto-orient/strip|imageView2/2/w/976)

> 译者注：原文档中cond方法的return值中有一处错误：state.eval是不存在的属性（或者也有可能是新版不支持了），这里修正为state.solver.eval。