# 加载一个二进制文件——CLE和angr工程

之前，你只看到了angr最原始的加载方法——你加载了`/bin/true`,之后又以不加载共享库文件的方式加载了一遍。你也看到了`proj.loader`和它能做的一些事情。现在，我们将会深入这些接口的细微之处，让它们告诉你更细节的信息。

我们简要提到了angr的二进制加载组件，CLE。CLE代表“CLE Loads Everything”，负责加载二进制文件（以及任何这个文件以来的库），并用一种容易操作的方式将它们展示给angr的其余组件。

# 加载器 (The Loader)

让我们重新加载`/bin/true`并且深入学习如何和loader交互：

![img](https:////upload-images.jianshu.io/upload_images/19793687-be890a064307690e.png?imageMogr2/auto-orient/strip|imageView2/2/w/639)

## 已加载的对象

CLE加载器(`cle.Loader`)代表一整个被加载的二进制对象的集合，它们被加载并且映射到同一个内存空间中。每一个二进制对象都被一个能够处理对应文件类型(`cle.Backend`的子类)的加载器后端加载。比如，`cle.ELF`被用来加载ELF格式的二进制文件。

内存中也会有一些和任何被加载的二进制文件都无关的对象。比如，被用来提供线程本地存储(Thread-Local storage)支持的对象和用于提供未解析的符号的外部对象。

> 译者注：这里的线程本地存储应该指的是[TLS](https://links.jianshu.com/go?to=http%3A%2F%2Fwww.cppblog.com%2FTim%2Farchive%2F2012%2F07%2F04%2F181018.html)

你可以使用`loader.all_objects`来获取CLE已经加载的所有对象，也可以指定更加具体的类别来访问这些对象：

![img](https:////upload-images.jianshu.io/upload_images/19793687-a8801fca33d72976.png?imageMogr2/auto-orient/strip|imageView2/2/w/700)

你可以直接和这些对象交互来获取元数据：

- 获取ELF的内存分段和文件分段

![img](https:////upload-images.jianshu.io/upload_images/19793687-2da3e7126f68e8b6.png?imageMogr2/auto-orient/strip|imageView2/2/w/1200)

- 获取PLT表信息

  ![img](https:////upload-images.jianshu.io/upload_images/19793687-e5d5483c4601aa22.png?imageMogr2/auto-orient/strip|imageView2/2/w/708)

- 展示[预链接](https://links.jianshu.com/go?to=https%3A%2F%2Flinux.die.net%2Fman%2F8%2Fprelink) 基址和实际装载到的内存基址：

![img](https:////upload-images.jianshu.io/upload_images/19793687-e3bb65c694612384.png?imageMogr2/auto-orient/strip|imageView2/2/w/305)

> 我这里的`obj.linked_base`返回0，而文档中返回的是和装载地址一样的值，由于不太了解预链接过程，目前猜测是系统相关的，这里不深究。

## 符号和重定位

在使用CLE的同时也可以使用符号。一个“符号”在形式化执行的世界中是一个基础概念，它将一个名字有效地(effectively)映射到一个地址。

从CLE中获取符号，最简单的方法是使用`loader.find_symbol`， 它接收一个名字或者一个地址并返回一个符号对象。

![img](https:////upload-images.jianshu.io/upload_images/19793687-83e9b1b5a1f447d1.png?imageMogr2/auto-orient/strip|imageView2/2/w/513)

一个符号最有用的属性是它的名字、父对象(owner)、和它的地址。但是一个符号的“地址”却是一个含糊的概念。有三种方式来准确表述一个符号的“地址”：

- `.rebased_addr` 是一个符号在全局地址空间中的地址。这就是你直接打印`symbol.addr`会显示的内容。

![img](https:////upload-images.jianshu.io/upload_images/19793687-b8c97588ce01eb89.png?imageMogr2/auto-orient/strip|imageView2/2/w/919)

- `.linked_addr`是符号相对于二进制文件预链接基址的地址，这个地址和用诸如readelf(1)显示的地址是一样的。
- `.relative_addr`是符号相对于对象基址的地址。在一些文献中(尤其在windows的文献中)，这样的地址被称为RVA(相对虚拟地址)

![img](https:////upload-images.jianshu.io/upload_images/19793687-9cf9c5d709d0235d.png?imageMogr2/auto-orient/strip|imageView2/2/w/632)

除了提供调试信息，符号还支持动态链接概念。libc提供了malloc作为导出函数，并且主程序("/bin/true")使用这个函数。如果我们要求CLE直接从主程序对象中给出一个malloc的符号，它将会告诉我们这是一个“导入符号”。导入符号没有与其关联的有意义的地址，但是它提供了能够用于解析它的对象的引用，可以用`.resolvedby`来获得引用。

![img](https:////upload-images.jianshu.io/upload_images/19793687-086a886a220f7f3e.png?imageMogr2/auto-orient/strip|imageView2/2/w/737)

说明：

- 在之前的loader中，我们使用`find_symbol`方法，因为它执行一个搜索操作来找到指定的符号。
- 在一个独立的对象中，这个方法是`get_symbol`，因为一个给定的名字只会对应一个符号。

导入符号(import symbol)和导出符号(export symbol)的关系应该在内存中以一种特殊的方式被记录，这种方式引出另一种特殊的概念——“重定位”。“重定位”说的是：当你将一个[import]和一个导出符号匹配的时候，请将导出符号的地址按照[format]的形式写到[location]。我们可以通过`obj.relocs`(获取`Relocation`实例)看到一个对象的完成重定位表，或者通过`obj.imports`看到符号名和他们的重定位地址的映射关系。对于导出符号表，angr中没有相应对象与之对应。

![img](https:////upload-images.jianshu.io/upload_images/19793687-455ab7cf16d45ad1.png?imageMogr2/auto-orient/strip|imageView2/2/w/975)

markdown-img-paste-2018011621104094.png

![img](https:////upload-images.jianshu.io/upload_images/19793687-59d019d76258eae2.png?imageMogr2/auto-orient/strip|imageView2/2/w/708)

一个对象中需要重定位的相应导入符号可以用`.symbol`获取。重定位将会写入的地址可以通过访问一个Symbol的地址的任何方式获取，你还可以通过`.owner_obj`来获得一个请求重定位的对象的引用。

> 译者注：经过测试，`.symbol` 似乎已经被 `.symbols_by_addr` 替代，具体情况我询问作者之后再来确认。测试情况如下：

![img](https:////upload-images.jianshu.io/upload_images/19793687-4304b43e92d48034.png?imageMogr2/auto-orient/strip|imageView2/2/w/789)

> 关于`.owner_obj`的测试，之前创建的之前创建的main_malloc返回的是主程序对象的引用：

![img](https:////upload-images.jianshu.io/upload_images/19793687-b4b8b0b5d83cb7ac.png?imageMogr2/auto-orient/strip|imageView2/2/w/504)

重定位信息不能以比较漂亮的形式展示出来，因为重定位的地址是python内置的，是和我们的程序无关的。

> 译者注：原文是“so”,我觉得逻辑不通，故译为"because"
>  这里“和我们的程序无关”的意思应该是重定位的地址有python内部决定，对于我们的程序而言不需要关心。

如果一个导入符号不能被解析为任何导出符号，比如找不到对应的共享库文件，CLE将会自动更新`loader.extern_obj`来表明这个符号由CLE导出。

# 加载选项

如果你正在使用`angr.Project`加载一些东西并且你想要给`cle.loader`实例传一个选项来创建Project，你可以直接传入关键字参数给Project的构造函数，你传入的关键字就会被传给CLE。如果你想要知道所有能够被作为选项传入的参数，你可以查看[CLE的API文档](https://links.jianshu.com/go?to=http%3A%2F%2Fangr.io%2Fapi-doc%2Fcle.html)。在本文档中，我们只看一些重要的并且被频繁使用的选项。

## 基本选项

我们已经用过了`auto_load_libs`选项——它控制CLE是否自动加载共享库文件，默认是自动加载的。另外，有一个相反的选项`except_missing_libs`,这个选项如果被设置为true，将在二进制包含无法解析的共享库时抛出一个异常。

你可以传入一个字符串列表给`force_load_libs`选项，每一个被列出的字符串将会被当做一个不可解析共享库依赖，或者你可以传入一个字符串列表给`skip_libs`来防止列表列出的共享库的被作为依赖添加。另外，你可以传入一个字符串列表给`custom_ld_path`选项，这个选项中的字符串会被作为额外的搜索共享库文件的路径，这些路径将会比任何默认路径先被搜索，默认路径包括：被加载文件所在的路径，当前工作路径，系统库路径。

## Per-Binary 选项

如果你想要对一个特定的二进制对象设置一些选项，CLE也能满足你的需求。参数`main_opts`和`lib_opts`接收一个以python字典形式存储的选项组。`main_opts`接收一个形如{选项名1：选项值1，选项名2：选项值2……}的字典，而`lib_opts`接收一个库名到形如{选项名1:选项值1，选项名2:选项值2……}的字典的映射。

> 译者注：lib_opts是二级字典，原因是一个二进制文件可能加载多个库，而main_opts指定的是主程序加载参数，而主程序一般只有一个，因此是一级字典。

这些选项的内容因不同的后台而异，下面是一些通用的选项：

- backend —— 使用哪个后台，可以是一个对象，也可以是一个名字(字符串)
- custom_base_addr —— 使用的基地址
- custom_entry_point —— 使用的入口点
- custom_arch —— 使用的处理器体系结构的名字

例子：

![img](https:////upload-images.jianshu.io/upload_images/19793687-6baa719b8455f781.png?imageMogr2/auto-orient/strip|imageView2/2/w/1200)

> 译者注：我尝试修改/bin/true的加载基址，但是似乎没有效果？

## 后台（Backends）

CLE目前有能够静态加载ELF,PE,CGC,Mach-O和ELF核心转储文件的后台，并且支持使用IDA加载二进制和加载文件到一个平坦地址空间。大部分情况下，CLE将会自动检测二进制文件来决定使用哪个后台，所以除非你在做一些很奇怪的工作，一般情况下你不需要指定使用哪个后台。

你可以和上一节描述的一样，用传入一个键的方式强制CLE使用指定的后台。一些后台不能被自动检测，因此必须用`custom_arch`指定。键值不需要匹配任何一个架构：根据你给出的任意架构的任意通用标识符，angr都能够识别出你指的是哪个架构。

为了指定使用的后台，使用下表列出的名字：

| 名字      | 描述                                                | 是否需要用custom_arch指定? |
| --------- | --------------------------------------------------- | -------------------------- |
| elf       | 基于PyELFTools的ELF文件静态加载器                   | 不需要                     |
| pe        | 基于PEFile的静态PE文件加载器                        | 不需要                     |
| mach-o    | Mach-O文件的静态加载器，不支持动态链接或者变基      | 不需要                     |
| cgc       | Cyber Grand Challenge系统中的二进制文件的静态加载器 | 不需要                     |
| backedcgc | 允许指定内存和寄存器支持的CGC二进制文件静态加载器   | 不需要                     |
| elfcore   | ELF核心转储文件的静态加载器                         | 不需要                     |
| ida       | 启动ida来分析文件                                   | 需要                       |
| blob      | 按照平坦模式加载文件到内存中                        | 需要                       |

> 关于表中提到的CGC，[这个youtube视频](https://links.jianshu.com/go?to=https%3A%2F%2Fwww.youtube.com%2Fwatch%3Fv%3DSYYZjTx92KU)展示了什么是CGC，简单来说就是一个简化的操作系统，这个系统构建的目的主要是用于CTF比赛中供各队伍使用自己的AI来自动化分析和寻找这个简化的系统上运行的程序的漏洞，CGC比赛是CTF的另一种形式。

# 符号函数摘要集(Symbolic Function Summaries)

> 译者注：这里的“摘要”不是指对符号函数的一个概括和总结，而是符号执行中的一个概念

默认情况下，Project都会尝试用SimProcedures这个符号摘要集(symbolic summaries)替换主程序的外部调用。SimProcedure使用
 pyhton函数高效地模拟外部库函数对state的影响。我们已经在SimProcedure中实现了[一个完整的函数集
 ](https://links.jianshu.com/go?to=https%3A%2F%2Fgithub.com%2Fangr%2Fangr%2Ftree%2Fmaster%2Fangr%2Fprocedures)。这些内建过程(procedures)能够在`angr.SIM_PROCEDURES`字典中获得，这个字典是一个两层结构，第一层的键是包名(libc,posix,win32,stubs)，第二层的键是库函数的名字。用SimProcedure替代实际库函数的执行虽然存在[一些潜在的不准确性](https://links.jianshu.com/go?to=https%3A%2F%2Fdocs.angr.io%2Fdocs%2Fgotchas.html)，但是可以让你的分析更加可控，

当找不到某个函数的摘要时：

- 如果`auto_load_libs`的值为`True`（默认值），那么真正的库函数就会被执行。这可能是你想要的，也可能不是，取决于实际的函数是什么。比如说，一些libc函数十分复杂，难以分析，并且极有可能导致用于确定执行的路径的状态数爆炸。
- 如果`auto_load_libs`是`False`，那么外部函数就是“未解析”的状态，并且Project对象将会将它们解析为叫做`ReturnUnconstrained`的通用“stub” SimProdurce。就如它的名字所描述的：每次这个符号被调用，它都会将一个唯一的无约束符号作为返回值。
- 如果`use_sim_procedures`(这是`angr.Project`的参数，不是`cle.loader`的参数)是`False`（默认是True），那么只有外部对象提供的符号才会被SimProcedures替代，并且他们将会被一个`ReturnUnconstrained`stub替代。
- 你可以给`angr.Project`传以下参数来指定一个不想被SimProcedure替代的符号：
   `exclude_sim_procedures_list` 和 `exclude_sim_procedures_func`。
- 查看`angr.Project._register_object`的源码来获取精确的算法。

## 钩子(Hooking)

angr使用python函数摘要替换库函数代码的机制叫做Hooking，而且你也可以这么做！在执行一次模拟（simulation）时，每一步执行angr都会检查当前地址是否被下了钩子（hooked），并且如果检查到钩子，就会执行钩子函数，而不是那个地址里的二进制码。使用API`proj.hook(addr,hook)`可以完成hook，这里参数中的`hook`是一个SimProcedure实例。你可以用`.is_hooked`，`.unhook`和`.hook_by`属性来管理你project中的钩子，这些属性的含义就如字面的意思，这里就不解释了。

通过把`proj.hook(addr)`作为一个函数装饰器(function decorator)。，你可以指定你自己的函数作为hook函数。如果你这么做了，你还可以指定一个可选的关键词参数`length`来决定在你的hook函数执行结束之后，程序跳过多少字节的机器码再继续执行。

![img](https:////upload-images.jianshu.io/upload_images/19793687-084df5df48f72d40.png?imageMogr2/auto-orient/strip|imageView2/2/w/784)

此外，你可以使用`proj.hook_symbol(name,hook)`,提供一个符号名称作为第一个参数，这样第二个参数指定的钩子函数会被下到这个符号被调用的每个地址中。它的一个很重要的用途是用来扩展angr的内建库SimProcedure的行为。因为这些库函数仅仅是一些类，你可以写它们的子类，重写它们的方法，并且把这些子类使用在hook中。

> 译者注：hook_symbol的使用方法如下

![img](https:////upload-images.jianshu.io/upload_images/19793687-dc125621349a4879.png?imageMogr2/auto-orient/strip|imageView2/2/w/580)

## So far so good!!

到目前为止，你应该在CLE加载器和angr Project的级别上对如何控制你分析时的环境有了一个理性的认识。你应该还理解了angr采用了一个合理的方式来简化它的分析：通过hook复杂的库函数，用SimProcedure这样的只在总体上表现库函数产生的影响的对象替代它们。

为了弄清使用CLE加载器和它的后台能做的所有事情，你可以查阅[CLE的API文档](https://links.jianshu.com/go?to=http%3A%2F%2Fangr.io%2Fapi-doc%2Fcle.html)。