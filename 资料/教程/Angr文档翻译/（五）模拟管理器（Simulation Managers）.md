# 模拟管理器（Simulation Managers）

SM（Simulation Managers）是angr中最重要的控制接口，它使你能够同时控制一组状态(state)的符号执行，应用搜索策略来探索程序的状态空间。现在我们就来学习如何使用它。

SM使你可以顺畅地控制多个状态。在SM中，状态都被组织在“stash”里，你可以对它们做执行一步、过滤、合并以及随意移动等操作。比如说，这允许你使两个不同的“stash”中的状态以不同的速度执行，然后再将它们合并。对大多数操作而言，默认的stash是`active`stash，当你初始化一个新的SM时，你的状态就放在那里面。

# 单步执行

SM的最基本能力就是让一个stash中的所有状态都执行一个基本块。使用`.step()`可以做到这一点：

![img](https:////upload-images.jianshu.io/upload_images/19793687-cb09387dcb854adf.png?imageMogr2/auto-orient/strip|imageView2/2/w/674)

markdown-img-paste-20180125101351431.png

当然，stash模式的真正强大之处在于，当一个状态执行到一个符号分支条件时，这个分支后的两个继承状态都会出现在stash中，而且你可以使它们同步地单步执行，如果你想仔细控制程序执行而且你只想执行到没有状态可以继续执行，你可以直接使用`.run()`方法：

![img](https:////upload-images.jianshu.io/upload_images/19793687-1d7aec9671396a35.png?imageMogr2/auto-orient/strip|imageView2/2/w/1200)

markdown-img-paste-20180125102818430.png

现在我们得到了3个“deadend”状态!如果一个状态在执行后不能够产生任何后继状态，例如它执行了一个`exit`的系统调用，那么这个状态就会被放入`deadend`stash。

# Stash 管理

让我们看看如何使用Stash。

使用`.move()`将状态在不同stash间移动，这个方法接收参数`from_stash`，`to_stash`和`filter_func`（这个参数是可选的，默认将stash中的所有状态都移动）。例如，我们可以将输出带有特定字符串的状态都移动到指定的stash中：

![img](https:////upload-images.jianshu.io/upload_images/19793687-47fc8576b78be5e3.png?imageMogr2/auto-orient/strip|imageView2/2/w/1163)

markdown-img-paste-20180125103612448.png

我们可以通过要求将状态移入某个新的stash的方法来创建一个新的stash。在这个stash中的所有状态的标准输出中都有一个“Welcome”字符串，在目前这是一个很好的状态分类指标。

> 译者注：因为就这个带后门的fauxware固件来说，有Welcome提示就意味着成功登录了。

每一个stash都是一个列表，你可以通过索引或者迭代器的方式访问到每一个独立的状态，但是也有一些替代的方法来访问每个状态。如果你用“one_stash名”的方式访问stash，那么你会获得这个stash中的第一个状态；如果你用“mp_stash名”的方式访问stash，那么你将会得到[mulpyplexed](https://links.jianshu.com/go?to=https%3A%2F%2Fgithub.com%2Fzardus%2Fmulpyplexer)版本的stash：

![img](https:////upload-images.jianshu.io/upload_images/19793687-cb51a332927e7f2d.png?imageMogr2/auto-orient/strip|imageView2/2/w/1200)

markdown-img-paste-20180125105632168.png

当然，`step`，`run`，以及任何其它的可以在一个stash的路径上操作的方法，都可以指定一个stash参数，指定对哪个stash做操作。

SM还提供了很多有趣的工具来帮助你管理你的stash。我们现在不会深入每一个工具的使用，但是你可以查看API文档。（文档链接未完成）

# stash类型

你可以使用任何你喜欢的stash，但是有一些被用于分类特殊状态的stash，它们是：

| Stash         | 描述                                                         |
| ------------- | ------------------------------------------------------------ |
| active        | 这个stash中的状态会被默认执行，除非执行前指定了特定要执行的stash |
| deadended     | 当一个状态因为某些原因不能继续执行时，它就进入"deadend"stash。这些原因包括没有合法指令可以执行、所有子状态（的约束条件）都不可满足、或者一个非法的PC指针。 |
| pruned        | 当使用`LAZY_SOLVES`时，不到万不得已时不会检测state是否可满足。当在`LAZY_SOLVES`模式下一个状态被发现不可满足时，这个状态的父状态就会被检查，以找出状态历史中最开始的那个不可满足的状态，这个状态的所有子孙状态都是不可满足的（因为一个不可满足的状态不会变为可满足的状态），因此这些状态都需要被剪切掉，并且放入“pruned”stash中。 |
| unconstrained | 如果`save_unconstrained`选项被提供给SM的构造函数，那么被认为"不受约束"的状态（比如指令指针被用户输入或者其他符号来源控制的状态）就被放在这个stash中。 |
| unsat         | 如果`save_unsat`选项被提供给SM的构造函数，那么被认定不可满足的状态（比如某个状态有两个互相矛盾的约束条件）会被放在这里。 |

# 简单探索(Simple Exploration)

符号执行最普遍的操作是找到能够到达某个地址的状态，同时丢弃其他不能到达这个地址的状态。SM为使用这种执行模式提供了捷径：`.explore()`方法。

当使用`find`参数启动`.explore()`方法时，程序将会一直执行，直到发现了一个和`find`参数指定的条件相匹配的状态。`find`参数的内容可以是想要执行到的某个地址、或者想要执行到的地址列表、或者一个获取state作为参数并判断这个state是否满足某些条件的函数。当`active`stash中的任意状态和`find`中的条件匹配的时候，它们就会被放到`found`stash中，执行随即停止。之后你可以探索找到的状态，或者决定丢弃它，转而探索其它状态。你还可以按照和`find`相同的格式设置另一个参数——`avoid`。当一个状态和`avoid`中的条件匹配时，它就会被放进`avoided`stash中，之后继续执行。最后，`num_find`参数指定函数返回前需要找到的符合条件的状态的个数，这个参数默认是1。当然，如果`active`stash中已经没有状态可以执行，那么不论有没有找到你指定的状态个数，都会停止执行。

让我们来简单看一个[crackme](https://links.jianshu.com/go?to=https%3A%2F%2Fgithub.com%2Fangr%2Fangr-doc%2Ftree%2Fmaster%2Fexamples%2FCSCI-4968-MBE%2Fchallenges%2Fcrackme0x00a)的例子：

首先我们加载这个二进制文件：

![img](https:////upload-images.jianshu.io/upload_images/19793687-c6e9abdcc667abf2.png?imageMogr2/auto-orient/strip|imageView2/2/w/426)

markdown-img-paste-20180125131451710.png

然后我们创建一个SM:

![img](https:////upload-images.jianshu.io/upload_images/19793687-f177767007d57769.png?imageMogr2/auto-orient/strip|imageView2/2/w/380)

markdown-img-paste-20180125131554962.png

现在我们符号执行直到我们找到一个符合我们要求的state（比如标准输出中输出“Congrats”）：

![img](https:////upload-images.jianshu.io/upload_images/19793687-065cc1124f1171f5.png?imageMogr2/auto-orient/strip|imageView2/2/w/628)

markdown-img-paste-20180125131709456.png

现在我们就可以从这个状态中获得flag啦～：

![img](https:////upload-images.jianshu.io/upload_images/19793687-d1f07e721ddc8c96.png?imageMogr2/auto-orient/strip|imageView2/2/w/1150)

markdown-img-paste-20180125131917376.png

你可以在[这里](https://links.jianshu.com/go?to=https%3A%2F%2Fgithub.com%2Fangr%2Fangr-doc%2Ftree%2Fmaster%2Fexamples)获取其它的例子。

# 探索技术（Exploration Techniques）

angr封装了几个功能使你能够自定义SM的行为，这些功能被称为"探索技术"。为什么你会需要探索技术呢？一个典型的例子是，你想修改程序状态空间的探索模式——默认是“每个state只执行一次”的广度优先搜索策略。但如果使用探索技术，你可以实现诸如深度优先搜索。然而这些探索技术能做的事(instrumentation power of these techniques)远比这些灵活——你可以完全改变angr单步执行的行为。在之后的章节里，我们会介绍如何编写你自己的探索技术。

调用`simgr.use_technique(tech)`使用特定的探索技术，其中`tech`是ExplorationTechnique的子类的实例。angr內建的探索技术可以在`angr.exploration_techniques`中找到.

这里是一些內建探索技术的简介：

- Explorer：这个技术实现了`.explore()`的功能，允许你寻找或避开某些指定的地址。
- DFS：深度优先搜索。每次只保持一个状态是`active`的，并把其余状态都放在`deferred`stash中，直到当前active状态达到`deadend`或`errors`。
- LoopLimiter：用一个循环次数的近似值来丢弃那些似乎会多次执行某个循环的状态，并把它们放入`spinning`stash中；当没有其它可执行的状态时，再把它们拉出来继续执行。
- LengthLimiter: 设置每个状态能够执行的路径长度的上限。
- ManualMergepoint: 将程序中的某个地址作为合并点，当某个状态到达那个地址时，会被短暂地存储，之后，在指定时延内到达同一地址的状态都会被合并到这个状态。
- Veritesting: 是一篇[CMU论文](https://links.jianshu.com/go?to=https%3A%2F%2Fusers.ece.cmu.edu%2F~dbrumley%2Fpdf%2FAvgerinos%20et%20al._2014_Enhancing%20Symbolic%20Execution%20with%20Veritesting.pdf)中提及的自动化定义合并点的方法的实现。这很有用，你可以通过在SM的构造函数中传入`veritesting=True`来启用它。注意这个技术通常不能和其余技术很好地兼容，因为它使用了入侵的方式来实现静态符号执行。
- Tracer: 一种使程序按照从其他资源获得动态追踪记录执行的探索技术（类似于复现某次执行过程？）。这个[动态跟踪仓库](https://links.jianshu.com/go?to=https%3A%2F%2Fgithub.com%2Fangr%2Ftracer)
   里有一些工具能够产生这些路径。
- Oppologist:这个“operation apologist”是一个特别有趣的技术——它被开启后，当angr执行到了一个不被支持的指令（比如一个奇怪的或者外部的浮点SIMD操作）时，它将会具体化这条指令的所有输入，并且使用独角兽引擎(unicorn engine)来执行这条指令，这使得程序执行得以延续。
- Threading: 对程序的单步执行加入线程级并发支持。由于python全局解释器的锁定，这并没有什么帮助，但是如果你有一个程序在分析时花费了大量时间在angr的本地代码依赖上，这个技术可能会起到加速效果。
- Spiller: 当`active`stash中有过多状态时，这项技术将会把其中的一些dump到硬盘上来保证低内存消耗。

查看[simulation manager](https://links.jianshu.com/go?to=http%3A%2F%2Fangr.io%2Fapi-doc%2Fangr.html%23module-angr.manager)和[exploration techniques](https://links.jianshu.com/go?to=http%3A%2F%2Fangr.io%2Fapi-doc%2Fangr.html%23angr.exploration_techniques.ExplorationTechnique)的API来获取更多的信息。