## 详解UnLink

## 解析

首先我们先说一下为什么会合并 chunk，这是为了避免 heap 中有太多零零碎碎的内存块，合并之后可以用来应对更大的内存块请求。合并的主要顺序为

- 先考虑物理低地址空闲块
- 后考虑物理高地址空闲块

且 只有不是 fast bin 的情况下才会触发 unlink ，本人感觉CTF Wiki上很多东西讲的不是很清楚，故自己写了

首先又是这张经典的图

![](https://github-1251836300.cos.ap-guangzhou.myqcloud.com/%E8%AF%A6%E8%A7%A3UnLink/unlink_smallbin_intro.png)

这张图，至少那时候我看得很迷糊，主要是unlink的时候到底那个是P，哪个是BK，哪个是FD，物理内存上到底又是什么样子的，就很迷糊，所以我觉得好好研究研究

![](https://github-1251836300.cos.ap-guangzhou.myqcloud.com/%E8%AF%A6%E8%A7%A3UnLink/old_unlink_vul.png)

又是这经典的图作为例子，还是很迷糊，于是我决定换个形式描述这张图，首先是一个**chunk**在内存中的真实布局

|   Low Address    |  Prev_size  |
| :--------------: | :---------: |
|                  |  **Size**   |
|                  |   **fd**    |
|                  |   **bk**    |
| **High Address** | **Content** |

所以上面那张图在内存中的布局应该是

|   Low Address    |    Prev_size     |           **Q**            |
| :--------------: | :--------------: | :------------------------: |
|                  |  **Size=0x81**   |                            |
|                  | **User Content** |                            |
|                  |  **Prev_Size**   |       **NextChunk**        |
|                  |  **Size=0x80**   |                            |
|                  |      **fd**      |                            |
|                  |      **bk**      |                            |
|                  | **Unuser Data**  |                            |
|                  |  **Prev_size**   | **NextChunk of NextChunk** |
|                  |  **Size=0x80**   |                            |
| **High Address** | **User Content** |                            |

 其中 **Q** 处于使用状态、**Nextchunk** 处于释放状态 , 当我们 **free(Q)**  

- **glibc** 判断这个块是 **small chunk**
- 先考虑物理低地址空闲块，判断前向合并，发现前一个 **chunk** 处于使用状态，不需要前向合并
- 后考虑物理高地址空闲块，判断后向合并，发现后一个 **chunk** 处于空闲状态，需要合并
- 继而对 **Nextchunk** 采取 **unlink** 操作

则此时，**P**即为**Nextchunk**，**FD**是**Q**，**BF**是**Nextchunk of Nextchunk**

![](https://github-1251836300.cos.ap-guangzhou.myqcloud.com/%E8%AF%A6%E8%A7%A3UnLink/QQ%E5%9B%BE%E7%89%8720191121011336.png)

此时横向内存布局也是Low Address ——> High Address

|     Q（FD）     | Nextchunk（P） | Nextchunk of Nextchunk（BK） |
| :-------------: | :------------: | :--------------------------: |
| **Low Address** |                |         High Address         |

那么 unlink 具体执行的效果是什么样子呢？我们可以来分析一下

- **FD=P->fd**  = **Nextchunk address - 12**
  -  **FD = Q**
- **BK=P->bk** 
  -  **BK = Nextchunk of Nextchunk**
- **FD->bk = BK** 
  - **Q->bk = Nextchunk of Nextchunk**
- **BK->fd = FD**
  - **Nextchunk of Nextchunk->fd = Q**

注意到倘若我们能修改**Nextchunk**的**fd**和**bk**，将**fd**和**bk**指向虚构的**chunk**地址，那么就有可能实现任意地址读写，那么假设我们把**Nextchunk**的**fd**设定为**target addr -12 **,**bk**设定为**expect value**，那么接下来

- **FD=P->fd = target addr -12**
- **BK=P->bk = expect value**
- **FD->bk = BK，即 *(target addr-12+12)=BK=expect value**
- **BK->fd = FD，即 *(expect value +8) = FD = target addr-12**

我们就可以使**target addr** = **expect value**, 看起来我们似乎可以通过 unlink 直接实现任意地址读写的目的，但是我们还是需要确保 expect value +8 地址具有可写的权限

比如说我们将 target addr 设置为某个 got 表项，那么当程序调用对应的 libc 函数时，就会直接执行我们设置的值（expect value）处的代码。例如我们将free修改为system，当程序执行free的时候就会执行system

**需要注意的是，expect value+8 处的值被破坏了，需要想办法绕过** 

我们刚才考虑的是没有检查的情况，但是一旦加上检查，就没有这么简单了。我们看一下对 fd 和 bk 的检查 

```c
// fd bk
if (__builtin_expect (FD->bk != P || BK->fd != P, 0))                      \
  malloc_printerr (check_action, "corrupted double-linked list", P, AV);  \
```

如果按照我们之前说所的那样修改fd和bk此时

- FD->bk = target addr - 12 + 12=target_addr
- BK->fd = expect value + 8 = target addr-12

就无法通过检查

首先我们通过覆盖，将 nextchunk 的 FD 指针指向了 fakeFD，将 nextchunk 的 BK 指针指向了 fakeBK 。那么为了通过验证，我们需要

- `fakeFD -> bk == P`  <=>  `*(fakeFD + 12) == P`
- `fakeBK -> fd == P`  <=>  `*(fakeBK + 8) == P`

当满足上述两式时，可以进入 Unlink 的环节，进行如下操作：

- `fakeFD -> bk = fakeBK`  <=>  `*(fakeFD + 12) = fakeBK`
- `fakeBK -> fd = fakeFD`  <=>  `*(fakeBK + 8) = fakeFD`

如果让 fakeFD + 12 和 fakeBK + 8 指向同一个指向 P 的指针，那么：

- `*P = P - 8`
- `*P = P - 12`

即通过此方式，P 的指针指向了比自己低 12 的地址处。此方法虽然不可以实现任意地址写，但是可以修改指向 chunk 的指针，这样的修改是可以达到一定的效果的。

需要注意的是，这里我们并没有违背下面的约束，因为 P 在 Unlink 前是指向正确的 chunk 的指针。

```
    // 由于P已经在双向链表中，所以有两个地方记录其大小，所以检查一下其大小是否一致。
    if (__builtin_expect (chunksize(P) != prev_size (next_chunk(P)), 0))      \
      malloc_printerr ("corrupted size vs. prev_size");               \
```

**此外，其实如果我们设置 next chunk 的 fd 和 bk 均为 nextchunk 的地址也是可以绕过上面的检测的。但是这样的话，并不能达到修改指针内容的效果**

## 利用思路 

### 条件 

1. UAF ，可修改 free 状态下 smallbin 或是 unsorted bin 的 fd 和 bk 指针
2. 已知位置存在一个指针指向可进行 UAF 的 chunk

### 效果 

使得已指向 UAF chunk 的指针 ptr 变为 ptr - 0x18

### 思路 

设指向可 UAF chunk 的指针的地址为 ptr

1. 修改 fd 为 ptr - 0x18
2.  修改 bk 为 ptr - 0x10
3.  触发 unlink

ptr 处的指针会变为 ptr - 0x18