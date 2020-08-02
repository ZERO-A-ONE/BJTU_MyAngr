#  长亭PWN笔记03

- 什么是堆
- glibc的堆管理实现
  - arena
  - bins
  - chunk
- malloc和free的工作流程
- fastbin attack  
- 新版本glibc中的tcache
- 堆的花式玩法

## 什么是堆

![ ](https://github-1251836300.cos.ap-guangzhou.myqcloud.com/%E9%95%BF%E4%BA%AD%E5%85%AC%E5%BC%80%E8%AF%BE/Pwn%E6%9C%AF%E8%BF%9B%E9%98%B6%EF%BC%8C%E7%8E%A9%E8%BD%AC%E5%A0%86%E6%BA%A2%E5%87%BA/QQ%E5%9B%BE%E7%89%8720200501204507.png)

- 栈通常用于为函数分配固定大小的局部内存
- 堆是可以根据运行时的需要进行动态分配和释放的内存，大小可变
  - Malloc/New
  - Free/Delete
- 堆的实现重点关注内存块的组织和管理方式，尤其是空闲内存块
  - 如何提高分配和释放效率
  - 如何降低碎片化，提高空间利用率
- 举例：浏览器的DOM树通常分配在堆上
  - 堆的实现算法影响堆分配网页加载和动态效果速度
  - 堆的实现算法影响浏览器对内存的使用效率 

## 常见堆实现

- dlmalloc - 通用分配器
- ptmalloc2 - glibc
  - 基于dlmalloc fork出来，在2006年增加了多线程支持
- jemalloc - FreeBSD、Firefox、Android
- tcmalloc - Google Chrome
- libumem - Solaris
- Windows 10 - segment heap

## ptmalloc2的多线程支持

- 不同的线程维护不同的堆，称为**per thread arena**
- 主线程创建的堆，称为**main arena**
- Arena数量受到CPU核数的限制
  - 对于32位系统：arena数量上限 = 2 * 核数
  - 对于64位系统：arena数量上限 = 8 * 核数

##  glibc的堆管理实现

- arena
  - 指的是堆内存区域本身，并非结构
  - 主线程的main arena通过sbrk创建
  - 其他线程arena通过mmap创建
- malloc_state
  - 管理arena的核心结构，包含堆的状态信息、bins链表等
  - main arena对应的malloc_state结构存储在glibc的全局变量中
  - 其他线程arena对应的malloc_state存储在arena本身当中
- bins
  - bins用来管理空闲内存块，通常使用链表结构来进行组织
- chunks
  - 内存块的结构

> 注意：
>
> （1）以下介绍的堆管理环境为glibc 2.26 以下（不含2.26），即出现tcache之前的堆管理方式
>
> （2）以下演示的环境均是64位程序及操作系统 

## Arena头部结构：malloc_state

malloc_state存储了Arena的状态，其中包括了很多用于管理空闲块的bins链表

```c
struct malloc_state {
	mutex_t mutex; /* 同步访问相关，互斥锁 */
	int flags; /* 标志位，以前是max_fast，在一些老的文章上可能还使用的这个说法，比如phrack */
	mfastbinptr fastbins[NFASTBINS]; /* fastbins，之后会说到,是一个chunk的链表 */
	mchunkptr top; /* top chunk，一个特殊的chunk，在之后会说到 */
	mchunkptr last_remainder; /* 最后一次拆分top chunk得到的剩余内容，之后会说到 */
	mchunkptr bins[BINS * 2]; /* bins，一个chunk的链表的数组，之后会说到 */
	unsigned int binmap[BINMAPSIZE]; /* bins是否为空的一个位图 */
	struct malloc_state *next; /* 链表，下一个malloc_state的位置 */
	struct malloc_state *next_free;
	INTERNAL_SIZE_T system_mem;
	INTERNAL_SIZE_T max_system_mem;
};
static struct mallo_state main_arena;/*global variable in libc.so*/
```

主线程的malloc_state结构存储在glibc的全局变量中，变量名为main_arena

##  Main Arena概览

![](C:\Users\syc\AppData\Roaming\Typora\typora-user-images\image-20200501213413134.png)

## 空闲内存块(free chunk)结构

![](https://github-1251836300.cos.ap-guangzhou.myqcloud.com/%E9%95%BF%E4%BA%AD%E5%85%AC%E5%BC%80%E8%AF%BE/Pwn%E6%9C%AF%E8%BF%9B%E9%98%B6%EF%BC%8C%E7%8E%A9%E8%BD%AC%E5%A0%86%E6%BA%A2%E5%87%BA/QQ%E5%9B%BE%E7%89%8720200502160807.png)

在64位平台下，free chunk的第一个字段prev_size（8字节）存储了前一个chunk的大小

free chunk的第二个字段size记录了当前chunk的大小，该字段最低三个bit被用作其他含义

- P代表PREV_INUSE，即代表前一个chunk是否被使用
- M代表IS_MMAPPED，代表当前chunk是否属于mmap出来的
- N代表NON_MAIN_ARENA，代表该chunk是否属于非MAIN Arena

第三个字段fd和第四个字段bk（8字节）前向指针和后向指针，这两个字段用于bin链表当中，用来链接大小相同或者相近的free chunk，便于后续分配时查找

## 已分配内存块（allocated chunk）结构

![](https://github-1251836300.cos.ap-guangzhou.myqcloud.com/%E9%95%BF%E4%BA%AD%E5%85%AC%E5%BC%80%E8%AF%BE/Pwn%E6%9C%AF%E8%BF%9B%E9%98%B6%EF%BC%8C%E7%8E%A9%E8%BD%AC%E5%A0%86%E6%BA%A2%E5%87%BA/QQ%E5%9B%BE%E7%89%8720200502163306.png)

allocated chunk的前两个字段和free chunk相通

第三个字段开始到最后，chunk中存储的都是用户数据。甚至下一个chunk的第一个字段prev_size，也可以被用来存放数据，原因是这个prev_size字段只有当“前一个”chunk是free的时候才有意义，如果“前一个”chunk是已经分配的，堆管理器并不关心

所以对一个chunk来说，用户可用大小从偏移+8开始，一直到下一个chunk的orev_size字段

在64位平台下，chunk的大小一定是0x10字节的整数倍。malloc返回的指针为图中mem指向的位置，即数据开头

## malloc参数与chunk大小的关系

![](https://github-1251836300.cos.ap-guangzhou.myqcloud.com/%E9%95%BF%E4%BA%AD%E5%85%AC%E5%BC%80%E8%AF%BE/Pwn%E6%9C%AF%E8%BF%9B%E9%98%B6%EF%BC%8C%E7%8E%A9%E8%BD%AC%E5%A0%86%E6%BA%A2%E5%87%BA/QQ%E5%9B%BE%E7%89%8720200502223237.png)

- malloc参数为用户申请的内存大小
- chunk包含数据和metadata
- 返回的chunk只要保证其中可用数据大小等于用户申请即可
- 在x86 32位平台下chunk的大小一定是8字节的整数倍；x64平台下，chunk的大小一定是16字节的整数倍

## Bins结构

- BIns是用来管理和组织**空闲**内存块的链表结构，根据chunk的大小和状态，有许多种不同的Bins结构
- Fast bins
  - 用于管理小的chunk
- Bins
  - small bins - 用于管理中等大小的chunk
  - large bins - 用于管理较大的chunk
  - unsorted bins - 用于存放未整理的chunk

## Fast bins

```c
struct malloc_state{
    mutex_t mutex;
    int flags;
    mfastbinptr fastbinsY[NFASTBINS];
    mchunkptr top;
    mchunkptr last_remainder;
    mchunkptr bins[NBINS*2-2];
    /*..*/
}
```

- 大小
  - x86_32平台：16~64字节
  - x64平台：32~128字节
- 相同大小的chunk放在一个bin中
- 单向链表
- 后进先出（FILO，First in last out）
- 相邻的空闲fastbin chunk不会被合并
- 当chunk被free时，不会清理PREV_INUSE标志

## Fast bins在内存中的结构示例

源代码：

```c
#include<stdio.h>
void main(){
    char *a1 = malloc(0x10);
    memset(a1,0x41,0x10);
    char *a2 = malloc(0x10);
    memset(a2,0x42,0x10);
    char *a3 = malloc(0x10);
    memset(a3,0x43,0x10);
    printf("Malloc done!\n");
    free(a1);
    free(a2);
    printf("Free done\n");
    return;
}
```

结果：

- 下断点在`printf("Malloc done!\n");`

![](https://github-1251836300.cos.ap-guangzhou.myqcloud.com/%E9%95%BF%E4%BA%AD%E5%85%AC%E5%BC%80%E8%AF%BE/Pwn%E6%9C%AF%E8%BF%9B%E9%98%B6%EF%BC%8C%E7%8E%A9%E8%BD%AC%E5%A0%86%E6%BA%A2%E5%87%BA/QQ%E5%9B%BE%E7%89%8720200502230606.png)

- 下断点在`printf("Free done\n");`

![](https://github-1251836300.cos.ap-guangzhou.myqcloud.com/%E9%95%BF%E4%BA%AD%E5%85%AC%E5%BC%80%E8%AF%BE/Pwn%E6%9C%AF%E8%BF%9B%E9%98%B6%EF%BC%8C%E7%8E%A9%E8%BD%AC%E5%A0%86%E6%BA%A2%E5%87%BA/QQ%E5%9B%BE%E7%89%8720200502230919.png)

## Small bins

```c
struct malloc_state{
    mutex_t mutex;
    int flags;
    mfastbinptr fastbinsY[NFASTBINS];
    mchunkptr top;
    mchunkptr last_remainder;
    mchunkptr bins[NBINS*2-2];
    /*..*/
}
```

- chunk大小 < 1024 bytes(64bit)
- 相同大小的chunk放在一个bin中
- 双向循环链表
- 先进先出（First in first out）
- 当有空闲块相邻时，chunk会被合并成一个更大的chunk
- bins[2],bins[3],...,bins[124],bins[125]共62组smallbin，大小范围[0x20,0x3f0]（64位）

## Large bins

```c
struct malloc_state{
    mutex_t mutex;
    int flags;
    mfastbinptr fastbinsY[NFASTBINS];
    mchunkptr top;
    mchunkptr last_remainder;
    mchunkptr bins[NBINS*2-2];
    /*..*/
}
```

- chunk大小 >= 1024 bytes(64bit)
- 每组bin表示一组size范围而不是具体的size，例如bins[126],bins[127]的链表中保存长度在[0x400,0x440]的chunk
- 双向循环链表
- 先进先出
-  chunk按照大小从大到小的排序
- 当有空闲块相邻，chunk会被合并
- bins[126],bins[127],...,bins[250],bins[251]共63组largebin，大小范围[0x400,X]（64位）

## Unsorted bin

```c
struct malloc_state{
    mutex_t mutex;
    int flags;
    mfastbinptr fastbinsY[NFASTBINS];
    mchunkptr top;
    mchunkptr last_remainder;
    mchunkptr bins[NBINS*2-2];
    /*..*/
}
```

- 64位平台中：chunk大小>128字节
- 只存在唯一一个unsorted bin
- 双向循环链表
- 当一个chunk（非fastbin）被free，它首先被放入unsorted bin，等后续整理时才会放入对应的small bin/fast bin
- bins[0],bins[1]

## Unsorted bins与small bins

![](https://github-1251836300.cos.ap-guangzhou.myqcloud.com/%E9%95%BF%E4%BA%AD%E5%85%AC%E5%BC%80%E8%AF%BE/%E5%B0%8F%E8%AF%95%E7%89%9B%E5%88%80%EF%BC%8C%E5%AE%9E%E6%88%98ROP%E5%88%A9%E7%94%A8%E6%8A%80%E5%B7%A7/S6.png)

## 其他chunk

- Top chunk
  - 不属于任何bin
  - 在arena中处于最高地址
  - 当没有其他空闲块时，top chunk就会被用于分配
  - 分裂时
    - 一块是请求大小的chunk
    - 另一块余下chunk将成为新的Top chunk
- Last_remainder
  - 当请求small chunk大小的内存时，如发生分裂，则剩余的chunk保存为last_remainder

## malloc的工作流程

1. 如果在size < max fast，在fast bins中寻找fast chunk，如找到则结束
2. 如果size in_smallbin_range，在small bins中寻找small chunk，如找到则结束
3. 如果size not in_smallbin_range，合并所有fastbin的chunk
4. 循环：
   1. 检查unsorted bin中的last_remainder
      - 如果满足一定条件，则分裂之，将剩余的chunk标记为新的last_remainder
   2. 在unsorted bin中搜索，同时进行整理
      - 如遇到精确大小，则返回，否则就把当前chunk整理到small/large bin中去
   3. 在small bin和large bin中搜索最合适的chunk（不一定是精确大小）
5. 使用top chunk

## free的工作流程

1. 如果size < masx fast，放入fast bin，结束
2. 如果前一个chunk是free的
   1. unlink前面的chunk
   2. 合并两个chunk，并放入unsorted bin
3. 如果后一个chunk是top chunk，则将当前chunk并入top chunk
4. 如果后一个chunk是free的
   1. unlink后面的chunk
   2. 合并两个chunk，并放入unsorted bin
5. 前后chunk都不是free的，放入unsorted bin

> 相当于所有的chunk在被free时只有三种去路：放入fastbin、放入unsortbin、并入top chunk

## 案例分析

```c
#include<stdio.h>
int main(){
    char *A,*B,*C,*D;
    A = malloc(0x100 - 8);
    B = malloc(0x100 - 8);
    C = malloc(0x100 - 8);
    D = malloc(0x100 - 8);

    free(A);
    free(C);

    A = malloc(0x100 - 8);
    free(A);
    A = malloc(0x80 - 8);
    free(B)

    return 0;
}
```

分配完malloc之后：

![](https://github-1251836300.cos.ap-guangzhou.myqcloud.com/%E9%95%BF%E4%BA%AD%E5%85%AC%E5%BC%80%E8%AF%BE/%E5%B0%8F%E8%AF%95%E7%89%9B%E5%88%80%EF%BC%8C%E5%AE%9E%E6%88%98ROP%E5%88%A9%E7%94%A8%E6%8A%80%E5%B7%A7/QQ%E5%9B%BE%E7%89%8720200503114458.png)

执行free之后：



再次执行`A = malloc(0x100 - 8)`：

![](https://github-1251836300.cos.ap-guangzhou.myqcloud.com/%E9%95%BF%E4%BA%AD%E5%85%AC%E5%BC%80%E8%AF%BE/%E5%B0%8F%E8%AF%95%E7%89%9B%E5%88%80%EF%BC%8C%E5%AE%9E%E6%88%98ROP%E5%88%A9%E7%94%A8%E6%8A%80%E5%B7%A7/QQ%E5%9B%BE%E7%89%8720200503114752.png)

再次`free(A)`：

![](https://github-1251836300.cos.ap-guangzhou.myqcloud.com/%E9%95%BF%E4%BA%AD%E5%85%AC%E5%BC%80%E8%AF%BE/%E5%B0%8F%E8%AF%95%E7%89%9B%E5%88%80%EF%BC%8C%E5%AE%9E%E6%88%98ROP%E5%88%A9%E7%94%A8%E6%8A%80%E5%B7%A7/QQ%E5%9B%BE%E7%89%8720200503114907.png)

再次`A = malloc(0x80 - 8)`：

![](https://github-1251836300.cos.ap-guangzhou.myqcloud.com/%E9%95%BF%E4%BA%AD%E5%85%AC%E5%BC%80%E8%AF%BE/%E5%B0%8F%E8%AF%95%E7%89%9B%E5%88%80%EF%BC%8C%E5%AE%9E%E6%88%98ROP%E5%88%A9%E7%94%A8%E6%8A%80%E5%B7%A7/QQ%E5%9B%BE%E7%89%8720200503115030.png)

![](https://github-1251836300.cos.ap-guangzhou.myqcloud.com/%E9%95%BF%E4%BA%AD%E5%85%AC%E5%BC%80%E8%AF%BE/%E5%B0%8F%E8%AF%95%E7%89%9B%E5%88%80%EF%BC%8C%E5%AE%9E%E6%88%98ROP%E5%88%A9%E7%94%A8%E6%8A%80%E5%B7%A7/QQ%E5%9B%BE%E7%89%8720200503115156.png)

![](https://github-1251836300.cos.ap-guangzhou.myqcloud.com/%E9%95%BF%E4%BA%AD%E5%85%AC%E5%BC%80%E8%AF%BE/%E5%B0%8F%E8%AF%95%E7%89%9B%E5%88%80%EF%BC%8C%E5%AE%9E%E6%88%98ROP%E5%88%A9%E7%94%A8%E6%8A%80%E5%B7%A7/QQ%E5%9B%BE%E7%89%8720200503115251.png)

执行`free(B)`后：

![](C:\Users\syc\Desktop\QQ图片20200503115440.png)

