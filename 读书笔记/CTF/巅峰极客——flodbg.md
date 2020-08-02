# 巅峰极客——flodbg

检查一下程序

```c
syc@ubuntu:/mnt/hgfs/share/巅峰极客/flodbg$ checksec flodbg
[*] '/mnt/hgfs/share/\xe5\xb7\x85\xe5\xb3\xb0\xe6\x9e\x81\xe5\xae\xa2/flodbg/flodbg'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    FORTIFY:  Enabled
```

拿到程序发现运行发现一直没有结果

```shell
syc@ubuntu:/mnt/hgfs/share/巅峰极客/flodbg$ ./flodbg

```

 直接IDA Pro打开分析一下函数流程

```cc
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char *v3; // rbx
  int v4; // er12
  int v5; // edi
  signed int v6; // ebx
  signed __int64 v7; // [rsp-8h] [rbp-4E0h]
  __int64 v8; // [rsp-8h] [rbp-4E0h]
  __int64 v9; // [rsp+0h] [rbp-4D8h]
  char v10; // [rsp+14h] [rbp-4C4h]
  char v11; // [rsp+4Ch] [rbp-48Ch]
  int v12; // [rsp+50h] [rbp-488h]
  int v13; // [rsp+54h] [rbp-484h]
  int v14; // [rsp+58h] [rbp-480h]
  int v15; // [rsp+5Ch] [rbp-47Ch]
  int v16; // [rsp+60h] [rbp-478h]
  int v17; // [rsp+64h] [rbp-474h]
  int v18; // [rsp+68h] [rbp-470h]
  int v19; // [rsp+6Ch] [rbp-46Ch]
  int v20; // [rsp+70h] [rbp-468h]
  int v21; // [rsp+74h] [rbp-464h]
  int v22; // [rsp+78h] [rbp-460h]
  int v23; // [rsp+7Ch] [rbp-45Ch]
  int v24; // [rsp+80h] [rbp-458h]
  int v25; // [rsp+84h] [rbp-454h]
  int v26; // [rsp+88h] [rbp-450h]
  int v27; // [rsp+8Ch] [rbp-44Ch]
  int v28; // [rsp+90h] [rbp-448h]
  int v29; // [rsp+94h] [rbp-444h]
  int v30; // [rsp+98h] [rbp-440h]
  unsigned __int64 v31; // [rsp+4A8h] [rbp-30h]

  v3 = (char *)&v9;
  v31 = __readfsqword(0x28u);
  v4 = time(0LL);
  do
  {
    v3 += 4;
    *((_DWORD *)v3 - 1) = _IO_getc(_bss_start);
  }
  while ( v3 != &v11 );
  v12 = 'S';
  v13 = '@';
  v14 = 'y';
  v15 = 'R';
  v16 = 't';
  v17 = 'f';
  v18 = 'T';
  v19 = 'l';
  v20 = '0';
  v21 = '+';
  v22 = 'a';
  v23 = 'g';
  v24 = '-';
  v25 = 'L';
  v26 = '_';
  v27 = '3';
  v28 = 'M';
  v29 = '}';
  v30 = '{';
  if ( ptrace(0, 0LL, 1LL, 0LL) >= 0 )
  {
    v5 = (unsigned __int64)time(0LL) - v4;
    if ( v5 <= 1 )
    {
      func3(&v10, 2LL, 7LL, 14LL);
      v7 = 4196782LL;
      JUMPOUT(__CS__, v8 + 10);
    }
    exit(v5);
  }
  v6 = 10000000;
  do
  {
    sleep(1u);
    --v6;
  }
  while ( v6 );
  exit(-1);
}
```

让我们长期等待无响应的代码是因为这段

```c
v6 = 10000000;
  do
  {
    sleep(1u);
    --v6;
  }
  while ( v6 );
```

然后注意到这里有一个**ptrace**函数，且调用的是**ptrace**函数，所以这个程序是加入了反调试的功能的。 **ptrace**函数提供了父进程观察和控制其子进程执行的能力，发送给被跟踪的子进程的信号(除了**SIGKILL**)，都会被转发给父进程，这也是调试器主要原理。 总而言之就是如果我们使用GDB调试这个程序，**ptrace**函数执行成功就会返回大于0的值，那么程序就会中止

这里还存在一个反调试方式就是时间戳的检查

```cc
v4 = time(0LL);
v5 = (unsigned __int64)time(0LL) - v4;
```

被调试时，进程的运行速度大大降低，例如，单步调试大幅降低恶意代码的运行速度，所以时钟检测是恶意代码探测调试器存在的最常用方式之一。有如下两种用时钟检测来探测调试器存在的方法。记录一段操作前后的时间戳，然后比较这两个时间戳，如果存在滞后，则可以认为存在调试器。记录触发一个异常前后的时间戳。如果不调试进程，可以很快处理完异常，因为调试器处理异常的速度非常慢。默认情况下，调试器处理异常时需要人为干预，这导致大量延迟。虽然很多调试器允许我们忽略异常，将异常直接返回程序，但这样操作仍然存在不小的延迟

然后我们看这段代码使用了花指令来混淆

```cc
JUMPOUT(__CS__, v8 + 10);
```

```c
.text:00000000004009C4                 dd 48EBEBEBh
.text:00000000004009C8                 dq 11B908247C8Dh, 4BE00000006BA00h, 440E8000000h, 0EBB866C8FFC0FFEBh
.text:00000000004009C8                 dq 0EB90EBFA74C03105h, 0FFC0FFEBC8FFC0FFh, 8D48C8FFC0FFEBC8h
.text:00000000004009C8                 dq 0AB924247Ch, 3BE00000005BAh, 0E800000409E80000h, 24B48D48FFFFFE04h
.text:00000000004009C8                 dq 75E8C789000000A0h, 0FC589C085000004h, 5C8D480000020B85h
.text:00000000004009C8                 dq 0BA0000000FB92C24h, 6BE00000009h, 3CFE8E7894800h, 6BA00000008B900h
.text:00000000004009C8                 dq 3BE000000h, 3B8E8DF8948h, 89FFFFFD71E8FF31h, 0F02FF83E72944C7h
.text:00000000004009C8                 dq 0EB9000001D48Fh, 0BE00000005BA0000h, 0E8EF894C00000001h
.text:00000000004009C8                 dq 0FFFCF7E80000038Ch, 0FFFFFD10E8C789FFh, 0FFFFFD78E8C58941h
.text:00000000004009C8                 dq 1AA850FC53941h, 13B9F63100h, 0E7894800000002BAh, 356E840246C8D4Ch
.text:00000000004009C8                 dq 0C03105EBB8660000h, 0FFC0FFEB90EBFA74h, 0C03105EBB86690C8h
.text:00000000004009C8                 dq 0C8FFC0FFEBEBFA74h, 10B90C247C8D48h, 0BE00000005BA0000h
.text:00000000004009C8                 dq 31FE800000003h, 4B93C247C8D4800h, 3BA000000h, 306E800000001BEh
.text:00000000004009C8                 dq 0C8FFC0FFEB900000h, 0C03105EBB8669090h, 5EBB86690EBFA74h
.text:00000000004009C8                 dq 909090EBFA74C031h, 0BB920247C8D48h, 0BE00000006BA0000h
.text:00000000004009C8                 dq 2CFE800000003h, 13B9F63100h, 0E7894800000007BAh, 0E89090000002BBE8h
.text:00000000004009C8                 dq 0C083485800000000h, 0EBEBEBEBEBE0FF0Ch, 74C03105EBB86690h
.text:00000000004009C8                 dq 3B9F63190EBFAh, 4C00000002BA0000h, 4800000289E8EF89h
.text:00000000004009C8                 dq 9B9F63128247C8Dh, 2BA000000h, 0E8FF3100000273E8h, 2944C789FFFFFC2Ch
.text:00000000004009C8                 dq 8F8F0F03FF83E7h, 8B9DF89480000h, 0BE00000003BA0000h
.text:00000000004009C8                 dq 45E8DB3100000001h, 3B9000002h, 4CF63100000002BAh, 0B800000231E8EF89h
.text:00000000004009C8                 dq 2E660EEB00000053h, 841F0Fh, 759C043B509C448Bh, 0FB834801C383483Chc
.text:00000000004009C8                 dq 400FFDBFED7513h, 948B48FFFFFB63E8h, 334864000004A824h
.text:00000000004009C8                 dq 0E889000000282514h, 4B8C481482475h, 0C35D415C415D5B00h
.text:00000000004009C8                 dq 0FF2BFD8EBFFCD83h, 89FFFFFB31E80040h
.text:0000000000400C50                 db 0DFh
```

我们绕过这些反调试的手法可以直接path掉或者在动态调试的时候通过直接修改寄存器绕过即可，我们首先来通过path修改绕过**ptrace**函数

```c
.text:000000000040096A                 call    _ptrace
```

变成

```cc
.text:000000000040096A                 nop                     ; Keypatch modified this from:
.text:000000000040096A                                         ;   call _ptrace
.text:000000000040096A                                         ; Keypatch padded NOP to next boundary: 4 bytes
.text:000000000040096B                 nop
.text:000000000040096C                 nop
.text:000000000040096D                 nop
.text:000000000040096E                 nop
```

在gdb动态调试中可以发现已经成功绕过

```cc
────────────────────────────────────────[ DISASM ]────────────────────────────────────────
   0x400933 <main+211>    mov    dword ptr [rsp + 0x88], 0x5f
   0x40093e <main+222>    mov    dword ptr [rsp + 0x8c], 0x33
   0x400949 <main+233>    mov    dword ptr [rsp + 0x90], 0x4d
   0x400954 <main+244>    mov    dword ptr [rsp + 0x94], 0x7d
   0x40095f <main+255>    mov    dword ptr [rsp + 0x98], 0x7b
 ► 0x40096a <main+266>    nop    
   0x40096b <main+267>    nop    
   0x40096c <main+268>    nop    
   0x40096d <main+269>    nop    
   0x40096e <main+270>    nop    
   0x40096f <main+271>    test   rax, rax
```

在这里我们遇到了时间戳检测

```cc
────────────────────────────────────────[ DISASM ]────────────────────────────────────────
   0x400972 <main+274>     js     main+1036 <0x400c6c>
 
   0x400978 <main+280>     xor    edi, edi
   0x40097a <main+282>     call   time@plt <0x4007e0>
 
   0x40097f <main+287>     mov    edi, eax
   0x400981 <main+289>     sub    edi, r12d
 ► 0x400984 <main+292>     cmp    edi, 1
   0x400987 <main+295>     jg     main+1009 <0x400c51>
```

我们只需要强制修改edi寄存器的值为1即可以绕过

```cc
pwndbg> set $edi = 1
```

就已经绕过了

```cc
────────────────────────────────────────[ DISASM ]────────────────────────────────────────
   0x40097a <main+282>    call   time@plt <0x4007e0>
 
   0x40097f <main+287>    mov    edi, eax
   0x400981 <main+289>    sub    edi, r12d
   0x400984 <main+292>    cmp    edi, 1
   0x400987 <main+295>    jg     main+1009 <0x400c51>
 
 ► 0x40098d <main+301>    lea    r13, [rsp + 0x14]
```

运行到这里

```cc
────────────────────────────────────────[ DISASM ]────────────────────────────────────────
   0x4009a1 <main+321>    mov    rdi, r13
   0x4009a4 <main+324>    call   func3 <0x400e20>
 
   0x4009a9 <main+329>    call   main+334 <0x4009ae>
 
   0x4009ae <main+334>    pop    rax
   0x4009af <main+335>    add    rax, 0xa
 ► 0x4009b3 <main+339>    jmp    rax <0x4009b8>
    ↓
   0x4009b8 <main+344>    call   main+349 <0x4009bd>
```

可以发现其实**0x4009b3**是**jump**到了**0x4009b8**处，我们在**IDA**里面修改即可

```
.text:00000000004009B3                 jmp     short loc_4009B8 ; Keypatch modified this from:
.text:00000000004009B3                                         ;   jmp rax
```

在这之前我们可以选定被花指令隐藏的数据按**U**或者右键选择“**Undefine**"先还原成数据，然后之后可以按”**C**“或者右键”**Code**“变成指令代码

继续运行

```
   0x4009bd <main+349>    pop    rbx
   0x4009be <main+350>    add    rbx, 0xa
 ► 0x4009c2 <main+354>    jmp    rbx <0x4009c7>
    ↓
   0x4009c7 <main+359>    lea    rdi, [rsp + 8]
```

**0x4009c2**到**0x4009c7**，其实这时候我们分析一下这些花指令，本质上就是跳转到**rbx+0xa**的内存上

```cc
0x4009bd <main+349>    pop    rbx
0x4009be <main+350>    add    rbx, 0xa
0x4009c2 <main+354>    jmp    rbx
```

再看一下这段，加加减减等于没有，然后异或同一个寄存器一定会跳转

```cc
   0x4009e1 <main+385>    inc    eax
   0x4009e3 <main+387>    dec    eax
   0x4009e5 <main+389>    mov    ax, 0x5eb
 ► 0x4009e9 <main+393>    xor    eax, eax
   0x4009eb <main+395>    je     main+391 <0x4009e7>
```

最终逆向完毕的版本

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int *v3; // rbx
  int v4; // er12
  unsigned int v5; // eax
  signed int v6; // ebp
  int v7; // edi
  __pid_t v8; // eax
  __pid_t v9; // er13
  __int64 correct_count; // rbx
  int i; // eax
  int result; // eax
  int input[19]; // [rsp+0h] [rbp-4D8h]
  char v14; // [rsp+4Ch] [rbp-48Ch]
  int enc[19]; // [rsp+50h] [rbp-488h]
  char v16; // [rsp+A0h] [rbp-438h]
  unsigned __int64 v17; // [rsp+4A8h] [rbp-30h]

  v3 = input;
  v17 = __readfsqword(0x28u);
  v4 = time(0LL);
  do
  {
    ++v3;
    *(v3 - 1) = _IO_getc(_bss_start);
  }
  while ( v3 != (int *)&v14 );
  enc[0] = 'S';
  enc[1] = '@';
  enc[2] = 'y';
  enc[3] = 'R';
  enc[4] = 't';
  enc[5] = 'f';
  enc[6] = 'T';
  enc[7] = 'l';
  enc[8] = '0';
  enc[9] = '+';
  enc[10] = 'a';
  enc[11] = 'g';
  enc[12] = '-';
  enc[13] = 'L';
  enc[14] = '_';
  enc[15] = '3';
  enc[16] = 'M';
  enc[17] = '}';
  enc[18] = '{';
  func3(&input[5], 2u, 7, 0xEu);
  func3(&input[2], 4u, 6, 0x11u);
  func3(&input[9], 3u, 5, 0xAu);
  v5 = getppid();
  v6 = get_name_by_pid(v5, &v16);
  if ( !v6 )
  {
    func3(input, 6u, 9, 0xFu);
    func3(&input[11], 3u, 6, 8u);
    v7 = (unsigned __int64)time(0LL) - v4;
    if ( v7 < 2 )
      goto LABEL_16;
    func3(&input[5], 1u, 5, 0xEu);
    v8 = getpid();
    v9 = getsid(v8);
    if ( v9 != getppid() )
    {
      func3(input, 0, 2, 0x13u);
      func3(&input[3], 3u, 5, 0x10u);
      func3(&input[15], 1u, 3, 4u);
      func3(&input[8], 3u, 6, 0xBu);
      func3(input, 0, 7, 0x13u);
      func3(&input[16], 0, 2, 3u);
      func3(&input[10], 0, 2, 9u);
      v7 = (unsigned __int64)time(0LL) - v4;
      if ( v7 >= 3 )
      {
        correct_count = 0LL;
        func3(&input[11], 1u, 3, 8u);
        func3(&input[16], 0, 2, 3u);
        for ( i = 'S'; i == input[correct_count]; i = enc[correct_count] )
        {
          if ( ++correct_count == 19 )
          {
            puts("win");
            goto LABEL_12;
          }
        }
        puts("You failed");
        v7 = correct_count;
      }
LABEL_16:
      exit(v7);
    }
LABEL_17:
    puts("what are you doing?!");
    v7 = 1;
    goto LABEL_16;
  }
  v6 = -1;
LABEL_12:
  result = v6;
  if ( __readfsqword(0x28u) != v17 )
    goto LABEL_17;c
  return result;
}
```

 输入字符串“0123456789abcdefghi”，然后在比较处设断点，可以看到输入字符串经过处理后的结果是“8f6c90e1dg237abh5i4”。
然后即可写脚本，把“S@yRtfTl0+ag-L_3M}{”进行还原。

```python
str = "0123456789abcdefghi"
str1 = "8f6c90e1dg237abh5i4"
str2 = "S@yRtfTl0+ag-L_3M}{"
flag = ""
for i in range(len(str2)):
flag += str2[str1.find(str[i])]
print flag
```

 得到flag为flag{My-StL_R0T@+3} 

[题目地址]: https://github-1251836300.cos.ap-guangzhou.myqcloud.com/CTF%E2%80%94%E2%80%94WriteUP/%E5%B7%85%E5%B3%B0%E6%9E%81%E5%AE%A2/flodbg/flodbg.zip
[最终IDA文件]: https://github-1251836300.cos.ap-guangzhou.myqcloud.com/CTF%E2%80%94%E2%80%94WriteUP/%E5%B7%85%E5%B3%B0%E6%9E%81%E5%AE%A2/flodbg/flodbg.i64

