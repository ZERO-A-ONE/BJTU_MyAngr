# 北极星杯网络网络攻防赛之PWN1

先检查一些程序

```c
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

获取的信息有：

- 64位程序
- 堆栈不可执行
- 没有地址随机化
- 有二进制程序且也有lib.so 意味着可以泄露地址

通过IDA Pro反汇编一下主代码

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  FILE *v3; // rdi
  char buf[8]; // [rsp+0h] [rbp-20h]
  __int64 v6; // [rsp+10h] [rbp-10h]
  __int64 v7; // [rsp+18h] [rbp-8h]

  strcpy(buf, "ret2dl?\n");
  v6 = 0LL;
  v7 = 0LL;
  v3 = stdout;
  setbuf(stdout, buf);
  vuln(v3, buf);
  return 0;
}
```

```c
ssize_t vuln()
{
  char buf; // [rsp+0h] [rbp-20h]

  setbuf(stdin, &buf);
  return read(0, &buf, 0x100uLL);
}
```

从题目中可以发现**ret2_dl**的提示，就提示了这题是**ret2_dl_runtime_resolve**类型的题目，然后我们发现**vuln()**函数内是存在着栈溢出漏洞的，栈溢出的长度应该是**0x20+0x8 = 0x28**

这题存在两种解法，因为服务器上提供了**libc**库那我们就可以直接泄露地址就是很容易的一道题，假设没有**libc**库，我们就得利用**ret2_dl_runtime_resolve**的思路进行解题

## 使用libc的方法



## ret2_dl的做法