# 转载Linux逆向之调试&反调试

转载自：https://xz.aliyun.com/t/6882

## 调试器的实现原理

要想进行调试，调试器是必不可少的，首先需要了解一下我们常用的Linux下的调试器如GDB，是如何实现的

GDB 基于ptrace编写而成的调试器，ptrace是一个Linux提供的用于调试的系统调用

函数原型如下

```
NAME 
    ptrace - process trace
SYNOPSIS
       #include <sys/ptrace.h>
       long ptrace(enum __ptrace_request request, pid_t pid,
                   void *addr, void *data);
```

简单来说， **ptrace系统调用提供了一种方法来让父进程可以观察和控制其它进程的执行，检查和改变其核心映像以及寄存器。 主要用来实现断点调试和系统调用跟踪**

这个函数根据 request 参数来表示想要请求执行的行为 ，并且根据不同的request决定后续的pid、addr、data参数是否有意义。

下面是几个常见的 request 参数的可选项：

- PTRACE_TRACEME ：表示本进程将被其父进程跟踪，此时剩下的pid、addr、data参数都没有实际意义可以全部为0

  这个选项只能用在被调试的进程中，也是被调试的子进程唯一能用的request选项，其他的都只能用父进程调试器使用

- PTRACE_ATTACH：attach到一个指定的进程，使其成为当前进程跟踪的子进程，而子进程的行为等同于它进行了一次PTRACE_TRACEME操作，可想而知，gdb的attach命令使用这个参数选项实现的

  ~~变成其他进程的爹，你就可以调试它~~

- PTRACE_CONT：继续运行之前停止的子进程，也可以向子进程发送指定的信号，这个其实就相当于gdb中的continue命令

除了上面的几个，还有很多操作子进程内存数据寄存器数据的request选项，详见man手册，这里不一一展开，

[![img](https://xzfile.aliyuncs.com/media/upload/picture/20191201144906-ab752400-1406-1.png)](https://xzfile.aliyuncs.com/media/upload/picture/20191201144906-ab752400-1406-1.png)

如上图所示，gdb调试的本质实际上就是父进程使用ptrace函数对子进程进行一系列的命令操作

这里举一个例子

```
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/reg.h>   /* For constants ORIG_EAX etc */
#include <sys/user.h>
#include <sys/syscall.h> /* SYS_write */
#include <stdio.h>
int main() {
    pid_t child;
    long orig_rax;
    int status;
    int iscalling = 0;
    struct user_regs_struct regs;

    child = fork();
    if(child == 0) 
    {
        ptrace(PTRACE_TRACEME, 0, 0);//发送信号给父进程表示已做好准备被调试
        execl("/bin/ls", "ls", "-l", "-h", 0);
    }
    else
    {
        while(1)
        {
            wait(&status);//等待子进程发来信号或者子进程退出
            if(WIFEXITED(status))
            //WIFEXITED函数(宏)用来检查子进程是被ptrace暂停的还是准备退出
            {
                break;
            }
            orig_rax = ptrace(PTRACE_PEEKUSER, child, 8 * ORIG_RAX, 0);
            //获取rax值从而判断将要执行的系统调用号
            if(orig_rax == SYS_write)
            {//如果系统调用是write
                ptrace(PTRACE_GETREGS, child, 0, &regs);
                if(!iscalling)
                {
                    iscalling = 1;
                    //打印出系统调用write的各个参数内容
                    printf("SYS_write call with %p, %p, %p\n",
                            regs.rdi, regs.rsi, regs.rdx);
                }
                else
                {
                    printf("SYS_write call return %p\n", regs.rax);
                    iscalling = 0;
                }
            }

            ptrace(PTRACE_SYSCALL, child, 0, 0);
            //PTRACE_SYSCALL,其作用是使内核在子进程进入和退出系统调用时都将其暂停
            //得到处于本次调用之后下次调用之前的状态
        }
    }
    return 0;
}
```

编译运行后，会输出如下

```
$ gcc ./ptrace1.c -o ptrace1 && ./ptrace1 
SYS_write call with 0x1, 0x9e1020, 0xf
总用量 940K
SYS_write call return 0xf
SYS_write call with 0x1, 0x9e1020, 0x35
-rwxrwxr-x 1 zeref zeref 8.7K 11月 16 03:10 ptrace1
SYS_write call return 0x35
SYS_write call with 0x1, 0x9e1020, 0x37
-rw-rw-r-- 1 zeref zeref  601 11月 16 03:10 ptrace1.c
SYS_write call return 0x37
SYS_write call with 0x1, 0x9e1020, 0x35
-rwxrwxr-x 1 zeref zeref 8.7K 11月 16 03:16 ptrace2
SYS_write call return 0x35
SYS_write call with 0x1, 0x9e1020, 0x37
-rw-rw-r-- 1 zeref zeref 1.3K 11月 16 03:16 ptrace2.c
SYS_write call return 0x37
SYS_write call with 0x1, 0x9e1020, 0x32
-rwxrwxr-x 1 zeref zeref 892K 11月 15 22:57 test
SYS_write call return 0x32
SYS_write call with 0x1, 0x9e1020, 0x33
-rwxrwxr-x 1 zeref zeref 8.4K 11月 15 22:51 test1
SYS_write call return 0x33
SYS_write call with 0x1, 0x9e1020, 0x35
-rw-rw-r-- 1 zeref zeref  174 11月 15 22:51 test1.c
SYS_write call return 0x35
```

可以看到，每一次进行系统调用前以及调用后的寄存器内容都发生的变化，并且输出了`ls -l -h`的内容

这只是ptrace的部分功能，ptrace能做到的事情还有更多，比如还能修改内存，修改寄存器的值，插入字节码实现下断点的功能，这里仅仅简单介绍一下gdb调试器的大概实现原理

如果对编写调试器感兴趣的话，可以康康这个大佬的博客： [veritas501](https://veritas501.space/2017/10/16/翻译_编写一个Linux调试器/)

## 反调试

介绍完调试的原理，就需要思考下一个问题，如果防止别人调试我们写好的程序？

最简单的办法如下

```
#include <sys/ptrace.h>
#include <stdio.h>
int main()
{
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) ==-1 )
    {
        printf("don't trace me:(\n");
        return 1;
    }
    printf("no one trace me:)\n");
    return 0;
}
```

根据前面说的，只要能当其他进程的爹，就能调试他，但ptrace有个规定是，每个进程只能被`PTRACE_TRACEME`一次，因此只要程序的开头就先执行一次`ptrace(PTRACE_TRACEME, 0, 0, 0)`，当gdb再想attach的时候就会发现已经执行了一次不能再执行了从而返回-1

~~这大概就是我先当了我自己的爹，别人就不能当我爹吧~~

运行情况如下

```
$ ./anti1 
no one trace me:)
----
$ gdb ./anti1
$pwndbg> r
Starting program: /home/zeref/桌面/debug&anti/anti1 
don't trace me:(
[Inferior 1 (process 21216) exited with code 01]
```

那如果遇到这种反调试该如何绕过呢？

一般有以下几种操作：

1. 打patch，把有关ptrace函数的部分nop掉

2. 利用hook技术，把ptrace函数给替换成自定义的ptrace函数，从而可以任意指定它的返回值

3. 充分利用gdb的catch命令，`catch syscall ptrace`会在发生ptrace调用的时候停下，因此在第二次停住的时候`set $rax=0`，从而绕过程序中`ptrace(PTRACE_TRACEME, 0, 0, 0) ==-1`的判断

   效果如下

   ```
   $ gdb ./anti1
    $pwndbg> catch syscall ptrace
    Catchpoint 1 (syscall 'ptrace' [101])
    $pwndbg> r
    Starting program: /home/zeref/桌面/debug&anti/anti1 
    Catchpoint 1 (call to syscall ptrace), 0x00007ffff7b0ae2e in ptrace (request=PTRACE_TRACEME) at ../sysdeps/unix/sysv/linux/ptrace.c:45
   
    $pwndbg> c
    Continuing.
   
    Catchpoint 1 (returned from syscall ptrace), 0x00007ffff7b0ae2e in ptrace (request=PTRACE_TRACEME) at ../sysdeps/unix/sysv/linux/ptrace.c:45
   
    在连续si到即将执行ret时
    $pwndbg> set $rax=0
    $pwndbg> c
    Continuing.
    no one trace me:)
    [Inferior 1 (process 21279) exited normally]
   ```

**那么问题又来了，如何防止我们的程序被这种骚操作绕过反调试呢？**

分析一下上面的绕过方法，发现本质上都是为了使得`ptrace(PTRACE_TRACEME, 0, 0, 0)`无效，因为使之无效化又不影响主程序的逻辑，那便可以完美绕过

所以这里一种方法是这样，想办法生成一个子进程，并且ptrace跟踪它，并且使他与父进程的运行逻辑密不可分，这样一来单纯的干掉一个ptrace函数调用就不能绕过反调试

比如，可以通过自己定义syscall的方式来实现父子进程之间的身份认证，确保子进程是与父进程在通讯，而不是与gdb在通讯

例子如下

```
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/user.h>
#define SYS_CALL_myread 12345
#define SYS_CALL_mywrite 67890


void myread(char *str,int len)
{
    syscall(SYS_CALL_myread, str,len,0);
}
void mywrite(char *str)
{
    syscall(SYS_CALL_mywrite, str,strlen(str),1);
}

void tracee() 
{
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    raise(SIGCONT);//向自身发送SIGCONT信号，表示继续执行
    char *str1="what is your name?\n";
    static char name[0x10];
    char *ptr_name=name;
    mywrite(str1);
    myread(ptr_name,0x10);

    puts("welcome!");
    mywrite(ptr_name);

}

void tracer(pid_t child_pid)
{
    int status;
    struct user_regs_struct regs;

    waitpid(child_pid, &status, 0);
    //如果子进程的ptrace被patch掉，则无法接收到status
    if (!WIFSTOPPED(status))
    {//宏用来指出子进程是正常退出的，返回一个非零值
        printf("gg\n");
        exit(1);
    }
    ptrace(PTRACE_SETOPTIONS, child_pid, 0, PTRACE_O_EXITKILL);
    //如果子进程处于退出状态则发送一个SIGKILL信号给它

    while (WIFSTOPPED(status))
    {
        ptrace(PTRACE_SYSCALL, child_pid, 0, 0);//在子进程进程syscall之前断下
        waitpid(child_pid, &status, 0);
        ptrace(PTRACE_GETREGS, child_pid, 0, &regs);//获取寄存器值

        if (regs.orig_rax == SYS_CALL_mywrite)
        {
            //str,strlen(str),1
            regs.orig_rax = SYS_write;
            unsigned long long int tmp = regs.rdx;
            regs.rdx = regs.rsi;
            regs.rsi = regs.rdi;
            regs.rdi=tmp;

            ptrace(PTRACE_SETREGS, child_pid, 0, &regs);
            //设置寄存器值，使其改为正确的syscall
        }
        if (regs.orig_rax == SYS_CALL_myread)
        {
            //str,strlen(str),0
            regs.orig_rax = SYS_read;
            unsigned long long int tmp = regs.rdx;
            regs.rdx = regs.rsi;
            regs.rsi = regs.rdi;
            regs.rdi=tmp;
            ptrace(PTRACE_SETREGS, child_pid, 0, &regs);
        }

        ptrace(PTRACE_SYSCALL, child_pid, 0, 0);
        waitpid(child_pid, &status, 0);
    }
}

int main() 
{
    pid_t child_pid = fork();
    if (child_pid < 0) 
    {
        printf("gg\n");
        exit(1);
    }
    if (child_pid == 0) 
    {
        tracee();
    } 
    else
    {
        tracer(child_pid);
    }
    return 0;
}
```

这种方法可以在一定程度上加大反调试力度，但其实还是有办法应对的，可以通过逆向发现父子进程直接的互动无非就是syscall的系统调用号和参数的转换，那只要逆的明明白白，仍然可以强行打patch，把myread，mywrite又改回正常的read，write就可以绕过反调试了

**所以又该怎么样继续加大反调试的力度呢？**

可以考虑如下操作

1. 加大力度，定义更多的syscal来代替libc函数，增大逆向难度
2. 不仅仅单纯的替换系统调用号和参数，可以加入数据的交互，比如通过管道通信添加加密与解密的操作
3. 给程序加很多花里胡哨的混淆，增加理解程序逻辑难度
4. ......

**这大概就是攻击与防御的乐趣吧，如果哪位大佬还有更骚操作和想法请务必评论区分享一波**

### 其他小技巧

上面是专门针对ptrace进行的反调试与绕过反调试的分析，下面还有几种比较偏门的反调试措施，但是这些措施都比较容易绕过，通过打patch基本上都可以绕过，这里就简单介绍一下

**1.检测/proc/self/status**

检查 `/proc/self/status` 中的 `TracerPID` - 正常运行时为0，在有debugger挂载的情况下变为debugger的PID。因此通过不断读取这个值可以发现是否存在调试器，进行对应处理

例子如下

```
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <string.h>

void test()
{
    FILE *fp;
    int TracerPid=0;
    fp=fopen("/proc/self/status","r");
    // printf("%p\n",fp);
    static char buf[0x100];
    char *ptr=&buf;
    while(fgets(ptr, 0x100, fp))
    {
        if (strstr(ptr,"TracerPid"))
        {   
            char tmp[0x10];
            int len=strlen(ptr);
            TracerPid=atoi((char *)ptr+len-3);
            if (TracerPid != 0)
            {
                puts("don't debug me!");
            }

        }
    }
}

int main(int argc, char const *argv[])
{
    while(1)
    {
        test();
        sleep(1);
    }
}
```

类似的操作还有扫描整个虚拟地址空间，在text段查找被修改的字节码，如当调试器下断点的时候实际上会插入int3的字节码，从而达到断下的目的，如果扫描到这些特征字节码（如0xcc等等）就马上停止程序，从而达到反调试的作用，同样的比较容易被绕过，这里就只提供一种思路，不再举具体例子

**2.检测/proc/self/cmdline**

这种操作本质上就是在检测输入的命令内容，如果输入执行`gdb ./xx`或者`strace ./xx`就会被检测到

总体还是还是比较鸡肋的，如果先进gdb在attach pid的话就检测不到。。。

```
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) 
{
   char buf1[0x20], buf2[0x100];
   FILE* fp;

   snprintf(buf1, 24, "/proc/%d/cmdline", getppid());
   fp = fopen(buf1, "r");
   fgets(buf2, 0x100, fp);
   fclose(fp);

   if(!strcmp(buf2, "gdb") || !strcmp(buf2, "strace")||!strcmp(buf2, "ltrace"))
   {
       printf("Debugger detected");
       return 1;
   }  
   printf("All good");
   return 0;
}
```

**3.忽略int3异常信号**

调试中最常见的操作便是下断点，而一般的下断点的方法就是在即将执行的指令前插入int3的字节码 (CC) ，在程序执行到int3时，就会触发 SIGTRAP 信号，而调试器就会接收到这些信号进行并对子进程进行处理，而如果子进程通过设置signal函数忽略SIGTRAP  信号，就可以使得断点无效，也就能达到反调试的作用

但是这个操作似乎只适用于反调试远古时期的gdb，现在的最新版本gdb基本上都防不住，仅提供一种思路

**4.设置时间间隔**

在程序启动时，通过alarm设置定时，到达时则中止程序 ，这样就不能长时间调试程序

```
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
void alarmHandler(int sig)
{
   printf("don' t debug me");
   exit(1);
}
void__attribute__((constructor))setupSig(void) 
{//设置程序一开始就执行
   signal(SIGALRM, alarmHandler);
   alarm(3);
}
int main(int argc, char *argv[]) 
{
   getchar();
   puts("hello!");
   puts("hello!");
   puts("hello!");
   return 0;
}
```

当然还是比较容易绕过，方法很多很多

## 参考链接

https://blog.toby.moe/linux-anti-debugging/

http://www.voidcn.com/article/p-hogkwhfh-ys.html

https://blog.csdn.net/stonesharp/article/details/8211526

http://drops.xmd5.com/static/drops/mobile-16969.html