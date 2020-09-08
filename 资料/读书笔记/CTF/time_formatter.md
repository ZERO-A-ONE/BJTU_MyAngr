#  time_formatter 

首先检查一下程序

```cc
syc@ubuntu:~/Downloads/tmp$ checksec time_formatter
[*] '/home/syc/Downloads/tmp/time_formatter'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    FORTIFY:  Enabled
```

可以知道是64位程序，且开启了栈不可执行等一系列保护

运行一下，感觉像是一个堆题

```c
syc@ubuntu:~/Downloads/tmp$ ./time_formatter
Welcome to Mary's Unix Time Formatter!
1) Set a time format.
2) Set a time.
3) Set a time zone.
4) Print your time.
5) Exit.
> 
```

开启IDA Pro阅读代码

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  __gid_t v3; // eax
  FILE *v4; // rdi
  int v5; // eax

  v3 = getegid();
  setresgid(v3, v3, v3);
  setbuf(stdout, 0LL);
  puts("Welcome to Mary's Unix Time Formatter!");
  do
  {
    while ( 2 )
    {
      puts("1) Set a time format.");
      puts("2) Set a time.");
      puts("3) Set a time zone.");
      puts("4) Print your time.");
      puts("5) Exit.");
      __printf_chk(1LL, "> ");
      v4 = stdout;
      fflush(stdout);
      switch ( sub_400D26() )
      {
        case 1:
          v5 = timeformat();
          break;
        case 2:
          v5 = settime(v4, "> ");
          break;
        case 3:
          v5 = timezone(v4, "> ");
          break;
        case 4:
          v5 = printtime(v4, "> ");
          break;
        case 5:
          v5 = Exit(v4, "> ");
          break;
        default:
          continue;
      }
      break;
    }
  }
  while ( !v5 );
  return 0LL;
}
```

这题题目是**FROM_UNIXTIME** ，这是将**MYSQL**中以INT(11)存储的时间以"YYYY-MM-DD"格式来显示

原版函数的语法是  **FROM_UNIXTIME(unix_timestamp,format)** ， 返回表示 **Unix** 时间标记的一个字符串，根据**format**字符串格式化。**format**可以包含与**DATE_FORMAT(**)函数列出的条目同样的修饰符 

根据**format**字符串格式化**date**值，下列修饰符可以被用在**format**字符串中：

> %M 月名字(January……December)
> %W 星期名字(Sunday……Saturday)
> %D 有英语前缀的月份的日期(1st, 2nd, 3rd, 等等。）
> %Y 年, 数字, 4 位
> %y 年, 数字, 2 位
> %a 缩写的星期名字(Sun……Sat)
> %d 月份中的天数, 数字(00……31)
> %e 月份中的天数, 数字(0……31)
> %m 月, 数字(01……12)
> %c 月, 数字(1……12)
> %b 缩写的月份名字(Jan……Dec)
> %j 一年中的天数(001……366)
> %H 小时(00……23)
> %k 小时(0……23)
> %h 小时(01……12)
> %I 小时(01……12)
> %l 小时(1……12)
> %i 分钟, 数字(00……59)
> %r 时间,12 小时(hh:mm:ss [AP]M)
> %T 时间,24 小时(hh:mm:ss)
> %S 秒(00……59)
> %s 秒(00……59)
> %p AM或PM
> %w 一个星期中的天数(0=Sunday ……6=Saturday ）
> %U 星期(0……52), 这里星期天是星期的第一天
> %u 星期(0……52), 这里星期一是星期的第一天
> %% 一个文字“%”