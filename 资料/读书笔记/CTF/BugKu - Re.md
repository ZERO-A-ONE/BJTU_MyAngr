# BugKu - Re（一）

## 入门逆向

没啥好说的

```c
mov     byte ptr [esp+2Fh], 'f'
mov     byte ptr [esp+2Eh], 'l'
mov     byte ptr [esp+2Dh], 'a'
mov     byte ptr [esp+2Ch], 'g'
mov     byte ptr [esp+2Bh], '{'
mov     byte ptr [esp+2Ah], 'R'
mov     byte ptr [esp+29h], 'e'
mov     byte ptr [esp+28h], '_'
mov     byte ptr [esp+27h], '1'
mov     byte ptr [esp+26h], 's'
mov     byte ptr [esp+25h], '_'
mov     byte ptr [esp+24h], 'S'
mov     byte ptr [esp+23h], '0'
mov     byte ptr [esp+22h], '_'
mov     byte ptr [esp+21h], 'C'
mov     byte ptr [esp+20h], '0'
mov     byte ptr [esp+1Fh], 'O'
mov     byte ptr [esp+1Eh], 'L'
mov     byte ptr [esp+1Dh], '}'
```

**flag{Re_1s_S0_C0OL}**

## Easy_vb

没啥好说的

```c
.text:00401A48 dword_401A48    dd 33AD4EE1h, 11CF6699h, 0AA000CB7h, 93D36000h, 2Eh
.text:00401A48                                         ; DATA XREF: .text:00402398↓o
.text:00401A48                                         ; .text:0040241E↓o ...
.text:00401A5C aMctfN3tRev1sE4:                        ; DATA XREF: .text:004023A9↓o
.text:00401A5C                 text "UTF-16LE", 'MCTF{_N3t_Rev_1s_E4ay_}',0
.text:00401A8C                 dd 14h
.text:00401A90 aTryAgain:                              ; DATA XREF: .text:00402473↓o
```

**flag{_N3t_Rev_1s_E4ay_}**

## Easy_re

没啥好说的，OD载入easy_vb.exe，右键中文字符串智能搜索,发现疑似flag字符串

![od.png](https://i.loli.net/2019/03/20/5c92561c36680.png)

**DUTCTF{We1c0met0DUTCTF}**

## 游戏过关

#### 修改Path法

搜索关键字符串**“flag”**直接找到**main**函数，我们找到了一个**jnz**和**call**的地方，因为不是**flag**的直接比较，所以想法是跳转至成功函数输出**flag**，总之就是寻找各种跳转函数，最后跳到**0x0045F66C**这个调用**sub_45E940**函数的地址即可

#### 直接逻辑法

搜索关键字符串**“flag**”直接找到**main**函数，然后修改常见函数名得到主函数

```c
void main()
{
  signed int i; // [esp+DCh] [ebp-20h]
  int v1; // [esp+F4h] [ebp-8h]

  printf(&unk_50B110);
  printf(&unk_50B158);
  printf(&unk_50B1A0);
  printf(&unk_50B1E8);
  printf(&unk_50B230);
  printf(&unk_50B278);
  printf(&unk_50B2C0);
  printf(&unk_50B308);
  printf("二                                                     |\n");
  printf("|              by 0x61                                 |\n");
  printf("|                                                      |\n");
  printf("|------------------------------------------------------|\n");
  printf(
    "Play a game\n"
    "The n is the serial number of the lamp,and m is the state of the lamp\n"
    "If m of the Nth lamp is 1,it's on ,if not it's off\n"
    "At first all the lights were closed\n");
  printf("Now you can input n to change its state\n");
  printf(
    "But you should pay attention to one thing,if you change the state of the Nth lamp,the state of (N-1)th and (N+1)th w"
    "ill be changed too\n");
  printf("When all lamps are on,flag will appear\n");
  printf("Now,input n \n");
  while ( 1 )
  {
    while ( 1 )
    {
      printf("input n,n(1-8)\n");
      getchar();
      printf("n=");
      scanf("%d", &v1);
      printf("\n");
      if ( v1 >= 0 && v1 <= 8 )
        break;
      printf("sorry,n error,try again\n");
    }
    if ( v1 )
    {
      sub_4576D6(v1 - 1);
    }
    else
    {
      for ( i = 0; i < 8; ++i )
      {
        if ( (unsigned int)i >= 9 )
          j____report_rangecheckfailure();
        byte_532E28[i] = 0;
      }
    }
    j__system("CLS");
    sub_458054();
    if ( byte_532E28[0] == 1
      && byte_532E28[1] == 1
      && byte_532E28[2] == 1
      && byte_532E28[3] == 1
      && byte_532E28[4] == 1
      && byte_532E28[5] == 1
      && byte_532E28[6] == 1
      && byte_532E28[7] == 1 )
    {
      sub_457AB4();
    }
  }
}
```

同时也找到了调用函数**sub_45E940**，存在两个数组，先两个数组按位异或，再与0x13异或，直接提取出数据然后写脚本跑即可

```c
 for ( i = 0; i < 56; ++i )
  {
    *(&v2 + i) ^= *(&v59 + i);
    *(&v2 + i) ^= 0x13u;
  }
```

```python
ss4 = [0x12,0x40,0x62,0x5,0x2,0x4,0x6,0x3,0x6,0x30,0x31,0x41,0x20,0x0C,0x30,0x41,0x1F,0x4E,0x3E,0x20,0x31,0x20,0x1,0x39,0x60,0x3,0x15,0x9,0x4,0x3E,0x3,0x5,0x4,0x1,0x2,0x3,0x2C,0x41,0x4E,0x20,0x10,0x61,0x36,0x10,0x2C,0x34,0x20,0x40,0x59,0x2D,0x20,0x41,0x0F,0x22,0x12,0x10,0x0]
ss8 = [0x7B,0x20,0x12,0x62,0x77,0x6C,0x41,0x29,0x7C,0x50,0x7D,0x26,0x7C,0x6F,0x4A,0x31,0x53,0x6C,0x5E,0x6C,0x54,0x6,0x60,0x53,0x2C,0x79,0x68,0x6E,0x20,0x5F,0x75,0x65,0x63,0x7B,0x7F,0x77,0x60,0x30,0x6B,0x47,0x5C,0x1D,0x51,0x6B,0x5A,0x55,0x40,0x0C,0x2B,0x4C,0x56,0x0D,0x72,0x1,0x75,0x7E,0x0]
flag = ""
for i in range(0,0x38):
    flag += chr(ss4[i]^ss8[i]^0x13)
print(flag)
```

得到flag：**zsctf{T9is_tOpic_1s_v5ry_int7resting_b6t_others_are_n0t}**

## Timer(阿里CTF)题目分析

- 在安卓模拟器上运行程序
   ![流程.png](https://i.loli.net/2019/04/10/5cadadbc74e63.png)

- 程序流程 

  > 提示信息  
  >
  > > Time remaining(s):200000
  > >  AliCTF{}  
  >
  > 初步分析  
  >
  > > 应该是200000秒之后才会出现flag
  > >  下一步使用安卓调试神器[JEB](https://www.52pojie.cn/thread-547547-1-1.html)进一步分析      

### JEB分析

- JEB介绍 

  > JEB:[IDA](https://www.52pojie.cn/thread-675251-1-1.html)+111=JEB,JEB相当于Windows平台上的IDA  
  >
  > smali代码:双击Bytecode,出现smali代码;相较于C之汇编,则smali之于Java  
  >
  > > ![smali.png](https://i.loli.net/2019/04/10/5cadb2004a6b6.png) 
  > >
  > > [smali语法参考文章](https://blog.csdn.net/cloverjf/article/details/78613830)  
  >
  > 快捷键：按`q`切换到java伪代码

- 进入android程序入口类

  - 进入方式

    `Bytecode/Hierarchy-net-tomorrow-MainActivity`

    ![入口类.png](https://i.loli.net/2019/04/10/5cadb2004c374.png)

    ![smali2.png](https://i.loli.net/2019/04/10/5cadb33e04764.png)
     \> 双击左边的Bytecode默认进入的就是此入口类  

  - 按 `Q` 查看java伪代码

    ![伪代码.png](https://i.loli.net/2019/04/10/5cadb3f5df43e.png)

  - 查看onCreate函数
     \> 一个activity启动回调的第一个函数就是onCreate,这个函数主要做这个activity启动的一些必要的初始化的工作。
     \>
     \> onCreate之后调用了还有onRestart()和onStart()等。

    ![注释onCreate.png](https://i.loli.net/2019/04/10/5cadc40677139.png)

  - 查看onCreate回调的MainActivity函数  

    ```
    public MainActivity() {
    super();
    this.beg = (((int)>(System.currentTimeMillis() / 1000))) + 200000;  
     //当前时间(beg)为200000加上当前时间(s)    
    this.k = 0;    
     //k初始化为0,和onCreate函数中的flag字符串存在联系
    this.t = 0;
    }
    ```

  - 查看onCreate回调的is2函数

    ![is2.png](https://i.loli.net/2019/04/10/5cadc494aef1e.png)

### 编写脚本

- 由于md渲染问题,代码放于文末

- 运行结果

  `k=1616384`

## Android killer修改并打包源程序

- 进入入口类

  ![载入程序.png](https://i.loli.net/2019/04/10/5cadd09e36dc6.png)

- 搜索字符串 `AliCTF`

  ![AliCTF.png](https://i.loli.net/2019/04/10/5cadd1383063a.png)

  ![搜索字符串.png](https://i.loli.net/2019/04/10/5cadd1a7a01b0.png)

- 定位到变量 `k`

  > 搜索`stringFromJNI2`  
  >
  > ![stringFromJNI2.png](https://i.loli.net/2019/04/10/5cadd332ec48c.png)  
  >
  > > 上一条句把k存放在寄存器`v3`中,下面修改v3,就可以修改k
  > >  寄存器用v开头数字结尾的符号来表示，如v0、v1、v2、...

- 修改变量k的值

  > `const v3;1616384`  
  >
  > ![修改变量k.png](https://i.loli.net/2019/04/10/5cadd3f6dfb97.png)

- 理一理思路

  > 这里我把`k`的值设置为正确的值,即执行200000次后会出现的值了  
  >
  > 但是因为if条件判断为假,程序还是会执行200000次，才会输出flag  
  >
  > 这里就需要把`<=`改为`>`  
  >
  > > 搜索`<=`附近的字符串`AliCTF`

- 修改if判断条件

  ![反过来了.png](https://i.loli.net/2019/04/10/5cadd86d23ea4.png)

  > 发现这里是反过来的,下一步把 `>` 改成 `<=` 
  >
  > 将`if-gtz v0, :cond_0`修改为`if-lez v0, :cond_0`  
  >
  > > ![小于.png](https://i.loli.net/2019/04/10/5cadd8f83b3c1.png)

- 编译打包程序  

  > 在编译的时候遇到以下问题
  >  \>>Project\res\values-v23\styles.xml:6: error: Error retrieving  parent for item: No resource found that matches the given name  '@android:style/WindowTitleBackground'.
  >  \>>
  >  \>>Project\res\values-v23\styles.xml:6: error: Error retrieving  parent for item: No resource found that matches the given name  '@android:style/WindowTitleBackground'.

- 解决方法

  > 找到res/value-v23/styles.xml，把resources下的东西注释掉  
  >
  > ```
  > <?xml version="1.0" encoding="utf-8"?>
  > <resources>
  > <!--
  > ...
  > -->
  > </resources>
  > ```
  >
  > \> 找到res/value/public.xml，把所有带Base.V23的东西（两个）注释掉  
  >
  > ```
  > <?xml version="1.0" encoding="utf-8"?>
  > <resources>
  > <!--
  > ...
  > -->
  > </resources>
  > ```

- 重新编译打包  

  ![编译成功.png](https://i.loli.net/2019/04/10/5cadeb314bca4.png)

### 模拟器载入新安装包

- 成功获取flag

  ![flag.png](https://i.loli.net/2019/04/10/5cadebc91d750.png)

- flag
   `flag{Y0vAr3TimerMa3te7}`

### 总结

- 环境问题

  > Android Killer编译apk始终失败  
  >
  > > 通过换jdk7以及修改res/xml成功编译  
  >
  > 运行Jeb闪退  
  >
  > > 修改jeb_winos.bat,替换java版本
  > >  ![java版本.png](https://i.loli.net/2019/04/10/5cadee07e601d.png)  

- 技术问题  

  > 不懂smati语言,但是Jeb和AK自身的伪代码转义功能较强,还是可以看懂程序流程 
  >
  > 下来需要潜心学习smati语法
  >
  > 本例程序代码量很少,遇到大型程序不会这么简单  

### 代码部分

```java
#include <iostream>
using namespace std;
bool is2(int arg4) 
{
        bool v1 = true;
        if(arg4 > 3) 
        {
            if(arg4 % 2 != 0 && arg4 % 3 != 0) 
            {
                int v0 = 5;
                while(true) 
                {
                    if(v0 * v0 <= arg4) 
                    {
                        if(arg4 % v0 != 0 && arg4 % (v0 + 2) != 0) 
                        {
                            v0 += 6;
                            continue;
                        }
                        return false;
                    }
                    else 
                        return v1;
                }
                return false;
            }
            v1 = false;
        }
        else if(arg4 <= 1) 
            v1 = false;
        return v1;
}

int main()
{
    int time = 200000;
    int k = 0;
    while(time > 0)
    {
        if(is2(time))
                k+=100;
        else
                k--;  
        time--;
    }
    cout << "k=" << k << endl ;
    return 0;
}
```

## 逆向入门

发现不是有效的**pe**文件，用**VisualStudio Code**打开试试,发现是**“image/png；base64”**，猜测是经过**base64**加密的图片，将整段内容复制下来，**base64**转图片

![](https://github-1251836300.cos.ap-guangzhou.myqcloud.com/Bugku/Re/index.png)

扫描二维码，得到flag：**bugku{inde_9882ihsd8-0}** 

## love

盲猜flag：I love you，算了不说笑了，还是真实做题吧

载入OD

搜索字符串

![img](https://img-blog.csdn.net/20171228160459980)

随意输入1111111111111111111

![img](https://img-blog.csdn.net/20171228160500294)

![img](https://img-blog.csdn.net/20171228160501460)

发现进行了base64加密

再向下单步 发现、

![img](https://img-blog.csdn.net/20171228160502178)

结合IDA看下

![img](https://img-blog.csdn.net/20171228160503183)

```c
int sub_4156E0()

{

size_t v0;// eax@6

constchar*v1;// eax@6

size_t v2;// eax@9

char v4;// [sp+0h] [bp-188h]@6

char v5;// [sp+Ch] [bp-17Ch]@1

size_t v6;// [sp+10h] [bp-178h]@3

size_t j;// [sp+DCh] [bp-ACh]@6

size_t i;// [sp+E8h] [bp-A0h]@1

char Dest[108];// [sp+F4h] [bp-94h]@5

char Str;// [sp+160h] [bp-28h]@6

char v11;// [sp+17Ch] [bp-Ch]@6

unsignedint v12;// [sp+184h] [bp-4h]@1

int savedregs;// [sp+188h] [bp+0h]@1

 

memset(&v5,0xCCu,0x17Cu);

v12 =(unsignedint)&savedregs ^ __security_cookie;

for( i =0;(signedint)i <100;++i )

{

v6 = i;

if( i >=0x64)

sub_411154();

Dest[v6]=0;

}

sub_41132F("please enter the flag:", v4);

sub_411375("%20s",(unsignedint)&Str);

v0 = j_strlen(&Str);

v1 =(constchar*)sub_4110BE(&Str, v0,&v11);

strncpy(Dest, v1,'(');

sub_411127();

i = j_strlen(Dest);

for( j =0;(signedint)j <(signedint)i;++j )

Dest[j]+= j;

v2 = j_strlen(Dest);

strncmp(Dest, Str2, v2);

if( sub_411127())

sub_41132F("wrong flag!\n", v4);

else

sub_41132F("rigth flag!\n", v4);

sub_41126C(&savedregs,&dword_415890);

sub_411280();

return sub_411127();

}
```

分析可知:将输入的串**Str1**先进行**base64**加密 再与串**Str2**比较 若相等 则输出**"right flag"**

由此，我们只需将**Str2**也就是**"e3nifIH9b_C@n@dH"**进行解密即可

```python
import base64

s ="e3nifIH9b_C@n@dH"

flag =""

for i in range(len(s)):

flag += chr(ord(s[i])- i)

flag = base64.b64decode(flag)

print(flag)
```

最后拿到答案**flag{i_l0ve_you}**

## LoopAndLoop

载入JEB，双击**MainActivity**，选择**Decompilea class**

```java
package net.bluelotus.tomorrow.easyandroid;
 
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.View$OnClickListener;
 
public class MainActivity extends AppCompatActivity {  // System.loadLibrary()是我们在使用Java的JNI机制时，会用到的一个非常重要的函数
    static {
        System.loadLibrary("lhm");  // 它的作用即是把我们在Java code中声明的native方法的那个libraryload进来，或者load其他什么动态连接库
    }
 
    public MainActivity() {
        super();
    }
 
    public native int chec(int arg1, int arg2) {  // native层的chec方法
    }
 
    public int check(int input, int s) {  // check方法将我们的输入和一个int型变量s返回到chec
        return this.chec(input, s);
    }
 
    public int check1(int input, int s) {  // check1定义v1为我们的输入，v0为循环变量1
        int v1 = input;
        int v0 = 1;
    label_2:  // 进入到label_2
        if(v0 < 100) {
            v1 += v0;  // 先判断v0是否小于100，如果成立，那么v1每次加上v0的值
            ++v0;  // v0每次也要自增1
            goto label_2;  // 直接走向label_2
        }
 
        return this.chec(v1, s);  // 还是将得到的v1及s返回给chec方法
    }
 
    public int check2(int input, int s) {  // 和上面的check与check1一样，都是需要两个参数，一个是我们的输入，一个是s
        int v2;  // v2还是作为chec方法的返回值
        int v3 = 1000;
        int v1 = input;  // 定义三个int型变量，v1还是我们的输入，v3做为定值1000，而v2作为返回值(相当于一个标志)
        if(s % 2 == 0) {
            int v0;  // 当s对2取余等于0，也就是说s能被2整除时，定义一个新的循环变量v0
            for(v0 = 1; v0 < v3; ++v0) {
                v1 += v0;  // v0等于1，当小于v3的值也就是小于1000时，v1每次加上v0，v0++
            }
 
            v2 = this.chec(v1, s);  // v2还是作为chec方法的返回值
        }
        else {
            for(v0 = 1; v0 < v3; ++v0) {//如果取余不等于0，那么还是和上边一样，只不过v1每次减去v0
                v1 -= v0;
            }
 
            v2 = this.chec(v1, s);//chec方法的返回值
        }
 
        return v2;//返回v2
    }
 
    public int check3(int input, int s) {//check3将输入给v1，将循环变量v0初值设为1，当v0小于10000，v1每次加上v0,而v0循环一次就加1
        int v1 = input;
        int v0;
        for(v0 = 1; v0 < 10000; ++v0) {
            v1 += v0;
        }
 
        return this.chec(v1, s);
    }
 
    public String messageMe(String text) {//messageMe方法是返回字符串"LoopOk"+text
        return "LoopOk" + text;
    }
 
    protected void onCreate(Bundle savedInstanceState) {//关键的方法onCreate
        super.onCreate(savedInstanceState);
        this.setContentView(2130968600);//这两行和布局有关，不用管
        this.findViewById(2131492946).setOnClickListener(new View$OnClickListener() {
            public void onClick(View v) {//最最重要的,从名字就可以看出，当我们点击GETYOURFLAG！这个按钮时触发的onClick
                int v1;
                String v2 = this.val$ed.getText().toString();//v2获取我们的输入并转成字符串
                try {										  //下边这个try,catch用来捕获将类型异常
                    v1 = Integer.parseInt(v2);//将v2这个String字符类型数据转换为Integer整型数据赋值给v1
                }
                catch(NumberFormatException v0) {
                    this.val$tv1.setText("Not a Valid Integer number");//如果不可以转成整数，就在屏幕打印"不是一个有效的整数"
                    return;
                }
 
                if(MainActivity.this.check(v1, 99) == 1835996258) {//如果我们输入的v1和s也就是99传给check方法，
                    this.val$tv1.setText("The flag is:");//接着传向chec方法得到的返回值等于1835996258，就输出flag
                    this.val$tv2.setText("alictf{" + MainActivity.this.stringFromJNI2(v1) + "}");//括号内是native层stringFromJNI2()方法处理v1后的
                }
                else {
                    this.val$tv1.setText("Not Right!");
                }
            }
        });
    }
 
    public boolean onCreateOptionsMenu(Menu menu) {
        this.getMenuInflater().inflate(2131558400, menu);
        return 1;
    }
 
    public boolean onOptionsItemSelected(MenuItem item) {
        boolean v1 = item.getItemId() == 2131492961 ? true : super.onOptionsItemSelected(item);
        return v1;
    }
 
    public native String stringFromJNI2(int arg1) {
    }
}
```

经过分析可知重要的**chec**和**stringFromJNI2**都在**native**层，那么就需要将**liblhm.so**文件载入**IDA**进行分析，载入后直接**shift+F12**搜索字符串双击**MainActivity**进入，接着找到引用

在按**F5**就可以将**chec**反汇编成伪代码了 经过分析 可以知道**chec**方法根据第二个参数乘2对3取模的结果调用**Java**层的三个**check**函数对我们的输入进行处理所以我们只需要写脚本将算法逆过来就好

```python
#! /usr/bin/env python
#-*- coding: utf-8 -*-
def getinput():
    target = 1835996258
    for i in range(2,100):
        if 2 * i % 3 == 0:
            target = check1(target,i - 1)
        elif 2 * i % 3 == 1:
            target = check2(target,i - 1)
        else:
            target = check3(target,i - 1)
    print target
def check1(input,loopNum):
    t = input
    for i in range(1,100):
        t = t - i
    return t
 
def check3(input,loopNum):
    t = input
    for i in range(1,10000):
        t = t - i
    return t
 
def check2(input, loopNum):
    t = input
    if loopNum % 2 == 0:
        for i in range(1,1000):
            t -= i
        return t
    for i in range(1,1000):
        t += i
    return t
 
if __name__ == '__main__':
  getinput()
```

得到答案：**alictf{Jan6N100p3r}**
