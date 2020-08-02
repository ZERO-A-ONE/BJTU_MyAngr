# IDA、GDB、DBG常用操作

## IDA Pro

- F5：反编译代码
- Space：切换汇编代码展示方式（流程图or顺序）
- tab：切换反编译窗口和汇编窗口
- n：自定义变量函数名
- y：自定义函数参数、调用方式
- /：添加注释
- x：交叉引用
- shift + E：导出数据

## Olly DBG

- F7：步进，跟进函数调用
- F8：步过，不跟进函数调用
- F9：运行直到断点
- F4：执行到光标
- F2：下断点
- ctrl+g：跳转到指定地址

## GDB

- 控制流操作
  - r：运行程序
  - r<a.txt：重定向输入
  - si：步进
  - ni：步过
  - c：继续运行直到断点
  - finish：运行到函数结束
- 断点
  - b *0xaabb：在指定位置下断点
  - b main：在指定函数下断点
  - watch *0xaabb：当修改内存时中断
  - rwatch *0xaabb：在读取内存时中断
  - info b：查看当前断电
  - en 1：打开1号断点
  - dis 1：关闭1号断点
- 查看内存
  - x命令查看内存
    - x/16xb 0xaabb
      - 查看0xaabb位置的内存，显示为16进制，单位为1字节
      - 16代表往后数16份单位内存，x代表十进制，b代表byte
    - x/32dw 0xaabb
      - 查看0xaabb位置的内存，显示为10进制整数，单位为2字节
      - d代表十进制整数，word代表1个字两个字节

## 其他工具

- Android\JAVA
  - JEB
  - jadx
  - xposed\Frida
- MIPS
  - JEB
  - Ghidra