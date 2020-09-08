# IDA脚本笔记一

## 0x01 读取和修改数据的函数

### 01 Byte

```c
long Byte(long addr)
```

从虚拟地址**addr**处读取一个字节值

### 02 Word

```c
long Word(long addr)
```

从虚拟地址**addr**处读取一个字（2字节）值

### 03 Dword

```c
long Dword(long addr)
```

从虚拟地址**addr**处读取一个双字（4字节）值

### 04 PatByte

```c
void PatchByte(long addr, long val)
```

设置虚拟地址**addr**处的一个字节值

### 05 PatchWord

```c
void PatchWord(long addr, long val)
```

设置虚拟地址**addr**处的一个字值

### 06 PatchDword

```c
void PatchDword(long addr,long val)
```

设置虚拟地址addr处的一个双字值

### 07 isLoaded

```c
bool isLoaded(long addr)
```

如果addr包含有效数据，则返回1，否则返回0

## 0x02 用户交互函数

### 01 Message

```c
void Message(string format,...)
```

在输出窗口打印一条格式化消息。这个函数类似于C语言的**printf**函数，并接受**printf**风格的格式化字符串

### 02 print

```c
void print(...)
```

在输出窗口中打印每个参数的字符串表示形式

### 03 Warning

```c
void Warning(string format,...)
```

在对话框中显示一条格式化消息

### 04 AskStr

```c
string AskFile(string default, string promat)
```

显示一个输入框，要求用户输入一个字符串值。如果操作成功，则返回用户的字符串；如果对话框被取消，则返回0

### 05 AskFile

```c
string AskFile(long doSave, string mask, string promat)
```

显示一个文件选择对话框，以简化选择文件的任务。你可以创建新文件保存数据(**doSave**=1)，或选择现有的文件读取数据(**doSave**=0)。你可以根据**mask**(如\*.*或\*.idc)过滤显示的文件列表。如果操作成功，则返回选定文件的名称；如果对话框被取消，则返回0

### 06 AskYN

```c
long AskYN(long default, string prompt)
```

用一个答案为“是”或“否”的问题提示用户，突出一个默认的答案（1为是，0为否，-1为取消）。返回值是一个表示选定答案的整数

### 07 ScreenEA

```c
long ScreenEA()
```

返回当前光标所在位置的虚拟地址

### 08 Jump

```c
bool Jump(long addr)
```

跳转到反汇编窗口的指定地址

## 0x03 字符串操纵函数

### 01 form

```c
string form(string format,...)
```

返回一个新字符串，该字符串根据所提供的格式化字符串和值进行格式化。这个函数基本上等同于C语言的**sprintf**函数

### 02 sprintf

```c
string sprintf()
```

在IDA5.6中，**sprintf**用于替代**form**

### 03 atol

```c
long atol(string val)
```

将十进制值val转换成对应的整数值

### 04 xtol

```c
long xtol(string val)
```

将十六进制值**val**（可选择以0x开头）转换成对应的整数值

### 05 ltoa

```c
string IItoa(long val, long radix)
```

一指定的**radix**（2、8、10或16）返回**val**的字符串值

### 06 ord

```c
long ord(string ch)
```

返回单字符字符串**ch**的**ASCII**值

### 07 strlen

```c
long strlen(string str)
```

返回所提供字符串的长度

### 08 strstr

```c
long strstr(string str, string substr)
```

返回**str**中**substr**的索引。如果没有发现子字符串，则返回-1

### 09 substr

```c
string substr(string str, long start, long end)
```

返回包含**str**中由**start**到**end-1**位置的字符的子字符串。如果使用分片，此函数等同于**str[start:end]**

## 0x04 文件输入/输出函数

### 01 fopen

```c
long fopen(string filename, string mode)
```

返回一个整数文件句柄（如果发生错误，则返回0），供所有**IDC**文件输入/输出函数使用。**mode**参数与C语言的fopen函数使用的模式（r表示读取，w表示写入，等等）类似

### 02 fclose

```c
void fclose(long handle)
```

关闭fopen中文件句柄指定的文件

### 03 filelength

```c
long filelength(long handle)
```

返回指定文件的长度，如果发生错误，则返回-1

### 04 fgetc

```c
long fgetc(long handle)
```

从给定的文件中读取一个字节，如果发生错误，则返回-1

### 05 fputc

```c
long fputc(long val, long handle)
```

写入一个字节到给定文件中。如果操作成功，则返回0；如果发生错误，则返回-1

### 06 fprintf

```c
long fprintf(long handle, string format, ...)
```

将一个格式化字符串写入到给定文件中

### 07 writestr

```c
long writestr(long handle, string str)
```

将指定的字符串写入到给定的文件中

### 08 readstr

```c
string/long readstr(long handle)
```

从给定文件中读取一个字符串。这个函数读取到下一个换行符为止的字符串（包括非**ASCII**字符），包括换行符本身（**ASCII 0xA**）。如果操作成功，则返回字符串；如果读取到文件结尾，则返回**-1**

### 09 writelong

```c
long writelong(long handle, long val, long bigendian)
```

使用大端**(bigendian =1)**或小端**(bigendian =0)**字节顺序将一个4字节整数写入到给定文件

### 10 readlong

```c
long readlong(long handle, long bigendian)
```

使用大端**(bigendian =1)**或小端**(bigendian =0)**字节顺序从给定的文件中读取一个4字节整数

### 11 writeshort

```c
long writeshort(long handle, long val, long bigendian)
```

使用大端**(bigendian =1)**或小端**(bigendian =0)**字节顺序将一个2字节整数写入到给定文件

### 12 readshort

```c
long readshort(long handle, long bigendian)
```

使用大端**(bigendian =1)**或小端**(bigendian =0)**字节顺序从给定的文件中读取一个2字节整数

### 13 loadfile

```c
bool loadfile(long handle, long pos, long addr, long length)
```

从给定文件的**pos**位置读取**length**数量的字节，并将这些字节写入到以**addr**地址开头的数据库中

### 14 savefile

```c
bool savefile(long handle, long pos, long addr, long length)
```

将以addr数据库地址开头的length数量的字节写入给定文件的**pos**位置

## 0x05 操纵数据库名称

### 01 Name

```c
string Name(long addr)
```

返回与给定地址有关的名称，如果该位置没有名称，则返回空字符串。如果名称被标记为局部名称，这个函数并不返沪用户定义的名称

### 02 NameEx

```c
string NameEx(long from, long addr)
```

返回与addr有关的名称。如果该位置没有名称，则返回空字符串。如果**from**是一个同样包含**addr**的函数中的地址，则这个函数返回用户定义的局部名称

### 03 MakeNameEx

```c
bool MakeNameEx(long addr, string name, long flags)
```

将给定的名称分配给定的地址。该名称使用flags位掩码中指定的属性创建而成。这些标志在帮助系统中的**MakeNameEx**文档中有记载描述，可用于指定各种属性，如名称是局部名称还是公共名称、名称是否应在名称窗口中列出

### 04 long LocByName

```c
long LocByName(string name)
```

返回一个位置（名称已给定）的地址。如果数据库中没有这个名称，则返回**BADADDR(-1)**

### 05 long LocByNameEX

```c
long LocByName(long funcaddr, string localname)
```

在包含funcaddr的函数中搜索给定的局部名称。如果给定的函数中没有这个名称，则返回**BADADDR(-1)**

## 0x06 处理函数的函数

### 01 GetFunctionAttr

```c
long GetFunctionAttr(long addr, long attrib)
```

返回包含给定地址的函数的被请求的属性。请参考IDC帮助文档了解属性常量。例如，要查找一个函数的结束地址，可以使用`GetFunctionAttr(addr, FUNCATTR_END)`

### 02 GetFunctionName

```c
string GetFunctionName(long addr)
```

返回包含给定地址的函数的名称。如果给定的地址并不属于一个函数，则返回一个空字符串

### 03 NextFunction

```c
long NextFunction(long addr)
```

返回给定地址后的下一个函数的起始地址。如果数据库中给定地址后没有其他函数，则返回-1

### 04 PrevFunction

```c
long PrevFunction(long addr)
```

返回给定地址之前距离最近的函数起始地址。如果在给定地址之前没有函数，则返回-1

### 05 long LocBy

```c
long LocBy(string Name)
```

根据函数的名称，返回该函数的起始地址

## 0x07 代码交叉引用函数

### 01 Rfirst

```c
long Rfirst(long from)
```

返回给定地址向其转交控制权的第一个位置。如果给定的地址没有引用其他地址，则返回**BADADDR(-1)**

### 02 Rnext

```c
long Rnext(long from, long current)
```

如果**current**已经在前一次调用**Rfirst**或**Rnext**时返回，则返回给定地址（**from**）转交控制权的下一个位置。如果没有其他交叉引用存在，**BADADDR(-1)**

### 03 XrefType

```c
long XrefType()
```

返回一个常量，说明某个交叉引用查询函数（如**Rfirst**）返回的最后一个交叉引用的类型。对于代码交叉引用，这些常量包括**fl_CN**(近调用)、**fl_CF**(远调用)、**fl_JN**(近跳转)、**fl_JF**(远跳转)和**fl_F**(普通顺序流)

### 04 RfirstB

```c
long RfirstB(long to)
```

返回转交控制权到给定地址的第一个位置。如果不存在对给定地址的交叉引用，则返回**BADADDR(-1)**

### 05 RnextB

```c
long RnextB(long to, long current)
```

如果**current**已经在前一次调用**RfirstB**或**RnextB**时返回，则返回下一个转交控制权到给定地址（**to**）的位置。如果不存在其他对给定位置的交叉引用，**BADADDR(-1)**

## 0x08

### 01 Dfirst

```c
long Dfirst(long from)
```

返回给定地址引用一个数据值的第一个位置。如果给定的地址没有引用其他地址，则返回**BADADDR(-1)**

### 02 Dnext

```c
long Dnext(long from, long current)
```

如果**current**已经在前一次调用**Dfirst**或**Dnext**时返回，则返回给定地址（**from**）向其引用一个数据值的下一个位置。如果没有其他交叉引用存在，**BADADDR(-1)**

### 03 XrefType

```c
long XrefType()
```

返回一个常量，说明某个交叉引用查询函数（如**Dfirst**）返回的最后一个交叉引用的类型。对于数据交叉引用，这些常量包括**dr_0**(提供的偏移量)、**dr_W**(数据写入)和**dr_R**(数据读取)

### 04 DfirstB

```c
long DfirstB(long to)
```

返回给定地址作为数据引用的第一个位置。如果不存在对给定地址的交叉引用，则返回**BADADDR(-1)**

### 05 DnextB

```c
long DnextB(long to, long current)
```

如果**current**已经在前一次调用**DfirstB**或**DnextB**时返回，则返回将给定地址（**to**）作为数据引用的下一次位置。如果没有其他交叉引用存在，**BADADDR(-1)**

## 0x09 数据库操纵函数

### 01 MakeUnkn

```c
void MakeUnkn(long addr, long flags)
```

取消位于指定地址的顶的定义。这里的表示（参见**IDC**的**MakeUnkn**文档）指出是否也取消随后的项的定义，以及是否删除任何与取消定义的项有关的名称。相关函数**MakeUnknown**允许你取消大块数据的定义

### 02 MakeCode

```c
long MakeCode(long addr)
```

将位于指定地址的字节转换成一条指令。如果操作成功，则返回指令的长度，否则返回0

### 03 MakeByte

```c
bool MakeByte(long addr)
```

将位于指定地址的项目转换成一个数据字节。类似的函数还包括**MakeWord**和**MakeDword**

### 04 MakeComm

```c
bool MakeComm(long addr, string comment)
```

在给定的地址处添加一条常规注释

### 05 MakeFunction

```c
bool MakeFunction(long begin, long end)
```

将由**begin**到**end**的指令转换成一个函数。如果**end**被指定为**BADADDR(-1)**，**IDA**会尝试通过定位函数的返回指令，来自动确定该函数的结束地址

### 06 MakeStr

```c
bool MakeStr(long begin, long end)
```

创建一个当前字符串(有**GetStringType**返回)类型的字符串，涵盖由**begin**到**end-1**之间的所有字节。如果**end**被指定为**BADADDR(-1)**，**IDA**会尝试自动确定字符串的结束位置

## 0x10 数据库搜索函数

在**IDA**中**Find**系列函数中的**flags**参数是一个位掩码，可用于指定查找操作的行为。3个最为常用的标志分别为**SEARCH_DOWN**，它指示搜索操作扫描高位地址；**SEARCH_NEXT**，它略过当前匹配项，以搜索下一个匹配项；**SEARCH_CASE**，它以区分大小写的方式进行二进制和文本搜索

### 01 FindCode

```c
long FindCode(long addr, long flags)
```

从给定的地址搜索一条指令

### 02 FindData

```c
long FindData(long addr, long flags)
```

从给定的地址搜索一个数据项

### 03 FindBinary

```c
long FindBinary(long addr, long flags, string binary)
```

从给定的地址搜索一个字节序列。字符**binary**指定一个十六进制字节序列值。如果没有设置**SEARCH_CASE**，且一个字节值指定了一个大写或小写**ASCII**字母，则搜索仍然会匹配对应的互补值。例如，"41 42"将匹配"61 62"和"61 42"，除非你设置了**SEARCH_CASE**标志位

### 04 FindText

```c
long FindText(long addr, long flags, long row, long column, string text)
```

在给定的地址，从给定行（**row**）的给定列搜索字符串**text**。注意，某个给定地址的反汇编文本可能会跨越几行，因此，你需要指定搜索应从哪一行开始

## 0x11 反汇编行组件

### 01 GetDisasm

```c
string GetDisasm(long addr)
```

返回给定地址的反汇编文本。反回的文本包括任何注释，但不包括地址信息

### 02 GetMnem

```c
string GetMnem(long addr)
```

返回位于给定地址的指令的助记符部分

### 03 GetOpnd

```c
string GetOpnd(long addr, long opnm)
```

返回指定地址的指定操作数的文本形式。IDA以零为起始编号，从左向右对操作数编号

### 04 GetOpType

```c
long GetOpType(long addr, long opnum)
```

返回一个整数，指出给定地址的给定操作数的类型。请参考**IDC**文档，了解操作数类型代码

### 05 GetOperandValue

```c
long GetOperandValue(long addr, long opnum)
```

返回与给定地址的给定操作数有关的整数值。返回值的性质取决于**GetOpType**指定的给定操作数的类型

### 06 CommentEx

```c
string CommentEx(long addr, long type)
```

返回给定地址处的注释文本。如果哦type为0，则返回常规注释的文本；如果type为1，则返回可重复注释的文本。如果给定地址处没有注释，则返回一个空字符串

## 脚本示例

### IDC脚本

实现的功能是导出一段内存的数据为数组形式

```c
auto str_addr,end_addr,dat;
str_addr = 0x00413CD2;
end_addr = 0x00413D1C;
dat = end_addr - str_addr;
auto i = 0;
Message("[");
for(i=0;i<dat;i++){ 
    if(i != dat-1)
    {
        Message("%d ,",Byte(str_addr+i));
    }
    else{
         Message("%d",Byte(str_addr+i));
    }
}
Message("]");
```

### IDAPython脚本

功能同上

```python
from idaapi import *
data = []
model = "db"
str_addr = 0x00413CD2
end_addr = 0x00413D1C
dat = end_addr - str_addr
i = 0
for i in range(dat):
    if model == "db":
        data.append(Byte(str_addr + i))
    if model == "dw":
        data.append(Word(str_addr + i))
    if model == "dd":
        data.append(Dword(str_addr + i))
print data
```

