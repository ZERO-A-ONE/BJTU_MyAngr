# ARM与QEMU-Tips-1

## QEMU的安装

### 0x01 安装必要环境

```shell
sudo apt install -y qemu-user gcc-arm-linux-gnueabi binutils-arm-linux-gnueabigcc-arm-linux-gnueabi lib32ncurses5 lib32z1
```

### 0x02 安装Qemu

有两种方法可以在Linux环境下安装Qemu工具，第一种直接使用XUbuntu系统的apt工具安装，但是这种方法安装的Qemu系统版本不是最新的，如果需要安装最新版本的Qemu工具，就需要通过Git工具下载源码，切换到最新分支再去编译安装了。具体操作如下所述

#### 快速安装Qemu：

```shell
sudo apt install qemu
```

#### 下载Qemu源码编译安装

从Git服务器下载Qemu代码，记着在下载之前选择并切换需要的源码分支：

```shell
git clone git://git.qemu-project.org/qemu.git
```

编译并安装Qemu：

```shell
./configure --target-list=arm-softmmu --audio-drv-list=
make
make install
```

#### 查看Qemu版本

```shell
qemu-system-arm --version
```

#### 查看Qemu支持的开发板

Qemu工具支持大量开发板的虚拟，现存的大部分常用开发板都能很好地支持。通过下面的命令操作可以看到当前版本的Qemu工具支持的开发板列表：

```shell
qemu-system-arm -M help
```

# 模拟ARM程序

需要设置**ld-linux.so**的加载路径

以下两种方式都可以：

- `qemu-arm -L /usr/arm-linux-gnueabi -cpu cortex-a15 awd7`
- `export QEMU_LD_PREFIX=/usr/arm-linux-gnueabi qemu-arm -cpu cortex-a15 awd7`

如果不这样设置的话，一般会出现这样的错误，提示不能加载`ld-linux`:

```shell
/lib/ld-linux.so.3: No such file or directory
```

当然，如果不这样设置的话，可以将程序编译成静态链接的，命令如下：

```shell
arm-linux-gnueabi-gcc -o simple -c simple -static
```

## ARM程序调试

进行远程调试关键是增加 -g 参数，指定端口

```shell
qemu-arm -g 1235 -L /usr/arm-linux-gnueabi -cpu cortex-a15 awd7
```

 然后使用GDB进行远程调试

```shell
(gdb) target remote :1235
Remote debugging using :1235
```