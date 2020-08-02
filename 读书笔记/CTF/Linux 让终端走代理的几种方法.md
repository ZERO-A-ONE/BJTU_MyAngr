# Linux 让终端走代理的几种方法

最近使用终端git的时候觉得速度有点慢，考虑一下是不是可以通过让终端走代理的方式来加快速度，尝试了一下以后确实是可以的。如果只是为了设置git的话可以直接在文章最后找到git的设置代理的方法。

**前期准备:**

认识代理的方式:代理是通过客户端与服务端通信,传输服务端能够访问到的资源文件,再由服务端客户端通信返回给客户端,从而间接访问服务端能访问的资源.

以socket5通信为例子,我们通过客户端(自己想一想酸酸乳)向服务端发送socket通信,服务端访问资源再由socket通信返回给客户端.但是这里面的通信设置必须通过端口来进行通信,类似switchyomega设置过程一样,我们会设定走的代理方式是127.0.0.1:1080;这个意思就是通过本地的1080端口来进行通信.具体在终端上如何使用呢?

- 如果默认是socket5通信且端口是1080,即127.0.01:1080的方式

使用如下两种方式

```text
socks5://127.0.0.1:1080
```

这里无关自己代理客户端是不是酸酸乳或酸酸只要是通过socket通信即可,前提是满足已经能够正常代理访问.

- 第二种是http代理,即通信方式为http而不是socket

```text
http://127.0.0.1:12333
```

## -方法一：（推荐使用）

>  为什么说这个方法推荐使用呢？因为他只作用于当前终端中，不会影响环境，而且命令比较简单

在终端中直接运行：

```text
export http_proxy=http://proxyAddress:port
```

如果你是SSR,并且走的http的代理端口是12333，想执行wget或者curl来下载国外的东西，可以使用如下命令：

```text
export http_proxy=http://127.0.0.1:12333
```

如果是https那么就经过如下命令：

```text
export https_proxy=http://127.0.0.1:12333
```

## 方法二 ：

>  这个办法的好处是把代理服务器永久保存了，下次就可以直接用了

把代理服务器地址写入shell配置文件.bashrc或者.zshrc 直接在.bashrc或者.zshrc添加下面内容

```text
export http_proxy="http://localhost:port"
export https_proxy="http://localhost:port"
```

或者走socket5协议（ss,ssr）的话，代理端口是1080

```text
export http_proxy="socks5://127.0.0.1:1080"
export https_proxy="socks5://127.0.0.1:1080"
```

或者干脆直接设置ALL_PROXY

```text
export ALL_PROXY=socks5://127.0.0.1:1080
```

最后在执行如下命令应用设置

```text
source ~/.bashrc
```

或者通过设置alias简写来简化操作，每次要用的时候输入setproxy，不用了就unsetproxy。

```console
 alias setproxy="export ALL_PROXY=socks5://127.0.0.1:1080" alias unsetproxy="unset ALL_PROXY"
```

## 方法三:

改相应工具的配置，比如apt的配置

```text
sudo vim /etc/apt/apt.conf
```

在文件末尾加入下面这行

```text
Acquire::http::Proxy "http://proxyAddress:port"
```

>  重点来了！！如果说经常使用git对于其他方面都不是经常使用，可以直接配置git的命令。

## 使用ss/ssr来加快git的速度

直接输入这个命令就好了

```text
git config --global http.proxy 'socks5://127.0.0.1:1080' 
git config --global https.proxy 'socks5://127.0.0.1:1080'
```

