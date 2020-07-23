# Angr入门笔记（一）

本文所使用Ubuntu环境皆为18.04 LTS 版本

## 安装篇

建议首先修改Linux和Python镜像至国内镜像加速体验

### Linux/Ubuntu国内镜像

- 首先打开Software&Updates
- 选择Download from
- 选择Other...
- 在国家列表中找到China
- 推荐选择的镜像源为：
  - 清华大学镜像站：`mirrors.tuna.tsinghua.edu.cn`
  - 阿里云镜像站：`mirrors.aliyun.com`
- Choose Server
- 选择Close后等待刷新镜像仓库
- 在shell中执行
  - `sudo apt update`
  - `sudo apt upgrade`

### Python国内镜像加速

首先切回用户主目录

```shell
cd ~
```

然后创建`.pip`目录

```shell
mkdir ~/.pip
cd ~/.pip
```

这里推荐编辑器使用传说中的神器`vim`

```shell
sudo apt install vim
```

在.pip目录下创建一个`pip.conf`文件

```shell
vim pip.conf
```

填入以下内容保存即可

```shell
[global]
index-url = https://pypi.tuna.tsinghua.edu.cn/simple
trusted-host = pypi.tuna.tsinghua.edu.cn
disable-pip-version-check = true
```

### 安装Angr

这里主要参照官方手册文档的教学

首先是安装必要的软件环境

```shell
sudo apt-get install python3-dev libffi-dev build-essential virtualenvwrapper
```

开始正式安装angr

```shell
mkvirtualenv --python=$(which python3) angr && pip install angr
```

angr安装完毕

angr官方推荐使用虚拟环境运行，每次需要调用具有angr环境时，只需要执行

```shell
 mkvirtualenv --python=$(which python3) angr
```

### Tips：

#### 1）如果遇上 mkvirtualenv: command not found 问题

- 在终端命令行输入以下命令：
  - `sudo pip install virtualenv`
  - `sudo pip install virtualenvwrapper`
- 没问题下一步
  - `cd ~/`
- 修改bashrc文件
  - `vim .bashrc`
  - 在文件末尾添加两行代码
    - `export WORKON_HOME=~/.environments`
    - `source /usr/local/bin/virtualenvwrapper.sh`
- 保存退出即可