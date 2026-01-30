# XYpsa 虚拟动态归档器

## 前置知识

- [XYpsa](XYpsaFormat/README.md)：这是项目作者自创的一个文件格式，类似于 tar 格式，但是支持更多特性：

  - 长文件名(65535 字节)
  - 不限制路径长度
  - 支持 4G 以上的文件
  - 支持分卷
  - 支持 AES 加密文件数据
  - 支持连目录结构一起加密
  - 支持附加不加密的备注信息
  - 可流式生成
  - 可流式解档
  - 流式生成前可精确预测大小
  - 所有文本信息均 UTF-8 编码
  - 多重完整性校验

- 虚拟文件系统：就是所谓的“虚拟磁盘”，可以简单理解成：软件会创建一个假的 U 盘，里面存储的文件和数据都是软件动态生成的，并不是真实存在的物理介质。

## 介绍

这是一款用 Python 编写的归档工具，可以将多个文件或文件夹打包成一个 XYpsa 文件，支持加密和分卷。

和`7-zip`、`WinRAR`、`WinZip`等工具不同，该工具会创建一个虚拟磁盘，里面存储着归档后的文件，可以正常的复制、读取文件内容、上传到网盘。

但是对应的归档文件并没有生成，只有在有程序试图读取文件数据时，才会进行归档操作。

考虑到某些网盘的特性，本程序挂载的虚拟磁盘可以存储小文件，这些文件会存储到内存中；所以**请勿把大文件复制到虚拟磁盘**，否则可能会导致内存不足。

## 项目结构

```
src/
├── gui.py                # GUI 界面实现
├── vfs.py                # 虚拟文件系统实现
└── xypsa_generator.py    # XYpsaGenStream 封装与逻辑
XYpsaFormat/
├── README.md             # XYpsa 格式的规范文档
├── xypsa.hexpat          # 适用于imhex的模式解析代码
├── XYpsaGenStream.py     # XYpsaGenStream 模块
└── XYpsaParseStream.py   # XYpsaParseStream 模块
GUI_unarchive.py          # 配套的GUI界面解档器
main.py                   # 主程序入口
main.spec                 # PyInstaller 打包配置文件，归档器和解档器打包到一起
```

ImHex 是一个十六进制编辑器，项目地址：https://github.com/WerWolv/ImHex

## 安装依赖

```sh
uv sync
```

或

```sh
pip install winfspy cryptography sortedcontainers
```

## 打包

```sh
uv pip install pyinstaller
uv run pyinstaller main.spec
```

或

```sh
pip install pyinstaller
pyinstaller main.spec
```

## pypy3 兼容性

项目可以在 `pypy3.10` 下运行

由于代码的问题，使用 `pypy` 会比 `Cpython` 慢很多，根据 2025.02.17 的实验，由`pypy3.10`执行加密归档任务只有 30MB/s，而 `Cpython` 可以达到 200MB/s。

## 许可证

本程序遵循 [GPL-3.0-only](https://opensource.org/license/gpl-3-0/)许可证。

本程序仅供学习研究使用，严禁用于商业用途！

> 注意：由于 GPL 协议的强约束性，如果您将本项目的代码用于您的商业项目，会导致您商业项目的所有代码被迫全部以相同协议开源

本项目许可证的具体内容详见项目根目录下的 LICENSE 文件

您也可访问[GNU 的网站](https://www.gnu.org/licenses/)获取更多有关 GPL 许可证以及自由软件运动的相关信息
