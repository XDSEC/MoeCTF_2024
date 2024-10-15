# 开发与运维方向 官方题解

## 运维入门指北

简单的文件整理工作。此处以 fish 作为示例：

```fish
rm *.bak
for i in *.xml
  mv $i (printf $i | sed 's/.xml/.html/g')
end
for i in *
  set folder1 (string sub -l 2 $i)
  set folder2 (string sub -s 3 -l 2 $i)
  mkdir -p $folder1/$folder2
  mv $i $folder1/$folder2/$i
end
```

然后使用 `su` 提权至 root 用户，将文件移动至 `/var/www/html` 下，稍等片刻后：

```fish
tail -F -n 10 /var/log/nginx/access.log
```

## 哦不！我的libc！

本题由于出题人失误，导致非预期非常的多。这里给出最简化的非预期方案，预期解可以移步 [哦不，我的nginx！](https://ctf.xidian.edu.cn/training/10?challenge=91) 查看。

```
echo $(< /flag.txt)
```

## 哦不！我的nginx！

本题来源于真实场景，为了适配 CTF 的现场情况，引入了 nginx 作为 check 服务。

在没有 glibc，服务器还没有 busybox 的情况下，我们几乎什么也使用不了。但是此时唯一存活的 bash 还是可以使用的。此时的第一想法是能不能从正在运行的进程里恢复 libc？

可惜不行。就算有神奇指令能从 `/proc/self/mem` 里拼凑一个能用的 libc 出来，还有个 ld 一样恢复不了。

### 利用 Bash 内建指令实现文件读写

此时我们需要考虑利用一下 bash 的内建指令，例如 echo, printf 等等。我们知道 利用管道重定向可以使用 bash 读写文件，而且用户权限是 root，因此我们几乎可以修改这个系统上的所有东西。

```
printf '\x11\x45\x14' > /bin/xxx
```

有了任意读写的功能之后，我们接下来需要考虑如何恢复 libc。最简便的方法是从网上找一个 libc，然后 printf 到既定位置，然后就万事大吉了……吗？并不。libc 与 ld 需要执行权限才能够和正常程序一起配合工作，但是在 bash 里没有办法用内建功能实现 chmod。于是我们现在需要考虑如何恢复 chmod 了。

### 恢复 chmod

根据题目提示（以及你的经验），此时最容易想到的方案是 [BusyBox](https://busybox.net/downloads/binaries)，BusyBox 是一套静态链接的基本指令集合，甚至内建了 sshd（dropbear）与 init。同时，BusyBox 还支持通过 `arg[0]` 模拟 coreutils，这意味着我们只需要将 BusyBox 重命名为某个指令，那么 BusyBox 就会自动尝试模拟这个指令。在 Linux 下读写文件时并不会修改文件的权限位，因此我们可以直接使用

```
printf '\x11\x45\x14' > /bin/chmod
```

的方式恢复出来 chmod。

但是最佳方案其实不是重定向到 chmod，而是重定向到 cp：

```
printf '\x11\x45\x14' > /bin/cp
cp /bin/cp /bin/chmod
cp /bin/cp /bin/mv
cp /bin/cp /bin/cat
cp /bin/cp /bin/nc
...
```

这样一来，就有一个完整的指令环境了。

#### 取巧小提示

在本题中提供了一个 neighbor 服务器，但是没有 root 权限。neighbor 是一个全功能服务器，因此我们可以利用 neighbor 和 bash 的 `/dev/tcp/` 伪协议实现文件的快速传输：

```sh
# 在自己电脑上
wget https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox
scp -P [WSRX port] ./busybox user@localhost:
```

```sh
# 在 neighbor 上
od -v -t x1 /bin/true | awk '{for (i=2; i<=NF; i++) printf "\\x%s", $i}' | nc -lvp 8000
```

```sh
# 在 broken 上，需要注意文件过大可能超出 read 的 32 位整数范围了，
# 第一次使用 `>` 清空，后面则使用 `>>` 附加，
# 执行个几次之后应该就能够从 neighbor 上把文件完整的传过来了，后面的过程保持一致。
exec [fd] <>/dev/tcp/127.0.0.1/8000 && read -u [fd] -N [size] -r [var] && printf $[var] > /bin/cp
exec [fd] <>/dev/tcp/127.0.0.1/8000 && read -u [fd] -N [size] -r [var] && printf $[var] >> /bin/cp
```

#### bash loadables

> 此思路由 [chi](https://github.com/chitao1234) 提供，感谢！

除此之外，bash 可以通过加载二进制扩展的方式扩展功能，例如 [bash-loadables](https://github.com/NobodyXu/bash-loadables)，加载二进制扩展并不要求扩展具有可执行权限，因此通过 printf 写入扩展二进制并加载，再由此恢复 chmod 也是可行的。

### 恢复 libc

我们有 busybox 之后，接下来的文件传输就变得方便许多了。busybox 内部有一个简易的 netcat 实现，利用 netcat 可以实现文件的一步到位传输：

```
# 在 neighbor 上，第一步
cat /usr/lib/x86_64-linux-gnu/libc.so.6 | nc -lnvp 8000
```

```
# 在 broken 上，第一步
nc 127.0.0.1 8000 > /usr/lib/x86_64-linux-gnu/libc.so.6
```

利用同样的方法传送过来 `/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2`

```
chmod +x /usr/lib/x86_64-linux-gnu/libc.so.6
chmod +x /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
```

本题就完成了。

### 启动 nginx

最后一步是启动 nginx：

```
nginx -g 'daemon off;'
```

开上几秒，然后关掉 nginx，去 `/var/log/nginx/access.log` 找 flag 即可。
