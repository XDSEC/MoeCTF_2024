# 关于WP
Author: 0xcafebabe
第三方题目（非XDSEC成员）: 
1.xor(大嘘) (Author: 中国人民警察大学的：Chovy)
2.Cython-Strike: Bomb Defusion (Author: 西安电子科技大学的：不玩逆向爱玩CS的同学)
# 入门指北
下载PDF，了解里面关于XOR的讲解内容后，可以发现直接给出了解题代码。
```c
#include <iostream>
int main()
{
	char password_enc[] = { 
		123, 121, 115, 117, 98, 112, 109, 100, 37, 96, 37, 100, 101, 37, 73, 39,
		101, 73, 119, 73, 122, 121, 120, 113, 73, 122, 121, 120, 113, 73, 97, 119, 
		111, 73, 98, 121, 73, 115, 110, 102, 122, 121, 100, 115, 107, 22 };
	// 因为a^b=c时, b^c=a, 所以我们可以这样还原数据:
	char password[47];
	for (int i = 0; i < 46; i++) {
		password[i] = password_enc[i] ^ 22;
	}
	password[46] = 0; // 使用0字符来截断掉%s的无尽输出..
		printf("%s\n", password); // 哈哈，这就是本题的f l a g，自己运行一下交上去吧！
	return 0;
}
```
可以拿到flag
```moectf{r3v3rs3_1s_a_long_long_way_to_explore}```

# Xor
拿到附件后发现是Windows下的可执行文件(.exe)，我们载入IDA后可以观察到反编译的代码
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  FILE *v3; // rax
  __int64 i; // rax
  char Buffer[16]; // [rsp+20h] [rbp-48h] BYREF
  __int128 v7; // [rsp+30h] [rbp-38h]
  __int64 v8; // [rsp+40h] [rbp-28h]
  int v9; // [rsp+48h] [rbp-20h]
  char v10; // [rsp+4Ch] [rbp-1Ch]

  sub_140001010("Input Your Flag moectf{xxx} (len = 45) \n");
  v8 = 0LL;
  *(_OWORD *)Buffer = 0LL;
  v9 = 0;
  v7 = 0LL;
  v10 = 0;
  v3 = _acrt_iob_func(0);
  fgets(Buffer, 45, v3);
  for ( i = 0LL; i < 44; ++i )
  {
    if ( ((unsigned __int8)Buffer[i] ^ 0x24) != byte_1400022B8[i] )
    {
      sub_140001010("FLAG is wrong!\n");
      system("pause");
      exit(0);
    }
  }
  sub_140001010("FLAG is RIGHT!\n");
  system("pause");
  return 0;
}
```
我们注意到```  char Buffer[16]; // [rsp+20h] [rbp-48h] BYREF```这个变量的大小是16，但是下面```  fgets(Buffer, 45, v3);```的大小是45，可以推测这个变量的大小反编译错误了。我们按y改成45，再刷新看代码。
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  FILE *v3; // rax
  __int64 i; // rax
  char Buffer[48]; // [rsp+20h] [rbp-48h] BYREF

  sub_140001010("Input Your Flag moectf{xxx} (len = 45) \n");
  memset(Buffer, 0, 45);
  v3 = _acrt_iob_func(0);
  fgets(Buffer, 45, v3);
  for ( i = 0LL; i < 44; ++i )
  {
    if ( ((unsigned __int8)Buffer[i] ^ 0x24) != byte_1400022B8[i] )
    {
      sub_140001010("FLAG is wrong!\n");
      system("pause");
      exit(0);
    }
  }
  sub_140001010("FLAG is RIGHT!\n");
  system("pause");
  return 0;
}
```
可以发现，下面那些由于反编译错误的变量消失了，这时我们可以看到程序主逻辑是异或0x24并且逐个与```byte_1400022B8```进行比较，我们双击byte_1400022B8。
```c
.rdata:00000001400022B8 ; _BYTE byte_1400022B8[56]
.rdata:00000001400022B8 byte_1400022B8  db 49h, 4Bh, 41h, 47h, 50h, 42h, 5Fh, 41h, 1Ch, 16h, 46h
.rdata:00000001400022B8                                         ; DATA XREF: main+58↑o
.rdata:00000001400022C3                 db 10h, 13h, 1Ch, 40h, 9, 42h, 16h, 46h, 1Ch, 9, 2 dup(10h)
.rdata:00000001400022CF                 db 42h, 1Dh, 9, 46h, 15h, 2 dup(14h), 9, 17h, 16h, 14h
.rdata:00000001400022DA                 db 41h, 2 dup(40h), 16h, 14h, 47h, 12h, 40h, 14h, 59h
.rdata:00000001400022E4                 db 0Ch dup(0)
```
发现这种形式，不方便抄出来，所以我们按U，他就会变成Undefined，再右键选中所有的，Convert拿出来成Python的List。
所以我们很容易写出EXP（解题脚本）。
```python
enc = [0x49, 0x4B, 0x41, 0x47, 0x50, 0x42, 0x5F, 0x41, 0x1C, 0x16, 0x46, 0x10, 0x13, 0x1C, 0x40, 0x09, 0x42, 0x16, 0x46, 0x1C, 0x09, 0x10, 0x10, 0x42, 0x1D, 0x09, 0x46, 0x15, 0x14, 0x14, 0x09, 0x17, 0x16, 0x14, 0x41, 0x40, 0x40, 0x16, 0x14, 0x47, 0x12, 0x40, 0x14, 0x59]
for i in enc:
    print(chr(i ^ 0x24), end='')
    # moectf{e82b478d-f2b8-44f9-b100-320edd20c6d0}
```
所以Flag：```moectf{e82b478d-f2b8-44f9-b100-320edd20c6d0}```

# upx
github下载UPX，然后用命令行启动，upx -d，就可以解压程序，再拖入IDA，即可查看正确的flag。
```moectf{ec5390dd-f8cf-4b02-bc29-3bb0c5604c29}```

# dynamic
程序要求我们进行动态调试，我们先载入IDA进行分析。
```c
int __fastcall main_0(int argc, const char **argv, const char **envp)
{
  char *v3; // rdi
  __int64 i; // rcx
  char v6; // [rsp+20h] [rbp+0h] BYREF
  _BYTE v7[80]; // [rsp+28h] [rbp+8h] BYREF
  _DWORD v8[56]; // [rsp+78h] [rbp+58h] BYREF

  v3 = &v6;
  for ( i = 34LL; i; --i )
  {
    *(_DWORD *)v3 = -858993460;
    v3 += 4;
  }
  j___CheckForDebuggerJustMyCode(&unk_140022067, argv, envp);
  v7[0] = -94;
  v7[1] = 5;
  v7[2] = 105;
  v7[3] = -117;
  v7[4] = -38;
  v7[5] = 23;
  v7[6] = 5;
  v7[7] = -31;
  v7[8] = -36;
  v7[9] = -52;
  v7[10] = -52;
  v7[11] = -63;
  v7[12] = 100;
  v7[13] = 116;
  v7[14] = -6;
  v7[15] = 80;
  v7[16] = -43;
  v7[17] = -95;
  v7[18] = -102;
  v7[19] = -84;
  v7[20] = -36;
  v7[21] = -34;
  v7[22] = 100;
  v7[23] = -65;
  v7[24] = -108;
  v7[25] = 45;
  v7[26] = 35;
  v7[27] = -13;
  v7[28] = 1;
  v7[29] = -43;
  v7[30] = 98;
  v7[31] = -56;
  v7[32] = -22;
  v7[33] = -83;
  v7[34] = -46;
  v7[35] = -42;
  v7[36] = 42;
  v7[37] = 80;
  v7[38] = 94;
  v7[39] = 107;
  v7[40] = 115;
  v7[41] = 12;
  v7[42] = -3;
  v7[43] = -116;
  v7[44] = 61;
  v7[45] = 56;
  v7[46] = 61;
  v7[47] = -47;
  v8[0] = -889275714;
  v8[1] = -559038242;
  v8[2] = 866566;
  v8[3] = 1131796;
  sub_14001129E(v7, 4294967284LL, v8);
  sub_1400113D4("What happened to my Flag?\n");
  sub_14001129E(v7, 12LL, v8);
  sub_1400113D4("Your Flag has REencrypted.");
  return 0;
}
```
可以发现，```What happened to my Flag?```上下都有一个sub_14001129E的函数，我们对4294967284LL进行分析，可以知道它其实是-12(```0xFFFFFFF4LL```)，再点进去，可以观察到如下代码
```c
__int64 __fastcall sub_140011820(int *a1, __int64 a2, __int64 a3)
{
  __int64 result; // rax
  unsigned int v4; // [rsp+24h] [rbp+4h]
  unsigned int v5; // [rsp+24h] [rbp+4h]
  unsigned int v6; // [rsp+44h] [rbp+24h]
  unsigned int v7; // [rsp+44h] [rbp+24h]
  unsigned int v8; // [rsp+44h] [rbp+24h]
  unsigned int v9; // [rsp+64h] [rbp+44h]
  unsigned int v10; // [rsp+64h] [rbp+44h]
  unsigned int j; // [rsp+84h] [rbp+64h]
  int i; // [rsp+84h] [rbp+64h]
  int v13; // [rsp+A4h] [rbp+84h]
  int v14; // [rsp+A4h] [rbp+84h]
  int v15; // [rsp+C4h] [rbp+A4h]
  unsigned int v16; // [rsp+C4h] [rbp+A4h]
  int v17; // [rsp+194h] [rbp+174h]
  int v18; // [rsp+194h] [rbp+174h]
  int v19; // [rsp+194h] [rbp+174h]
  int v20; // [rsp+194h] [rbp+174h]
  int v22; // [rsp+1C8h] [rbp+1A8h]
  int v23; // [rsp+1C8h] [rbp+1A8h]

  v22 = a2;
  result = j___CheckForDebuggerJustMyCode(&unk_140022067, a2, a3);
  if ( v22 <= 1 )
  {
    if ( v22 < -1 )
    {
      v23 = -v22;
      v14 = 52 / v23 + 6;
      v10 = 1131796 * v14;
      v5 = *a1;
      do
      {
        v16 = (v10 >> 2) & 3;
        for ( i = v23 - 1; i; --i )
        {
          v7 = a1[i - 1];
          v19 = a1[i]
              - (((v7 ^ *(_DWORD *)(a3 + 4LL * (v16 ^ i & 3))) + (v5 ^ v10)) ^ (((16 * v7) ^ (v5 >> 3))
                                                                              + ((4 * v5) ^ (v7 >> 5))));
          a1[i] = v19;
          v5 = v19;
        }
        v8 = a1[v23 - 1];
        v20 = *a1
            - (((v8 ^ *(_DWORD *)(a3 + 4LL * v16)) + (v5 ^ v10)) ^ (((16 * v8) ^ (v5 >> 3)) + ((4 * v5) ^ (v8 >> 5))));
        *a1 = v20;
        v5 = v20;
        v10 -= 1131796;
        result = (unsigned int)--v14;
      }
      while ( v14 );
    }
  }
  else
  {
    v13 = 52 / v22 + 6;
    v9 = 0;
    v6 = a1[v22 - 1];
    do
    {
      v9 += 1131796;
      v15 = (v9 >> 2) & 3;
      for ( j = 0; j < v22 - 1; ++j )
      {
        v4 = a1[j + 1];
        v17 = (((v6 ^ *(_DWORD *)(a3 + 4LL * (v15 ^ j & 3))) + (v4 ^ v9)) ^ (((16 * v6) ^ (v4 >> 3))
                                                                           + ((4 * v4) ^ (v6 >> 5))))
            + a1[j];
        a1[j] = v17;
        v6 = v17;
      }
      v18 = (((v6 ^ *(_DWORD *)(a3 + 4LL * (v15 ^ j & 3))) + (*a1 ^ v9)) ^ (((16 * v6) ^ ((unsigned int)*a1 >> 3))
                                                                          + ((4 * *a1) ^ (v6 >> 5))))
          + a1[v22 - 1];
      a1[v22 - 1] = v18;
      v6 = v18;
      result = (unsigned int)--v13;
    }
    while ( v13 );
  }
  return result;
}
```
这其实是一个标准的XXTEA，当n>1的时候（也就是+12）的时候，是加密，-12就是解密。
所以这个程序其实在做一个事情：把内置的flag进行解密后又马上加密回去，所以我们只需要动态调试，找到解密后的flag即可。
最后我们附上这个题目的c语言源码
```c
#include <iostream>
#include <stdint.h>
#define MX (((z>>5^y<<2) + (y>>3^z<<4)) ^ ((sum^y) + (key[(p&3)^e] ^ z)))
#define DELTA 0x114514
void ppp(uint32_t* v, int n, uint32_t const key[4])
{
        uint32_t y, z, sum;
        unsigned p, rounds, e;
        if (n > 1)            /* Coding Part */
        {
                rounds = 6 + 52 / n;
                sum = 0;
                z = v[n - 1];
                do
                {
                        sum += DELTA;
                        e = (sum >> 2) & 3;
                        for (p = 0; p < n - 1; p++)
                        {
                                y = v[p + 1];
                                z = v[p] += MX;
                        }
                        y = v[0];
                        z = v[n - 1] += MX;
                } while (--rounds);
        }
        else if (n < -1)      /* Decoding Part */
        {
                n = -n;
                rounds = 6 + 52 / n;
                sum = rounds * DELTA;
                y = v[0];
                do
                {
                        e = (sum >> 2) & 3;
                        for (p = n - 1; p > 0; p--)
                        {
                                z = v[p - 1];
                                y = v[p] -= MX;
                        }
                        z = v[n - 1];
                        y = v[0] -= MX;
                        sum -= DELTA;
                } while (--rounds);
        }
}
int main()
{
        char v[] = { 0xa2,0x05,0x69,0x8b,0xda,0x17,0x05,0xe1,0xdc,0xcc,0xcc,0xc1,0x64,0x74,0xfa,0x50,0xd5,0xa1,0x9a,0xac,0xdc,0xde,0x64,0xbf,0x94,0x2d,0x23,0xf3,0x01,0xd5,0x62,0xc8,0xea,0xad,0xd2,0xd6,0x2a,0x50,0x5e,0x6b,0x73,0x0c,0xfd,0x8c,0x3d,0x38,0x3d,0xd1 };
        uint32_t k[] = { 0xcafebabe , 0xdeadc0de, 0xd3906, 0x114514 };
        ppp((uint32_t*)v, -12, k);
        printf("What happened to my Flag?");
        ppp((uint32_t*)v, 12, k);
        printf("Your Flag has encrypted.");
        return 0;
}

```
```moectf{18d4c944-947c-4808-9536-c7d34d6b3827}```

# Reverse 问卷: Bye, MoeCTF2024
填写问卷即可获得flag。
```moectf{Thank_You_FOR_Playing_Reverse_Challenges}```

# upx-revenge
解法1：这个程序直接upx -d是显示无法进行解压的，原因是UPX解压的时候会检测程序段名称是否为UPX0\UPX1这类的，但是我改成了vmp0，导致无法直接解压，我们使用010Editor打开后更改这个字符串也就可以解密了。
解法2：直接拖入X64dbg进行动态调试，调试起来后直接搜索全局字符串，就可以找到flag。
解法3：CheatEngine进行字符串搜索。
```moectf{554ea35c-a1bb-4d8f-a323-bd697564bf27}```

# XTEA
我们拿到文件后拖入IDA，可以获得以下代码
```cpp
int __fastcall main_0(int argc, const char **argv, const char **envp)
{
  char *v3; // rdi
  __int64 i; // rcx
  __int64 v5; // rax
  __int64 v6; // rax
  __int64 v7; // rax
  __int64 v8; // rax
  __int64 v10; // rax
  char v11; // [rsp+20h] [rbp+0h] BYREF
  unsigned int v12; // [rsp+24h] [rbp+4h]
  char Str[48]; // [rsp+48h] [rbp+28h] BYREF
  _DWORD v14[12]; // [rsp+78h] [rbp+58h] BYREF
  _BYTE Src[32]; // [rsp+A8h] [rbp+88h] BYREF
  _BYTE v16[28]; // [rsp+C8h] [rbp+A8h] BYREF
  int j; // [rsp+E4h] [rbp+C4h]

  v3 = &v11;
  for ( i = 58LL; i; --i )
  {
    *(_DWORD *)v3 = -858993460;
    v3 += 4;
  }
  j___CheckForDebuggerJustMyCode(&unk_140028066, argv, envp);
  v12 = 32;
  memset(Str, 0, 0xDuLL);
  v5 = sub_1400110AA(std::cout, "please input key:");
  std::ostream::operator<<(v5, sub_140011046);
  sub_14001153C(std::cin, Str);
  v14[0] = 2;
  v14[1] = 0;
  v14[2] = 2;
  v14[3] = 4;
  v6 = sub_1400110AA(std::cout, "let me check your key");
  std::ostream::operator<<(v6, sub_140011046);
  v7 = sub_1400110AA(std::cout, "emmm");
  std::ostream::operator<<(v7, sub_140011046);
  if ( j_strlen(Str) == 12 )
  {
    memset(v16, 0, 8uLL);
    j_memcpy(Src, Str, 8uLL);
    sub_14001119F(v12, Src, v14);
    j_memcpy(Str, Src, 8uLL);
    j_memcpy(v16, &Str[4], 8uLL);
    sub_14001119F(v12, v16, v14);
    j_memcpy(&Str[4], v16, 8uLL);
    for ( j = 0; j < 12; ++j )
    {
      if ( Str[j] != byte_140022000[j] )
        goto LABEL_5;
    }
    v10 = sub_1400110AA(std::cout, "Correct key! Your flag is moectf{your key}");
    std::ostream::operator<<(v10, sub_140011046);
    return 0;
  }
  else
  {
LABEL_5:
    v8 = sub_1400110AA(std::cout, "XD,wrong!");
    std::ostream::operator<<(v8, sub_140011046);
    return 0;
  }
}
```
可以观察到，```sub_14001119F```为加密函数，因为在memcpy之后进行的它，并且它的结果又覆盖回去了，最后与正确的结果进行对比。
以下是XTEA的加密
```c
__int64 __fastcall sub_1400148C0(unsigned int a1, unsigned int *a2, __int64 a3)
{
  __int64 result; // rax
  unsigned int i; // [rsp+24h] [rbp+4h]
  unsigned int v5; // [rsp+44h] [rbp+24h]
  unsigned int v6; // [rsp+64h] [rbp+44h]
  unsigned int v7; // [rsp+84h] [rbp+64h]

  j___CheckForDebuggerJustMyCode(&unk_140028066, a2, a3);
  v5 = *a2;
  v6 = a2[1];
  v7 = 0;
  for ( i = 0; i < a1; ++i )
  {
    v5 += (*(_DWORD *)(a3 + 4LL * (v7 & 3)) + v7) ^ (v6 + ((v6 >> 5) ^ (16 * v6)));
    v7 -= 855655493;
    v6 += (*(_DWORD *)(a3 + 4LL * ((v7 >> 11) & 3)) + v7) ^ (v5 + ((v5 >> 5) ^ (16 * v5)));
  }
  *a2 = v5;
  result = 4LL;
  a2[1] = v6;
  return result;
}
```
我们可以观察到IDA存在一些反编译错误，比如a3是一个DWORD型的指针（在main函数中，这个数组被赋值为了2 0 2 4）。我们进行修改，并且我们发现第一个参数是rounds(循环次数)，第二个参数是Source，修改后的结果如下：
```c
__int64 __fastcall sub_1400148C0(unsigned int rounds, unsigned int *source, _DWORD *key)
{
  __int64 result; // rax
  unsigned int i; // [rsp+24h] [rbp+4h]
  unsigned int v5; // [rsp+44h] [rbp+24h]
  unsigned int v6; // [rsp+64h] [rbp+44h]
  unsigned int v7; // [rsp+84h] [rbp+64h]

  j___CheckForDebuggerJustMyCode(&unk_140028066, source, key);
  v5 = *source;
  v6 = source[1];
  v7 = 0;
  for ( i = 0; i < rounds; ++i )
  {
    v5 += (key[v7 & 3] + v7) ^ (v6 + ((v6 >> 5) ^ (16 * v6)));
    v7 -= 855655493;
    v6 += (key[(v7 >> 11) & 3] + v7) ^ (v5 + ((v5 >> 5) ^ (16 * v5)));
  }
  *source = v5;
  result = 4LL;
  source[1] = v6;
  return result;
}
```
于是，我们可以观察到这是一个魔改了Delta的XTEA。
我们再返回main函数进行观察
```c
  if ( j_strlen(Str) == 12 )
  {
    memset(v16, 0, 8uLL);
    j_memcpy(Src, Str, 8uLL);
    xtea_encrypt(len, (__int64)Src, (__int64)key);
    j_memcpy(Str, Src, 8uLL);
    j_memcpy(v16, &Str[4], 8uLL);
    xtea_encrypt(len, (__int64)v16, (__int64)key);
    j_memcpy(&Str[4], v16, 8uLL);
    for ( j = 0; j < 12; ++j )
    {
      if ( Str[j] != byte_140022000[j] )
        goto LABEL_5;
    }
    v10 = sub_1400110AA(std::cout, "Correct key! Your flag is moectf{your key}");
    std::ostream::operator<<(v10, sub_140011046);
    return 0;
  }
```
可以注意到，输入的数据是12字节，也就是flag长度是12字节，首先Str（输入的字符）前8个字节先拷贝到了Src里面，然后Src进行加密，加密了前8个字节（因为Xtea只加密8个字节），然后，memcpy把加密的8个字节再覆盖回Str里面，接下来，Memcpy对str+4拷贝（拷贝后8个字节）到v16中，然后对v16进行加密，所以上面的流程可以等效为：
```c
xtea_encrypt(len, (__int64)Src, (__int64)key);
xtea_encrypt(len, (__int64)(Src + 4), (__int64)key);
```
最后和标准结果进行对比。
我们写出最后的EXP *(由于Regadgets库暂时不公开，所以我只放出了部分使用到的函数的源码。)
```python
enc = [0xA3, 0x69, 0x96, 0x26, 0xBD, 0x78, 0x0B, 0x3D, 0x9D, 0xA5, 0x28, 0x62]
key = [2, 0, 2, 4]

# 拆分成3个DWORD
dw1, dw2, dw3 = byte2dword(enc)

dw2, dw3 = xtea_decrypt((dw2, dw3), key=key, delta=-0x33004445, rounds=32)
dw1, dw2 = xtea_decrypt((dw1, dw2), key=key, delta=-0x33004445, rounds=32)

print(dword2byte([dw1, dw2, dw3]))
# b'moectf2024!!'

'''
from regadgets import *
Internal Functions Of Regadgets
'''
from typing import List, Tuple
from struct import unpack
from ctypes import c_uint32
def byte2dword(x: List[int]):
    if len(x) % 4 != 0:
        if type(x) == bytes:
            x += b'\x00' * (4 - (len(x) % 4))
        else:
            x += [0] * (4 - (len(x) % 4))
    return [v[0] for v in (unpack('<I', bytes(x[i:i+4])) for i in range(0, len(x), 4))]

def xtea_decrypt(
    src: Tuple[int, int], key: List[int], delta: int = 0x9E3779B9, rounds: int = 32
):
    l, r = c_uint32(src[0]), c_uint32(src[1])
    sum = c_uint32(delta * rounds)
    k = [c_uint32(key[0]), c_uint32(key[1]), c_uint32(key[2]), c_uint32(key[3])]
    for _ in range(rounds):
        r.value -= (((l.value << 4) ^ (l.value >> 5)) + l.value) ^ (
            sum.value + k[(sum.value >> 11) & 3].value
        )
        sum.value -= delta
        l.value -= (((r.value << 4) ^ (r.value >> 5)) + r.value) ^ (
            sum.value + k[sum.value & 3].value
        )
    return (l.value, r.value)

def dword2byte(x: List[int]):
    result = []
    if type(x) == int:
        for j in range(4):
            result.append((x >> j*8) & 0xff)
        return bytes(result)
    for i in range(len(x)):
        for j in range(4):
            result.append((x[i] >> j*8) & 0xff)
    return bytes(result)
'''
Internal Functions Of Regadgets
'''
```
所以最后的flag是```moectf{moectf2024!!}```

# dotNet(d0tN3t)
dll（核心代码）拖入dnSpy进行分析
```CSharp
using System;
using System.Runtime.CompilerServices;

// Token: 0x02000002 RID: 2
[CompilerGenerated]
internal class Program
{
    // Token: 0x06000001 RID: 1 RVA: 0x00002050 File Offset: 0x00000250
    private static void <Main>$(string[] args)
    {
        byte[] array = new byte[]
        {
            0xAD,
            .....
            0xA4
        };
        Console.WriteLine("Input Your Flag:");
        string text = Console.ReadLine();
        if (text.Length != array.Length)
        {
            Console.WriteLine("Flag is WRONG!!!");
            return;
        }
        int num = 1;
        for (int i = 0; i < array.Length; i++)
        {
            if ((byte)((int)((byte)text[i] + 0x72 ^ 0x72) ^ i * i) != array[i])
            {
                num &= 0;
            }
        }
        if (num == 1)
        {
            Console.WriteLine("Correct Flag!!!");
            return;
        }
        Console.WriteLine("Flag is WRONG!!!");
    }
}
```
注意到flag的加密逻辑
```CSharp
(byte)((int)((byte)text[i] + 0x72 ^ 0x72) ^ i * i)
```
写出解密脚本即可
```CSharp
byte[] s3cr3t = {173, 146, 161, 174, 132, 179, 187, 234, 231, 244, 177, 161, 65, 13, 18, 12, 166, 247, 229, 207, 125, 109, 67, 180, 230, 156, 125, 127, 182, 236, 105, 21, 215, 148, 92, 18, 199, 137, 124, 38, 228, 55, 62, 164};
for (int i = 0; i < s3cr3t.Length; i++)
{
    Console.Out.Write((char)((byte)(s3cr3t[i] ^ i*i ^ 114) - 114));
}
```
同时我们给出python的exp
```python
enc = [173, 146, 161, 174, 132, 179, 187, 234, 231, 244, 177, 161, 65, 13, 18, 12, 166, 247, 229, 207, 125, 109, 67, 180, 230, 156, 125, 127, 182, 236, 105, 21, 215, 148, 92, 18, 199, 137, 124, 38, 228, 55, 62, 164]

for i in range(len(enc)):
    print(chr(((i*i ^ 114 ^ enc[i]) - 114) & 0xff), end='')

# moectf{7ce581d2-b2ab-4ceb-9bbe-435873083db6}
```
由于很多人用Python写的，但是没有注意到Python的int是无限精度的，所以我们必须限制它在0xff(byte)的范围内，才可以解出flag，不然可能会出现负数的情况。
flag: ```moectf{7ce581d2-b2ab-4ceb-9bbe-435873083db6}```

# RC4
拖入IDA，我们发现ida没有找到main函数，这时按Shift+F12，定位String，然后对着String按X（交叉引用），就可以定位到main函数。
```c
__int64 __fastcall sub_4013F0(__int64 a1, const char *a2)
{
  unsigned __int64 v2; // rax
  __int64 v3; // rax
  __int64 v4; // rax
  __int64 v6; // [rsp+18h] [rbp-88h]
  int i; // [rsp+24h] [rbp-7Ch]
  __int64 v8; // [rsp+28h] [rbp-78h]
  _BYTE v9[72]; // [rsp+50h] [rbp-50h] BYREF
  unsigned __int64 v10; // [rsp+98h] [rbp-8h]

  v10 = __readfsqword(0x28u);
  v2 = sub_404748("A71A68ECD82711CC8C9B16155CD2673E82ADCE75D4BC5756C28A52B86BD6CCF8A4BA722FE05715B92411");
  v8 = sub_401B01(v2 >> 1);
  for ( i = 0;
        i < (unsigned __int64)sub_404748("A71A68ECD82711CC8C9B16155CD2673E82ADCE75D4BC5756C28A52B86BD6CCF8A4BA722FE05715B92411") >> 1;
        ++i )
  {
    sub_40202D((__int64)&aA71a68ecd82711[2 * i], (__int64)"%02x", i + v8);
  }
  sub_401F8D("Welcome to MoeCTF 2024!");
  sub_401F8D("This is a simple RC4 challenge.");
  sub_401ECD((__int64)"Enter your flag: ");
  sub_401BCC(&unk_40E120);
  sub_401D17(v9, 64LL, &unk_40E020);
  v9[sub_40469F(v9, "\n")] = 0;
  v3 = sub_404748(v9);
  v6 = sub_401B01(4 * v3);
  sub_401360("RC4_1s_4w3s0m3", v9, v6);
  v4 = sub_404748(v9);
  if ( (unsigned int)sub_404679(v6, v8, v4) )
    sub_401F8D("Wrong!");
  else
    sub_401F8D("Correct!");
  if ( __readfsqword(0x28u) != v10 )
    sub_40183E();
  return 0LL;
}
```
显然题目说了是Rc4，并且```RC4_1s_4w3s0m3```很可能是密码，我们直接拿上面的HEX进行解密就出了。
```python
print(rc4_crypt(rc4_init(b"RC4_1s_4w3s0m3"), bytes.fromhex('A71A68ECD82711CC8C9B16155CD2673E82ADCE75D4BC5756C28A52B86BD6CCF8A4BA722FE05715B92411')))
# b'moectf{why_Rc4_haS_The_Rev32sabl3_pr0ceSS}'

'''
from regadgets import *
Internal Functions Of Regadgets
'''
from typing import List, Iterator
def rc4_init(key: bytes, box_size: int = 256) -> List[int]:
    if type(key) == str:
        key = key.encode()
    s = list(range(box_size))
    j = 0
    key_length = len(key)

    # Key scheduling algorithm (KSA)
    for i in range(box_size):
        # permit key is empty.
        j = (j + s[i] + 0 if key_length == 0 else j + s[i] + key[i % key_length]) % box_size
        # Swap s[i], s[j]
        s[i], s[j] = s[j], s[i]

    return s

def rc4_crypt(s: bytes, data: bytes, box_size: int = 256) -> bytes:
    i, j = 0, 0
    result = bytearray()

    # Pseudo-random generation algorithm (PRGA)
    for k in range(len(data)):
        i = (i + 1) %  box_size
        j = (j + s[i]) % box_size

        # Swap s[i], s[j]
        s[i], s[j] = s[j], s[i]

        t = (s[i] + s[j]) % box_size
        result.append(data[k] ^ s[t])

    return bytes(result)
'''
Internal Functions Of Regadgets
'''
```python

# xxtea
给出题目源码
```c
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#define DELTA 0x9e3779b9
#define MX (((z>>5^y<<2) + (y>>3^z<<4)) ^ ((sum^y) + (key[((p&3)^e)&0xff] ^ z)))

void btea(uint32_t* v, int n, const uint32_t key[4])
{
    uint32_t y, z, sum;
    unsigned p, rounds, e;
    if (n > 1)            /* Coding Part */
    {
        rounds = 6 + 52 / n;
        sum = 0;
        z = v[n - 1];
        do
        {
            sum += DELTA;
            e = (sum >> 2) & 3;
            for (p = 0; p < n - 1; p++)
            {
                y = v[p + 1];
                z = v[p] += MX;
            }
            y = v[0];
            z = v[n - 1] += MX;
        } while (--rounds);
    }
    else if (n < -1)      /* Decoding Part */
    {
        n = -n;
        rounds = 6 + 52 / n;
        sum = rounds * DELTA;
        y = v[0];
        do
        {
            e = (sum >> 2) & 3;
            for (p = n - 1; p > 0; p--)
            {
                z = v[p - 1];
                y = v[p] -= MX;
            }
            z = v[n - 1];
            y = v[0] -= MX;
            sum -= DELTA;
        } while (--rounds);
    }
}
int main() {
    unsigned char enc[] = { 0x64,0xf5,0xe1,0x78,0xe1,0xf0,
0x35,0xa8,0x34,0xff,0x12,0x05,
0xfb,0x13,0xe9,0xb0,0x50,0xa3,
0xb9,0x89,0xb1,0xda,0x43,0xc9,
0x4f,0xc8,0xdb,0x01,0x20,0xdb,
0x16,0xaf,0xed,0x67,0x17,0x96
    };
    int r = 9;
    unsigned char input_key[13] = "moectf2024!!"; 
    const uint32_t k[4] = { *((uint32_t*)input_key),*((uint32_t*)(input_key + 4)), *((uint32_t*)(input_key + 8)),0xccffbbbb };
    btea(((uint32_t*)enc),-r,k);
    //btea(((uint32_t*)input), -r, ((uint32_t*)input_key));
    for (int i = 0; i < 36; i++) {
        printf("%c",enc[i]);
    }
    return 0;
}
```
EXP:
```cpp
#include <stdio.h>
#include <string.h>
#include <stdint.h>



#define DELTA 0x9e3779b9
#define MX (((z>>5^y<<2) + (y>>3^z<<4)) ^ ((sum^y) + (key[((p&3)^e)&0xff] ^ z)))

void btea(uint32_t* v, int n, const uint32_t key[4])
{
    uint32_t y, z, sum;
    unsigned p, rounds, e;
    if (n > 1)            /* Coding Part */
    {
        rounds = 6 + 52 / n;
        sum = 0;
        z = v[n - 1];
        do
        {
            sum += DELTA;
            e = (sum >> 2) & 3;
            for (p = 0; p < n - 1; p++)
            {
                y = v[p + 1];
                z = v[p] += MX;
            }
            y = v[0];
            z = v[n - 1] += MX;
        } while (--rounds);
    }
    else if (n < -1)      /* Decoding Part */
    {
        n = -n;
        rounds = 6 + 52 / n;
        sum = rounds * DELTA;
        y = v[0];
        do
        {
            e = (sum >> 2) & 3;
            for (p = n - 1; p > 0; p--)
            {
                z = v[p - 1];
                y = v[p] -= MX;
            }
            z = v[n - 1];
            y = v[0] -= MX;
            sum -= DELTA;
        } while (--rounds);
    }
}
int main() {
    unsigned char enc[] = { 0x64,0xf5,0xe1,0x78,0xe1,0xf0,
0x35,0xa8,0x34,0xff,0x12,0x05,
0xfb,0x13,0xe9,0xb0,0x50,0xa3,
0xb9,0x89,0xb1,0xda,0x43,0xc9,
0x4f,0xc8,0xdb,0x01,0x20,0xdb,
0x16,0xaf,0xed,0x67,0x17,0x96
    };
    int r = 9;
    unsigned char input_key[13] = "moectf2024!!"; // Adjusted size to fit 12 characters + null terminator
    
    const uint32_t k[4] = { *((uint32_t*)input_key),*((uint32_t*)(input_key + 4)), *((uint32_t*)(input_key + 8)),0xccffbbbb };
    btea(((uint32_t*)enc),-r,k);
    //moectf{j9h8hg75nky6vhkslh5v5awibr4i}
    //btea(((uint32_t*)input), -r, ((uint32_t*)input_key));
    for (int i = 0; i < 36; i++) {
        printf("%c",enc[i]);
    }
    return 0;
}
```
选手只需要在网上找到xxtea实现并且对照逆向即可。
```moectf{j9h8hg75nky6vhkslh5v5awibr4i}```

# TEA
本题是标准的TEA（难度低于XTEA和XXTEA），选手只需要打开IDA找到v = {0x284c2234, 0x3910c558}, k = "base64xorteaxtea"，再通过观察，对比程序内TEA和正常TEA逻辑相同，故写出解密脚本：
```cpp
#include <iostream>
#include <stdint.h>

void decrypt(uint32_t* v, uint32_t* k) {
        uint32_t v0 = v[0], v1 = v[1];
        uint32_t delta = 0x9e3779b9;
        uint32_t sum = delta * 32;
        uint32_t k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3];

        for (int i = 0; i < 32; i++) {
                v1 -= ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
                v0 -= ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
                sum -= delta;
        }

        v[0] = v0;
        v[1] = v1;
}


int main()
{
        uint32_t v[2]; uint32_t v2;
        v[0] = 0x284c2234;
        v[1] = 0x3910c558;
        decrypt(v, (uint32_t*)"base64xorteaxtea");
        printf("moectf{%x-", v[0]);
        printf("%x-", v[1] >> 16 );
        printf("%x-9c42-caf30620caaf}", v[1] & 0xffff);
        return 0;
}
```
```moectf{836153a5-8e00-49bd-9c42-caf30620caaf}```

# 逆向工程进阶之北
这个指北中的问题是，如何求解乘法逆元。
我们使用Python的库pycryptodome3
```python
>>> from Crypto.Util.number import *
>>> inverse(0xccffbbbb, 0xffffffff+1) 
2371998067
```
很容易就可以求得乘法逆元，注意的是要+1，是因为0xffffffff范围内还有0，而模数（第二个参数）取决于有限域的大小而不是最大值。
EXP
```cpp
void flag_decryption()
{
        DWORD flag[12] = { 0xb5073388 , 0xf58ea46f , 0x8cd2d760 , 0x7fc56cda , 0x52bc07da , 0x29054b48 , 0x42d74750 , 0x11297e95 , 0x5cf2821b , 0x747970da , 0x64793c81, 0x00000000 };
        for (int i = 0; i < 11; i++)
        {
                *(flag + i) ^= 0xdeadbeef + 0xd3906;
                *(flag + i) -= 0xdeadc0de;
                *(flag + i) *= 2371998067; // 0xccffbbbb 的乘法逆元（在mod 0xffffffff+1下） Ref: https://zh.planetcalc.com/3311/
        }

        std::cout << (unsigned char*)flag << std::endl;

        // moectf{c5f44c32-cbb9-444e-aef4-c0fa7c7a6b7a}
}
```
```moectf{c5f44c32-cbb9-444e-aef4-c0fa7c7a6b7a}```

# moedaily
题目实现了一个Excel表格，利用其中的Function功能实现了一个TEA加密。
在表单可以发现有s3cr3t，进去后可以看到满屏的计算过程
进行分析，发现是密码为 114514 1919810 415144 19883
偏移为114514的标准TEA加密，而且加密了两次。
回到第一页，找到判断条件
```text
=IF(LEN(D11)=48,IF(AND(AND(AND(AND(AND(AND(H14=1397140385,I14=2386659843),AND(H15=962571399,I15=3942687964)),AND(H16=3691974192,I16=863943258)),AND(H17=216887638,I17=3212824238)),AND(H18=3802077983,I18=1839161422)),AND(H19=1288683919,I19=3222915626)),"恭喜你，拿到了真的FLAG","FLAG输入错了，再试试"),"flag长度不对")
```
可以得到结论
```text
H14=1397140385,I14=2386659843
H15=962571399,I15=3942687964
H16=3691974192,I16=863943258
H17=216887638,I17=3212824238
H18=3802077983,I18=1839161422
H19=1288683919,I19=3222915626
```
带入TEA可以得到（注意程序进行了两次TEA加密）
```moectf{3xC3l_1S_n0t_just_f0r_d41ly_w0rk_bu7_R3V}```

# moejvav
题目是在Java下的简单虚拟机（vm）逆向工程。
稍微分析一下，得到下面的结论
| Step | Instruction       |
|------|-------------------|
| 0    | getByte           |
| 1    | xor store, p1     |
| 2    | add store, p1     |
| 3    | sub store, p1     |
| 4    | shl store, p1     |
| 5    | or store, p1      |
| 6    | check store, p1   |
| 7    | Exit              |
把VM的Insn进行排列
```text
0 1 60 2 -20 6 -25
0 1 60 2 -20 6 -27
0 1 60 2 -20 6 -33
0 1 60 2 -20 6 -31
0 1 60 2 -20 6 -50
0 1 60 2 -20 6 -36
0 1 60 2 -20 6 -39
0 1 60 2 -20 6 -24
0 1 60 2 -20 6 -52
0 1 60 2 -20 6 -29
0 1 60 2 -20 6 -52
0 1 14 2 5 6 -64
0 1 14 2 5 6 -58
0 1 14 2 5 6 -63
0 1 14 2 5 6 -52
0 1 14 2 5 6 -90
0 1 14 2 5 6 -39
0 1 14 2 5 6 -43
0 1 14 2 5 6 26
0 1 14 2 5 6 25
0 1 14 2 5 6 -49
0 1 14 2 5 6 -64
0 1 10 2 5 6 -51
0 1 10 2 5 6 25
0 1 10 2 5 6 -45
0 1 10 2 5 6 -55
0 1 10 2 5 6 -47
0 1 10 2 5 6 24
0 1 10 2 5 6 -41
0 1 10 2 5 6 -60
0 1 10 2 5 6 22
0 1 10 2 5 6 -40
0 1 10 2 5 6 -60
0 2 14 2 10 6 -15
0 2 14 2 10 6 50
0 2 14 2 10 6 -51
0 2 14 2 10 6 -31
0 2 14 2 10 6 50
0 2 14 2 10 6 50
0 2 14 2 10 6 -35
0 2 14 2 10 6 50
0 2 14 2 10 6 -35
0 2 14 2 10 6 51
0 2 14 2 10 6 -17
```
这里我们使用Z3-Solver进行约束求解
```python
from z3 import *
import copy
x = [BitVec(f"x{i}", 8) for i in range(44)]
y = copy.deepcopy(x)
for i in range(len(x)):
   x[i] ^= 0xca
   x[i] += 0x20

s = Solver()

ans1 = [-25,-27,-33,-31,-50,-36,-39,-24,-52,-29,-52]
for i in range(0, 11):
   s.add((x[i] ^ 60) - 20 == ans1[i]) 

ans2 = [-64,-58,-63,-52,-90,-39,-43,26,25,-49,-64]
for i in range(0, 11):
   s.add((x[11 + i] ^ 14) + 5 == ans2[i]) 

ans3 = [-51,25,-45,-55,-47,24,-41,-60,22,-40,-60]
for i in range(0, 11):
   s.add((x[22 + i] ^ 10) + 5 == ans3[i]) 

ans4 = [-15,50,-51,-31,50,50,-35,50,-35,51,-17]
for i in range(0, 11):
   s.add((x[33 + i] + 14) + 10 == ans4[i]) 

print(s.check())
m = s.model()
for i in y:
   print(chr(m[i].as_long()), end='') 
# sat
# moectf{jvav_eXcEpt10n_h4ndl3r_1s_s0_c00o0o1}
```
```moectf{jvav_eXcEpt10n_h4ndl3r_1s_s0_c00o0o1}```

# sm4
题目头文件
```c
#ifndef _SM4_H_
#define _SM4_H_
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define u8 unsigned char
#define u32 unsigned long

void four_uCh2uLong(u8 *in, u32 *out);             //四字节转换成u32

void uLong2four_uCh(u32 in, u8 *out);              //u32转换成四字节

unsigned long move(u32 data, int length);          //左移，保留丢弃位放置尾部

unsigned long func_key(u32 input);                 //先使用Sbox进行非线性变化，再将线性变换L置换为L'

unsigned long func_data(u32 input);                //先使用Sbox进行非线性变化，再进行线性变换L

void print_hex(u8 *data, int len);                 //无符号字符数组转16进制打印

void encode_fun(u8 len,u8 *key, u8 *input, u8 *output);   //加密函数

void decode_fun(u8 len,u8 *key, u8 *input, u8 *output);   //解密函数

/******************************定义系统参数FK的取值****************************************/
const u32 TBL_SYS_PARAMS[4] = {
        0xa3b1bac6,
        0x56aa3350,
        0x677d9197,
        0xb27022dc
};

/******************************定义固定参数CK的取值****************************************/
const u32 TBL_FIX_PARAMS[32] = {

    0x00070e15,0x1c232a31,0x383f464d,0x545b6269,
        0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
        0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,
        0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
        0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,
        0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
        0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,
        0x10171e25,0x2c333a41,0x484f565d,0x646b7279
};

/******************************SBox参数列表****************************************/
const u8 TBL_SBOX[256] = {

    0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
        0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
        0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
        0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
        0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
        0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
        0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
        0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
        0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
        0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
        0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
        0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
        0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
        0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
        0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
        0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48
};

#endif
```
主程序
```c
#include "sm4.h"


//4字节无符号数组转无符号long型
void four_uCh2uLong(u8 *in, u32 *out)
{
        int i = 0;
        *out = 0;
        for (i = 0; i < 4; i++)
                *out = ((u32)in[i] << (24 - i * 8)) ^ *out;
}

//无符号long型转4字节无符号数组
void uLong2four_uCh(u32 in, u8 *out)
{
        int i = 0;
        //从32位unsigned long的高位开始取
        for (i = 0; i < 4; i++)
                *(out + i) = (u32)(in >> (24 - i * 8));
}

//左移，保留丢弃位放置尾部
u32 move(u32 data, int length)
{
        u32 result = 0;
        result = (data << length) ^ (data >> (32 - length));

        return result;
}

//秘钥处理函数,先使用Sbox进行非线性变化，再将线性变换L置换为L'
u32 func_key(u32 input)
{
        int i = 0;
        u32 ulTmp = 0;
        u8 ucIndexList[4] = { 0 };
        u8 ucSboxValueList[4] = { 0 };
        uLong2four_uCh(input, ucIndexList);
        for (i = 0; i < 4; i++)
        {
                ucSboxValueList[i] = TBL_SBOX[ucIndexList[i]];
        }
        four_uCh2uLong(ucSboxValueList, &ulTmp);
        ulTmp = ulTmp ^ move(ulTmp, 13) ^ move(ulTmp, 23);

        return ulTmp;
}

//加解密数据处理函数,先使用Sbox进行非线性变化，再进行线性变换L
u32 func_data(u32 input)
{
        int i = 0;
        u32 ulTmp = 0;
        u8 ucIndexList[4] = { 0 };
        u8 ucSboxValueList[4] = { 0 };
        uLong2four_uCh(input, ucIndexList);
        for (i = 0; i < 4; i++)
        {
                ucSboxValueList[i] = TBL_SBOX[ucIndexList[i]];
        }
        four_uCh2uLong(ucSboxValueList, &ulTmp);
        ulTmp = ulTmp ^ move(ulTmp, 2) ^ move(ulTmp, 10) ^ move(ulTmp, 18) ^ move(ulTmp, 24);

        return ulTmp;
}

//加密函数（可以加密任意长度数据，16字节为一次循环，不足部分补0凑齐16字节的整数倍）
//len:数据长度(任意长度数据) key:密钥（16字节） input:输入的原始数据 output:加密后输出数据
void encode_fun(u8 len,u8 *key, u8 *input, u8 *output)
{
        int i = 0,j=0; 
        u8 *p = (u8 *)malloc(50);      //定义一个50字节缓存区
        u32 ulKeyTmpList[4] = { 0 };   //存储密钥的u32数据
        u32 ulKeyList[36] = { 0 };     //用于密钥扩展算法与系统参数FK运算后的结果存储
        u32 ulDataList[36] = { 0 };    //用于存放加密数据

        /***************************开始生成子秘钥********************************************/
        four_uCh2uLong(key, &(ulKeyTmpList[0]));
        four_uCh2uLong(key + 4, &(ulKeyTmpList[1]));
        four_uCh2uLong(key + 8, &(ulKeyTmpList[2]));
        four_uCh2uLong(key + 12, &(ulKeyTmpList[3]));

        ulKeyList[0] = ulKeyTmpList[0] ^ TBL_SYS_PARAMS[0];
        ulKeyList[1] = ulKeyTmpList[1] ^ TBL_SYS_PARAMS[1];
        ulKeyList[2] = ulKeyTmpList[2] ^ TBL_SYS_PARAMS[2];
        ulKeyList[3] = ulKeyTmpList[3] ^ TBL_SYS_PARAMS[3];

        for (i = 0; i < 32; i++)             //32次循环迭代运算
        {
                //5-36为32个子秘钥
                ulKeyList[i + 4] = ulKeyList[i] ^ func_key(ulKeyList[i + 1] ^ ulKeyList[i + 2] ^ ulKeyList[i + 3] ^ TBL_FIX_PARAMS[i]);
        }
        /***********************************生成32轮32位长子秘钥结束**********************************/

        for (i = 0; i < len; i++)        //将输入数据存放在p缓存区
                *(p + i) = *(input + i);
        for (i = 0; i < 16-len % 16; i++)//将不足16位补0凑齐16的整数倍
                *(p + len + i) = 0;

        for (j = 0; j < len / 16 + ((len % 16) ? 1:0); j++)  //进行循环加密,并将加密后数据保存（可以看出此处是以16字节为一次加密，进行循环，即若16字节则进行一次，17字节补0至32字节后进行加密两次，以此类推）
        {
                /*开始处理加密数据*/
                four_uCh2uLong(p + 16 * j, &(ulDataList[0]));
                four_uCh2uLong(p + 16 * j + 4, &(ulDataList[1]));
                four_uCh2uLong(p + 16 * j + 8, &(ulDataList[2]));
                four_uCh2uLong(p + 16 * j + 12, &(ulDataList[3]));
                //加密
                for (i = 0; i < 32; i++)
                {
                        ulDataList[i + 4] = ulDataList[i] ^ func_data(ulDataList[i + 1] ^ ulDataList[i + 2] ^ ulDataList[i + 3] ^ ulKeyList[i + 4]);
                }
                /*将加密后数据输出*/
                uLong2four_uCh(ulDataList[35], output + 16 * j);
                uLong2four_uCh(ulDataList[34], output + 16 * j + 4);
                uLong2four_uCh(ulDataList[33], output + 16 * j + 8);
                uLong2four_uCh(ulDataList[32], output + 16 * j + 12);
        }
}

//解密函数（与加密函数基本一致，只是秘钥使用的顺序不同，即把钥匙反着用就是解密）
//len:数据长度 key:密钥 input:输入的加密后数据 output:输出的解密后数据
void decode_fun(u8 len,u8 *key, u8 *input, u8 *output)
{
        int i = 0,j=0;
        u32 ulKeyTmpList[4] = { 0 };//存储密钥的u32数据
        u32 ulKeyList[36] = { 0 };  //用于密钥扩展算法与系统参数FK运算后的结果存储
        u32 ulDataList[36] = { 0 }; //用于存放加密数据

        /*开始生成子秘钥*/
        four_uCh2uLong(key, &(ulKeyTmpList[0]));
        four_uCh2uLong(key + 4, &(ulKeyTmpList[1]));
        four_uCh2uLong(key + 8, &(ulKeyTmpList[2]));
        four_uCh2uLong(key + 12, &(ulKeyTmpList[3]));

        ulKeyList[0] = ulKeyTmpList[0] ^ TBL_SYS_PARAMS[0];
        ulKeyList[1] = ulKeyTmpList[1] ^ TBL_SYS_PARAMS[1];
        ulKeyList[2] = ulKeyTmpList[2] ^ TBL_SYS_PARAMS[2];
        ulKeyList[3] = ulKeyTmpList[3] ^ TBL_SYS_PARAMS[3];

        for (i = 0; i < 32; i++)             //32次循环迭代运算
        {
                //5-36为32个子秘钥
                ulKeyList[i + 4] = ulKeyList[i] ^ func_key(ulKeyList[i + 1] ^ ulKeyList[i + 2] ^ ulKeyList[i + 3] ^ TBL_FIX_PARAMS[i]);
        }
        /*生成32轮32位长子秘钥结束*/

        for (j = 0; j < len / 16; j++)  //进行循环加密,并将加密后数据保存
        {
                /*开始处理解密数据*/
                four_uCh2uLong(input + 16 * j, &(ulDataList[0]));
                four_uCh2uLong(input + 16 * j + 4, &(ulDataList[1]));
                four_uCh2uLong(input + 16 * j + 8, &(ulDataList[2]));
                four_uCh2uLong(input + 16 * j + 12, &(ulDataList[3]));

                //解密
                for (i = 0; i < 32; i++)
                {
                        ulDataList[i + 4] = ulDataList[i] ^ func_data(ulDataList[i + 1] ^ ulDataList[i + 2] ^ ulDataList[i + 3] ^ ulKeyList[35 - i]);//与加密唯一不同的就是轮密钥的使用顺序
                }
                /*将解密后数据输出*/
                uLong2four_uCh(ulDataList[35], output + 16 * j);
                uLong2four_uCh(ulDataList[34], output + 16 * j + 4);
                uLong2four_uCh(ulDataList[33], output + 16 * j + 8);
                uLong2four_uCh(ulDataList[32], output + 16 * j + 12);
        }
}

//无符号字符数组转16进制打印
void print_hex(u8 *data, int len)
{
        int i = 0;
        char alTmp[16] = { '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f' };
        for (i = 0; i < len; i++)
        {
                printf("%c", alTmp[data[i] / 16]);
                printf("%c", alTmp[data[i] % 16]);
        putchar(' ');
        }
        putchar('\n');
}
/*在主函数中实现任意字节加密与解密，并且结果正确*/
int main(void)
{
        u8 i,len;
        u8 encode_Result[50] = { 0 };    //定义加密输出缓存区
        u8 decode_Result[50] = { 0 };    //定义解密输出缓存区
        u8 key[16] = { 0x74,0x68,0x65,0x6b,0x65,0x79,0x74,0x6f,0x73,0x6f,0x6d,0x65,0x74,0x68,0x69,0x6e };       //定义16字节的密钥
    /*u8 Data_plain[45]={0x6d,0x6f,0x65,0x63,0x74,0x66,
                             0x7b,0x43,0x6f,0x6e,0x67,0x72,
                                                 0x61,0x74,0x75,0x6c,0x61,0x74,
                                                 0x69,0x6f,0x6e,0x73,0x5f,0x79,
                                                 0x6f,0x75,0x5f,0x61,0x72,0x65,
                                                 0x5f,0x61,0x6e,0x5f,0x53,0x4d,
                                                 0x34,0x5f,0x6d,0x61,0x73,0x74,
                                                 0x65,0x72,0x21,0x21,0x21,0x7d};//moectf{Congratulations_you_are_an_SM4_master!!!}*/
        u8 Data_plain[48]={0};
        printf("please input your flag:\n");
        scanf("%s",Data_plain);
        len = 16 * (sizeof(Data_plain) / 16) + 16 * ((sizeof(Data_plain) % 16) ? 1 : 0);

        encode_fun(sizeof(Data_plain),key, Data_plain, encode_Result);            //数据加密
        //printf("加密后数据是：\n");
        //for (i = 0; i < len ; i++)
        //        printf("0x%x,", *(encode_Result + i));
        u8 enc[48]={0xad,0x6c,0xcd,0xc1,0x9,0xfc,0xdd,0xef,0x83,0xae,0x93,0x8,0x53,0x8e,0xc5,0x37,0x5c,0xdd,0x1b,0x4b,0x3,0x99,0x19,0xa2,0x69,0x24,0x96,0x42,0x77,0xc1,0x27,0x5f,0x2d,0xd4,0x5d,0xf5,0x2b,0xb0,0x32,0xf7,0xa5,0x97,0xc6,0x8a,0xee,0x48,0xae,0x93};                
        decode_fun(len,key, encode_Result, decode_Result);      //数据解密
        printf("解密后数据是：\n");
        for (i = 0; i < len; i++)
            printf("%x ", *(decode_Result + i)); 
        for(i=0;i<48;i++)
        {
                if(enc[i]!=*(encode_Result+i))
                {
                        printf("Wrong!");
                        exit(0);
                }
        }
        printf("Congratulations");
        system("pause");
        return 0;
}

```
是从网上找到的SM4加密实现，但是程序在输入的时候，使用了scanf并且当你输入正确的flag长度的时候，最后一个是0字符截断，他会覆盖下一个变量的首字节，刚好下一个变量是key，所以key的首字节变成了0，导致很多人解不出来，其实只要输入一个正确长度的flag就可以进行解密。
```moectf{Congratulations_you_are_an_SM4_master!!!}```

# ezMAZE
题目使用了OI常用技巧——状态压缩来存储迷宫，使用二进制的1和0代表是否可以通过。
题目源码
```c
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

char buf[1177] = { 0 };
unsigned char theMaze[56][10] = {
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xbf,0xff,0xea,0xa8,0xa4,0x92,0x4f,0xff,0xff,0xff,
        0x80,0x00,0x3d,0x14,0x94,0x92,0xb8,0x00,0x00,0xff,
        0xff,0xff,0xbb,0xda,0x1f,0x29,0x7b,0xff,0xfe,0xff,
        0xc0,0x00,0x3b,0xda,0xdc,0x00,0x03,0x00,0x00,0xff,
        0xdf,0xff,0xfb,0xda,0xdd,0xff,0xff,0x7f,0xff,0xff,
        0xc0,0x00,0x3b,0xda,0xdc,0x00,0x03,0x00,0x00,0xff,
        0xff,0xff,0xb8,0x42,0x1f,0xff,0xfb,0xff,0xfe,0xff,
        0xc0,0x00,0x3f,0xff,0xfc,0x00,0x03,0x00,0x00,0xff,
        0xdf,0xff,0xf8,0x7c,0x3d,0xff,0xff,0x7f,0xff,0xff,
        0xc0,0x00,0x3b,0xfd,0xbc,0x00,0x03,0x00,0x3e,0x1f,
        0xff,0xff,0xb8,0x7c,0x7f,0xff,0xfb,0xff,0xbe,0xdf,
        0xff,0xff,0xbf,0x7d,0xbd,0x29,0x7b,0xff,0xbe,0xdf,
        0xff,0xff,0x98,0x7c,0x3f,0xff,0xfb,0xff,0xbe,0xdf,
        0x80,0x00,0x4f,0xff,0xf8,0x00,0x02,0x00,0x3e,0xdf,
        0xbf,0x7f,0x6f,0xff,0xfb,0xff,0xfe,0xff,0xfe,0xdf,
        0x96,0xab,0x60,0x00,0x08,0x00,0x02,0x01,0xfe,0xdf,
        0x96,0xab,0x7f,0xff,0xef,0xff,0xfb,0xfd,0xfe,0xdf,
        0x95,0x4b,0x70,0x00,0x0c,0x00,0x03,0x01,0xfe,0xdf,
        0x95,0x4b,0x77,0xff,0xfd,0xff,0xff,0x7f,0xfe,0xdf,
        0xaa,0x96,0x70,0x00,0x0c,0x00,0x03,0x00,0x06,0xdf,
        0x92,0x57,0x7f,0xff,0xef,0xff,0xfb,0xff,0xf6,0xdf,
        0x92,0x94,0x70,0x00,0x0c,0x00,0x03,0x00,0x06,0xdf,
        0x8a,0x4b,0x77,0xff,0xfd,0xff,0xff,0x7f,0xfe,0xdf,
        0xae,0xd5,0x70,0x00,0x0c,0x00,0x03,0x00,0x0e,0xdf,
        0x95,0x4a,0xff,0xff,0xef,0xff,0xfb,0xff,0xee,0xdf,
        0x8a,0x4a,0x4a,0x50,0xec,0x00,0x03,0xff,0xee,0xdf,
        0xbf,0x7f,0x7f,0xff,0xe1,0xff,0xff,0xff,0xee,0xdf,
        0xff,0xff,0xf5,0x5d,0x7f,0xff,0xff,0xff,0xee,0xdf,
        0x80,0x00,0x38,0xd5,0x35,0x2a,0x98,0x00,0x0e,0xdf,
        0xbf,0xff,0xbd,0x51,0x2f,0xff,0xfb,0xff,0xfe,0xdf,
        0xa0,0x00,0x3f,0xff,0xfc,0x00,0x03,0x00,0x00,0xdf,
        0xaf,0xff,0xff,0xc0,0x7d,0xff,0xff,0x7f,0xff,0xdf,
        0xa0,0x00,0x3f,0xdf,0x7c,0x00,0x03,0x00,0x00,0xdf,
        0xbf,0xff,0xbf,0xdf,0x7f,0xff,0xfb,0xff,0xfe,0xdf,
        0xa0,0x00,0x3f,0xdf,0x7c,0x00,0x03,0x00,0x00,0xdf,
        0xaf,0xff,0xff,0xdf,0x7d,0xff,0xff,0x7f,0xff,0xdf,
        0xa0,0x00,0x3f,0xdf,0x7c,0x00,0x03,0x00,0x00,0xdf,
        0xbf,0xff,0xbf,0xdf,0x7f,0xff,0xfb,0xff,0xfe,0xdf,
        0xbc,0x8b,0xbf,0xdf,0x7f,0xff,0xfb,0xff,0xfe,0xdf,
        0xa9,0x24,0x9f,0xdf,0x7f,0xff,0xfb,0xff,0xfe,0x5f,
        0xb2,0xa1,0xcf,0xdf,0x78,0x00,0x02,0x00,0x03,0x5f,
        0xb1,0x52,0xef,0xdf,0xfb,0xff,0xfe,0xff,0xfb,0x5f,
        0xaa,0x22,0xe0,0x00,0x08,0x00,0x02,0x01,0xf8,0x5f,
        0xbd,0x29,0xff,0xff,0xef,0xff,0xfb,0xfd,0xff,0xdf,
        0xb2,0x52,0xb0,0x00,0x0c,0x00,0x03,0x01,0xff,0xdf,
        0xb4,0x94,0xb7,0xff,0xfd,0xff,0xff,0x7f,0xff,0xdf,
        0xb2,0x4a,0xb0,0x00,0x0c,0x00,0x03,0x00,0x00,0xdf,
        0xb2,0x52,0x5f,0xff,0xef,0xff,0xfb,0xff,0xfe,0xdf,
        0xb2,0x54,0xd0,0x00,0x0c,0x00,0x03,0x00,0x00,0xdf,
        0xb2,0x52,0x57,0xff,0xfd,0xff,0xff,0x7f,0xff,0xdf,
        0xb2,0x91,0x30,0x00,0x00,0x00,0x0f,0x00,0x00,0xdf,
        0xb0,0x89,0x7f,0xff,0xff,0xff,0xf8,0x7f,0xfe,0xdf,
        0xbc,0x91,0x10,0xff,0xe0,0x00,0x03,0xff,0xfe,0xdf,
        0x80,0x00,0x00,0x00,0x0d,0xff,0xfe,0x94,0x8a,0x5f,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
};

int checkForMaze(int x, int y)
{
        unsigned char val;
        // 1 means cannot pass.

        if (x > 10 * 8 || y > 56 || x < 1 || y < 1) return 1;
        val = theMaze[y - 1][(x - 1) / 8];
        theMaze[y - 1][(x - 1) / 8] = val | (1 << (7 - ((x - 1) % 8)));
        return ((val >> (7 - ((x - 1) % 8))) & 1);
}

char* calculateFlag(char* buf)
{
        unsigned long long sumOf;
        char* flag;
        flag = (char*)malloc(128);
        memcpy_s(flag, 40, "moectf{", 7);
        sumOf = 0;
        for (int i = 0; i < 1176; i++)
        {
                sumOf += (buf[i] * 3113131 * i + i * i + 0x114514) & 0xffffffffffffffff;
        }
        snprintf(flag + 7, 128 - 8, "the_%llu_amazing_maze!!}", sumOf);
        return flag;
}


int main()
{
        char* result;
        int x, y, i;
        printf("M0EC7F-2024 ezMaze\n");
        printf("ohno I'v stuck in a M4Z3... h3lp me (use w,a,s,d)\n");
        x = 2;
        y = 2;
        printf("please input the path sequence...\n");
        if (!scanf_s("%1177s", buf, 1177))
        {
                printf("input err.\n");
                return -1;
        }
        i = 0;
        while (1)
        {
                printf("\rx =%3d, y =%3d", x, y);
                if (x == 75 && y == 55)
                {
                        printf("\n%s\n", buf);
                        result = calculateFlag(buf);
                        printf("\nYOU WIN!!! the flag is %s\n", result);
                        free(result);
                        system("pause");
                        return 0;
                }
                if (!buf[i])
                {
                        printf("\nmission failed..\n");
                        return -1;
                }
                switch (buf[i++])
                {
                case 'w':
                        if (y > 1 && !checkForMaze(x, y - 1)) y -= 1;
                        else printf("You cannot walk the same path!!\n");
                        break;
                case 's':
                        if (y < 56 && !checkForMaze(x, y + 1)) y += 1;
                        else printf("You cannot walk the same path!!\n");
                        break;
                case 'a':
                        if (x > 1 && !checkForMaze(x - 1, y)) x -= 1;
                        else printf("You cannot walk the same path!!\n");
                        break;
                case 'd':
                        if (x < 10 * 8 && !checkForMaze(x + 1, y)) x += 1;
                        else printf("You cannot walk the same path!!\n");
                        break;
                default:
                        printf("you can only input w,a,s,d\n");
                        continue;
                }
        }
}
```
WP:
其一（抄出来，bfs）：
```c
using namespace std;


bool is_wall(int x, int y) {

uint8_t temp;


if (x > 80 || y > 56 || x < 1 || y < 1)
    return true;
temp = maze[10 * y - 10 + (x - 1) / 8];
maze[10 * y - 10 + (x - 1) / 8] = (1 << (7 - (x - 1) % 8)) | temp;
return ((int)temp >> (7 - (x - 1) % 8)) & 1;



}


string find_path(int begin_x, int begin_y, int end_x, int end_y) {

vector<pair<int, int>> dirs = {{0, -1}, {0, 1}, {-1, 0}, {1, 0}};

vector

<char> dir_chars = {'w', 's', 'a', 'd'};</char>




queue<tuple<int, int, string>> q;
set<pair<int, int>> visited;

q.push({begin_x, begin_y, ""});
visited.insert({begin_x, begin_y});

while (!q.empty()) {
    auto [x, y, path] = q.front();
    q.pop();

    if (x == end_x && y == end_y - 1) {
        return path;
    }
    
    for (int i = 0; i < dirs.size(); ++i) {
        int new_x = x + dirs[i].first;
        int new_y = y + dirs[i].second;

        if (!is_wall(new_x, new_y) && visited.find({new_x, new_y}) == visited.end()) {
            visited.insert({new_x, new_y});
            q.push({new_x, new_y, path + dir_chars[i]});
        }
    }
}

return nullptr;



}
```
因为那个函数其实就是判断(x,y)是否可通行，返回值也非常简单
其二（硬核爆破）
```c
import subprocess

directions = ["w", "a", "s", "d"]

def move(path) -> str:
    result = subprocess.run(["echo", path, "|", "ezMaze.exe"], shell=True, capture_output=True, text=True)
    return result.stdout

def main() -> None:
    stack = [("", (2, 2))]
    visited = set()
    visited.add((2, 2))

    while stack:
        path, (x, y) = stack.pop()
        result = move(path)

        if "YOU WIN!!! the flag is" in result:
            print(path)
            return
        
        if "You cannot walk the same path!!" in result:
            continue

        for direction in directions:
            new_path = path + direction
            new_x, new_y = x, y

            if direction == "w":
                new_y -= 1
            elif direction == "a":
                new_x -= 1
            elif direction == "s":
                new_y += 1
            elif direction == "d":
                new_x += 1

            if (new_x, new_y) not in visited:
                visited.add((new_x, new_y))
                stack.append((new_path, (new_x, new_y)))

if __name__ == "__main__":
    main()

```
其三：
先用upx脱壳，本程序由于使用了x方向的状态压缩，把01的迷宫压缩成了一个数组，并且使用位运算进行读取。
所以把迷宫抄出来，用notepad++来显示路径，即可写出答案（或者使用bfs进行路径获取）
```text
sddddddddddddddddssaaaaaaaaaaaaaaassdddddddddddddddssaaaaaaaaaaaaaaassdddddddddddddddsssdsdssddddddddddddddddssaaaaaaaaaaaaaaassdddddddddddddddssaaaaaaaaaaaaaaassdddddddddddddddsssdddwdddddddddddddddwwaaaaaaaaaaaaaaawwdddddddddddddddwwaaaaaaaaaaaaaaawwdddddddddddddddwwaaaaaaaaaaaaaaaawwddddddddddddddddwwwwaaaaaaaaaaaaaaawwdddddddddddddddwwaaaaaaaaaaaaaaawwdddddddddddddddwwddddddddddddddddddssaaaaaaaaaaaaaaassdddddddddddddddssaaaaaaaaaaaaaaassdddddddddssssaaaaaaaaaassdddddddssaaaaaassddddddddddddssaaaaaaaaaaaassdddddddddddsssssaaaaaaaaaaaaaassaaaaaaaaaaaaaaassdddddddddddddddssaaaaaaaaaaaaaaassdddddddddddddddssssaaaaaaaaaaaaaaaassddddddddddddddddssaaaaaaaaaaaaaaassdddddddddddddddssaaaaaaaaaaaaaaassaaaaaaaaaaaaaaaaaawwdddddddddddddddwwaaaaaaaaaaaaaaawwdddddddddddddddwwaaaaaaaaaaaaaaaawwawawwwaaaaaaaaaaaaaawwddddddddddddddwwaaaaaaaaaaaaaawwddddddddddddddwwaaaaaaaaaaaaaaaasssssssssssssssssssssssssddddddddddddddddddddddddddddddddddwddddddddddddddddddwdddwwwdddddddddddddddwwaaaaaaaaaaaaaaawwddddddwwaaaaaaawwddddddddddddddssdddwwwawwwaaaaaaaaaaaaaaawwdddddddddddddddwwaaaaaaaaaaaaaaawwdddddddddddddddwwwwwwwwwwwwwwwwwwwwwdddssssssssssssssssssssssssssssssssssssssssssss
```
路径是唯一解，因为不能往回走。（终点可以从程序里面拿到，是右下角最后一个0的位置）
```moectf{the_18446744024826406994_amazing_maze!!}```

# Just-Run-It
包含了四个可执行文件，这个题可以载入静态分析，获取flag，也可以仅仅RUN，获得flag
0x0 与 0x1均加了upx壳
0x0 windows下的x64执行文件，运行后
```text
moectf2024@xdsec ~> cat /flag.0
6257396c5933526d657a55355a6d45
```
0x1 linux下的x64执行文件，运行后
```text
moectf2024@xdsec ~> cat /flag.1
324d444a6a4c5459794e4745744e44
```
0x2 Android apk，安装并运行后
```text
moectf2024@xdsec ~> cat /flag.2
42694e7930345954566a4c57557a4e
```
APK源码
```kotlin
package cn.edu.xidian.myapplication

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import cn.edu.xidian.myapplication.ui.theme.MyApplicationTheme

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MyApplicationTheme {
                // A surface container using the 'background' color from the theme
                Surface(
                    color = MaterialTheme.colorScheme.background
                ) {
                    MyScreenContent()
                }
            }
        }
    }
}

@Composable
fun MyScreenContent() {
    Column(modifier = Modifier.fillMaxSize()) {
        Greeting("Android")
        render()
    }
}

@Composable
fun Greeting(name: String) {
    Text(text = "Hello moectf2024!")
}

@Composable
fun render() {
    Column {
        Text(text = "moectf2024@xdsec ~> cat /flag.2")
        Text(text = "42694e7930345954566a4c57557a4e")
    }
}

@Preview(showBackground = true)
@Composable
fun DefaultPreview() {
    MyApplicationTheme {
        MyScreenContent()
    }
}
```
0x3 riscv ELF64程序
```text
# Kali Linux 下
sudo apt install qemu-user
chmod +x ./0x3.riscv64.elf
qemu-riscv64 ./0x3.riscv64.elf
# [87, 85, 49, 78, 122, 82, 106, 90, 106, 108, 105, 79, 88, 48, 61]
```
```python
a = [87, 85, 49, 78, 122, 82, 106, 90, 106, 108, 105, 79, 88, 48, 61]
"".join(map(chr,a))
# WU1NzRjZjliOX0=
```
```text
6257396c5933526d657a55355a6d45324d444a6a4c5459794e4745744e4442694e7930345954566a4c57557a4e
bW9lY3RmezU5ZmE2MDJjLTYyNGEtNDBiNy04YTVjLWUzN
再加上最后0x3的WU1NzRjZjliOX0=
bW9lY3RmezU5ZmE2MDJjLTYyNGEtNDBiNy04YTVjLWUzNWU1NzRjZjliOX0=
base64 decode
# moectf{59fa602c-624a-40b7-8a5c-e35e574cf9b9}
```

```moectf{59fa602c-624a-40b7-8a5c-e35e574cf9b9}```

# SecretModule
Magisk Module 
Shell Script解密
然后是一点点Android知识
需要知道 getevent 命令
```bash
testk() {
  echo "Welcome to the Secret module!But before you begin,you need to prove your self."
  (/system/bin/getevent -lc 1 2>&1 | /system/bin/grep VOLUME | /system/bin/grep " DOWN" > $MODPATH/events) || return 1
  return 0
}   

choose() {
  while true; do
    /system/bin/getevent -lc 1 2>&1 | /system/bin/grep VOLUME | /system/bin/grep " DOWN" > $MODPATH/events
    if (`cat $MODPATH/events 2>/dev/null | /system/bin/grep VOLUME >/dev/null`); then
      break
    fi
  done
  if (`cat $MODPATH/events 2>/dev/null | /system/bin/grep VOLUMEUP >/dev/null`); then
    echo "114514"
  else
    echo "1919810"
  fi
}

if testk; then
  ui_print "Great! Now enter the secret."

else
  ui_print "Legacy Device. Use a newer device to do this challenge"
  exit
fi

concatenated=""

for i in 1 2 3 4 5 6 7
do
  result=$(choose)
  concatenated="${concatenated}${result}"
done

input_str=$(echo -n $concatenated | md5sum | awk '{print $1}')
sec="77a58d62b2c0870132bfe8e8ea3ad7f1"
if test $input_str = $sec
then
	echo 'You are right!Flag is'
    echo "moectf{$concatenated}"
else
    echo 'Wrong. Try again.'
	exit
fi


```
里面是一个MD5的选择爆破，用Python或者手动猜都可以。
```114514114514191981011451411451419198101919810```

# Cython-Strike: Bomb Defusion
```python
from bomb_defuse import Bomb, DefuseKit

def read_bombmemory(kit):
    processed_data = []
    for address in range(0x0, 0x400):
        try:
            data = kit.read_memory(address)
            if data != '0x0':
                #print(data)
                processed_data.append(data)
        except Exception as e:
            #print(e)
            processed_data.append('*')
    return processed_data

bomb = Bomb()
kit = DefuseKit(bomb)
print(f"Bomb State: {bomb.state}")
print(f"Bomb Mask: {bomb.mask}")
memory_data = read_bombmemory(kit)
code = ''.join(chr(int(data, 16)) if data != '*' else '*' for data in memory_data)

print(code)

password = 3786171  #60578736 >> ((7355608 % 5) + 1)
flag = bomb.enter_pwd(password)
print(f"Bomb has been defused! Counter Terrorists Win! Flag: {flag}")

#Your defusekit has successfully connected to the bomb! The wire are tangled, but you've found the bomb's inst ram!
#Scanning through the inst ram...
#We've got access to some juicy data. Time to defuse!
#tip: use read_memory method to read data from the inst ram
#Bomb State: planted
#Bomb Mask: 7355608
#de*i*e MAX_*** 0xffffff***unsign*d int ma**;***int p*ant_b**b(unsigned int input){if *input <= MAX_***) {ma** = input;r**urn 0;} e*se*{***ret**n -1;} }***void expl*de_b*m***oid)*{***void def**e_**mb(v*id){***}***check_p**d(uns*gned*int in*u*)*{if*(input*> MAX_***)*{***explode_b**b();***}***if*((in**t ^ ma** == 114) && (input << (ma** % 5) + 1 == 60578736))*{defuse_b**b();r**urn**}***explode_b**b();***retu**;***}
#Bomb defused! Flag: moectf{CoUnter_TerR0rists_w1n}
```

找我们的gpt补一下源码：
```c
#define MAX_VAL 0xffffff
unsigned int mask;

int plant_bomb(unsigned int input) {
    if (input <= MAX_VAL) {
        max = input;
        return 0;
    } else {
        return -1;
    }
}

void explode_bomb(void) {
}

void defuse_bomb(void) {
}

void check_pwd(unsigned int input) {
    if (input > MAX_VAL) {
        explode_bomb();
    }

    if (input ^ mask == 114 && ((input << ((mask % 5) + 1)) == 60578736)) {
        defuse_bomb();
        return;
    }

    explode_bomb();
    return;
}
```
- 值得注意的是 input ^ mask == 114 ，其中由于运算符优先级，右边 mask == 114 会被优先计算，很多选手都认为是题目的问题，而且python中，左边反而会被先计算...算是一个坑
```moectf{CoUnter_TerR0rists_w1n}```


# SMCProMax
SMC + 偷偷改东西 + z3使用
先动调，发现smc解密异或0x90，然后就可以patch，然后拖入IDA，可以抄出来一个类似hash的算法，但是这个算法是可以求解其输入的，我们就可以解了。
```python
from z3 import *
from Crypto.Util.number import long_to_bytes as l2b

keys = [2053092702,-490481854,-1704322843,-1418679088,86802781,987171458,965631658,264545711,-1342106783,-825370173]
x = [BitVec(f"x{i}", 32) for i in range(len(keys))]

def hash(v):
    for i in range(32):
        # 由于左移会变偶数，而xor后又会变成奇数，所以有唯一解
        v = If(v < 0 , (v << 1) ^ 0xc4f3b4b3, v << 1)
    return v

s = Solver()

for i in range(len(keys)):
    s.add(hash(x[i]) == keys[i])
s.check()
m = s.model()

result = [0] * len(keys)

for p in m.decls():
    result[int(p.name()[1:])] = m[p].as_long()
for i in result:
    print(l2b(i))

# moectf{y0u_mu5t_know_vvHAt_1s__SMC__n0w}
```
但是要注意，这是程序在后面判断flag的逻辑
在此之前，程序偷偷修改了H字符，让它异或了0x12，所以正确的flag是
```text
moectf{y0u_mu5t_know_vvZAt_1s__SMC__n0w}
真不容易啊，终于对了！！这就是逆向，豪吃，多吃。
Press any key to continue . . .
```
```moectf{y0u_mu5t_know_vvZAt_1s__SMC__n0w}```

# ezMAZE-彩蛋
接上文ezMAZE题目，在地图可以找到
```moectf{LUOSB}```

# xor(大嘘)
XOR里面藏了一个TEA，并且有花指令，ida直接看不出来。
EXP
```c
#include <iostream>

void decrypt(uint32_t* v, uint32_t* k) {
    uint32_t v0 = v[0], v1 = v[1];
    uint32_t delta = 0x9e3779b9;
    uint32_t sum = delta * 32;
    uint32_t k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3];

    for (int i = 0; i < 32; i++) {
        v1 -= ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
        v0 -= ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
        sum -= delta;
    }

    v[0] = v0;
    v[1] = v1;
}


int main()
{
    unsigned char ans[] = {
0x2B, 0xF2, 0x82, 0x41, 0x48, 0x74, 0x9D, 0xAA, 0x7E, 0x4C, 0xDA, 0x04, 0x08, 0x2C, 0xA8, 0x52,
 0x97, 0x77, 0xB7, 0x3B, 0x16, 0x2D, 0xD4, 0xFC, 0x60, 0xBE, 0xC4, 0xB6, 0x73, 0x19, 0x94, 0x87
    };
    unsigned char axxxx[] = {
0x3C, 0x0D, 0x05, 0x1F, 0x30, 0x6E, 0x1E, 0x30, 0x04, 0x3C, 0x12, 0x52, 0x59, 0x03, 0x6D, 0x52,
 0x04, 0x04, 0x0B, 0x33, 0x1F, 0x33, 0x17, 0x3B, 0x17, 0x1A, 0x2B, 0x07, 0x55, 0x04, 0x5B, 0x5A
    };
    for (int i = 0; i < 32; i++)
    {
        axxxx[i] ^= ans[i];
    }

    const char* xxx = "hello_moectf2024";

    uint32_t* v = (uint32_t*)axxxx;
    uint32_t* k = (uint32_t*)xxx;
    decrypt(v, k);
    decrypt(v+2, k);
    decrypt(v+4, k);
    decrypt(v+6, k);

    unsigned char* vv = (unsigned char*)v;
    for (int i = 0; i < 32; i++)
    {
        vv[i] ^= xxx[i % 16];
        putchar(vv[i]);
        // moectf{how_an_easy_junk_and_tea}
    }
}

```
```moectf{how_an_easy_junk_and_tea}```

# babe-z3
src
```cpp
#include <iostream>
#include <Windows.h>
int main()
{
        puts("$ root@moectf2024 ~> Welcome to moectf 2024!\n | 0xcafebabe encountered a difficult challenge!!!\n | He was lost in the z3-solver's WORLD, Please Use Your MAGIC to help him.\n | input: moectf{YOUR_INPUT}");
        char x[36]; //9c0525dcbadf4cbd9715067159453e74
        fgets(x, 36, stdin);
        uint64_t a1 = *(0 + (uint64_t*)x);
        uint64_t a2 = *(1 + (uint64_t*)x);
        uint64_t a3 = *(2 + (uint64_t*)x);
        uint64_t a4 = *(3 + (uint64_t*)x);
/*

        std::cout << (a1 & a2 & (~(a1 | a2) | a3 & a2 | a4 & a1 & ~a4) | a4 & a1 & a3) << std::endl;
        std::cout << ((a2 ^ (a4 & ~a1 | a4 & ~a3 | (a1 + a3) & a3 | (a2 + a4) & a2 & ~a1))) << std::endl;
        std::cout << ((a1 - a2) ^ (a3 - a4)) << std::endl;
        std::cout << ((a4 + a2) ^ (a1 + a3)) << std::endl;
        std::cout << (a1 ^ a2 ^ a3 ^ a4) << std::endl;
        std::cout << (a1 & a2 & a3 & a4) << std::endl;
        std::cout << (a1 + a2 - a3 + a4) * (a1 + a3 - a4 + a2) << std::endl;
        std::cout << (a1 + a2 +a3 + a4) % 114514 << std::endl;
        std::cout << (a1 * a2 * a3 * a4) % 1919810 << std::endl;

*/
        uint64_t switch_0 = 0;
        uint64_t switch_1 = 0;
        uint64_t switch_2 = 0;
        uint64_t switch_3 = 0;
        uint64_t switch_4 = 0;
        uint64_t switch_5 = 0;
        uint64_t switch_6 = 0;
        uint64_t switch_7 = 0;
        uint64_t switch_8 = 0;
        
        // FAKE CONDITION
        if ((a3 & a1 & (~(a4 + a2) | a2 & a2 | a4 & a1 & ~a4) ^ a4 & a3) == 0xcafebabedeadc0de) (switch_0 |= 0x0000000010000000);

        if ((a1 & a2 & (~(a1 | a2) | a3 & a2 | a4 & a1 & ~a4) | a4 & a1 & a3) == 2316015897844654385) switch_0 = (switch_0 |= 0x0000000100000000);
        if(((a2 ^ (a4 & ~a1 | a4 & ~a3 | (a1 + a3) & a3 | (a2 + a4) & a2 & ~a1))) == 8102257287365753684) switch_1 = 1;
        if(((a1 - a2) ^ (a3 - a4)) == 287668530830180307) switch_2 = 1;
        if(((a4 + a2) ^ (a1 + a3)) == 865433324338348261) switch_3 = 1;
        if((a1 ^ a2 ^ a3 ^ a4) == 145809558366915671) switch_4 = 1;
        if((a1 & a2 & a3 & a4) == 2314885599605039392) switch_5 = 1;
        if(((a1 + a2 - a3 + a4) * (a1 + a3 - a4 + a2)) == 1840182356754417097) switch_6 = 1;
        if((a1 + a2 + a3 + a4) % 114514 == 21761) switch_7 = 1;
        if((a1 * a2 * a3 * a4) % 1919810 == 827118) switch_8 = 1;

        DWORD fake = (DWORD)switch_0;
        if (switch_0 && switch_1 && switch_2 && switch_3 && switch_4 && switch_5 && switch_6 && switch_7 && switch_8 && !fake)
        {
                printf("Finally, You Win!!!");
        }
        else
        {
                printf("NO!! Try Again. PLEASE");
        }

}
```

这题主要的坑其实是一个64位的变量的高32位和低32位控制了两个不同的条件，最后检查的时候，分别进行了检查，致敬RCTF2024的 PPTT（同样的操作，当时被恶心了）
Exp
```python
from z3 import *
from Crypto.Util.number import *

x = [BitVec(f"x{i}", 64) for i in range(4)]
s = Solver()

a1 = x[0]
a2 = x[1]
a3 = x[2]
a4 = x[3]

# This Condition Is Fake!(!=)
s.add((a3 & a1 & (~(a4 + a2) | a2 & a2 | a4 & a1 & ~a4) ^ a4 & a3) != 0xd81ac01fbba91837)

# These Are True.
s.add((a1 & a2 & (~(a1 | a2) | a3 & a2 | a4 & a1 & ~a4) | a4 & a1 & a3) == 2316015897844654385)
s.add(((a2 ^ (a4 & ~a1 | a4 & ~a3 | (a1 + a3) & a3 | (a2 + a4) & a2 & ~a1))) == 8102257287365753684)
s.add(((a1 - a2) ^ (a3 - a4)) == 287668530830180307)
s.add(((a1 + a2 - a3 + a4) * (a1 + a3 - a4 + a2)) == 1840182356754417097)
s.add((a1 + a2 + a3 + a4) % 114514 == 21761)
s.add((a1 * a2 * a3 * a4) % 1919810 == 827118)

print(s.check())
m = s.model()
result = b""
for i in x:
    result += long_to_bytes(m[i].as_long())[::-1]
print(result)
# b'9c0525dcbadf4cbd9715067159453e74'
```
```moectf{9c0525dcbadf4cbd9715067159453e74}```

# BlackHole
根据纸条内容，我们采用LoadLibrary然后调用函数进行暴力破解即可。
这是源码
```c
extern "C" {
        __declspec(dllexport) int checkMyFlag(char* your_flag, size_t length)
        {
                if (length != 15)
                {
                        return 0;
                }
                if (memcmp(your_flag, "moectf{", 7)) return 0;
                if (your_flag[14] != '}') return 0;
                if (your_flag[7] == 'c' &&
                        your_flag[8] == 'r' &&
                        your_flag[9] == '4' &&
                        your_flag[10] == 'c' &&
                        your_flag[11] == 'k' &&
                        your_flag[12] == 'm' &&
                        your_flag[13] == '3')
                {
                        return 1;
                }

                return 0;
        }
}
```
EXP
```c
#include <iostream>
#include <Windows.h>


void bruteForce()
{
        HMODULE h = NULL;
        h = LoadLibraryA("you_cannot_crack_me.vmp.dll");
        if (!h)
        {
                printf("failed to load dll...\n");
                return;
        }
        typedef int(*checkFlag)(char*, size_t);
        char* cracking = (char*)malloc(16);
        if (!cracking) return;
        cracking[0] = 'm';
        cracking[1] = 'o';
        cracking[2] = 'e';
        cracking[3] = 'c';
        cracking[4] = 't';
        cracking[5] = 'f';
        cracking[6] = '{';

        cracking[7] = 'c';
        cracking[12] = 'm';

        cracking[14] = '}';
        cracking[15] = '\0';
        checkFlag check = (checkFlag)GetProcAddress(h, "checkMyFlag");
        for (char b = 'a'; b <= 'z'; b++)
        {
                for (char c = '0'; c <= '9'; c++)
                {
                        for (char d = 'a'; d <= 'z'; d++)
                        {
                                for (char e = 'a'; e <= 'z'; e++)
                                {
                                        for (char g = '0'; g <= '9'; g++)
                                        {
                                                cracking[8] = b;
                                                cracking[9] = c;
                                                cracking[10] = d;
                                                cracking[11] = e;
                                                cracking[13] = g;
                                                if (check(cracking, 15))
                                                {
                                                        printf("found answer: %s\n", cracking);
                                                        return;
                                                }
                                        }
                                }
                        }
                }
        }


        CloseHandle(h);
}

int main()
{
        bruteForce();
        system("pause");
        return 0;
}

```
```moectf{cr4ckm3}```

# moeprotector
考点SEH, 反调试
解法：挂上x64dbg+ScyllaHide(不要开TitanHide，有检测)，然后通过软件断点来不断追踪flag变化。
容易得到下面的伪代码
```text
flag[0]^=0x31;
flag[0]+=0x31;
flag[0]-=0x31;
flag[0]^=0x31;
for(inti=0;i<57;i++)
{
        flag[i]^=21+i;
        flag[i]+=20;
}
for(inti=0;i<57;i++)
{
        flag[i]^=26+i;
        flag[i]+=20;
}
for(inti=0;i<57;i++)
{
        flag[i]^=25+i;
        flag[i]+=20;
}
for(inti=0;i<57;i++)
{
        if(hexData[i]!=flag[i])
                die();
}
```
找到hexData的值，写解密脚本就行了。
```moectf{w1Nd0Ws_S3H_15_A_g0oD_m37h0d_70_h4nd13_EXCEPTI0NS}```

# 特工luo: 闻风而动
1.考察易语言程序的逆向分析，Keygen就不说了，一个简单的异或转换工具，cli在连接后会收到服务器发来的DES加密后flag，加密密码是WIFI密码走keygen，而客户端保存的时候再会走一次RC4加密，密码是 flag.fromserver 对没错 密码就是文件名
2.考察无线安全中对于无线握手包的密码破解。选手需要将cap文件转换为可以供hashcat读取的哈希，并使用hashcat结合题目提示来进行暴力破解（cap文件分析发现是WAP2类型，所以哈希类型是22000）跑出来就可以写解密脚本了（用易语言写最好）
3.值得注意的是，在爆破的时候，需要对密码keygen进行分析，可以从异或数字的大小来观察是数字还是字符，然后反异或过来，就可以缩减密码文本，从而降低爆破时间。
解密
```text
输出调试文本(到文本(解密数据(解密数据(读取文件("flag.fromserver"), "flag.fromserver", #RC4加密), "4g3n71u0", #DES加密)))
```
```moectf{h4cker_Lu0Q1@n_is_trying_to_0p3n_your_r3g15t3r3d_res1denc3}```

# 特工luo: 深入敌营
简单VM题目，拿去年 NCTF ezVM 的题改的简单版本，去掉了trash code，用z3-solver即可化简、求解。属于本比赛最难的逆向工程题目。
首先UPX -d 脱一下壳，放入ida分析一下
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  unsigned __int8 saver; // r15
  __int64 _code; // rdi
  __int64 _rsp; // rax
  __int64 _rip; // rcx
  unsigned __int8 v7; // cl
  __int16 v8; // cx
  int v9; // ecx
  __int64 v10; // rcx
  int v11; // ebp
  unsigned __int64 v12; // rbx
  unsigned __int8 v13; // r14
  rsize_t v14; // rdx
  __int64 v15; // rax
  __int64 v16; // rdx
  __int64 v17; // rcx

  saver = 0;
  LODWORD(_code) = 0;
LABEL_2:
  _rsp = (unsigned int)save;
  while ( 1 )
  {
    _rip = (unsigned int)_code;
    _code = (unsigned int)(_code + 1);
    switch ( insn[_rip] )
    {
      case 0xBu:                                // v_add_rsp_8
        _rsp = (unsigned int)(_rsp + 8);
        save = _rsp;
        continue;
      case 0xCu:
        _rsp = (unsigned int)(_rsp - 2);        // v_push_word
        save = _rsp;
        stack[_rsp + 1] = stack[(unsigned int)(_rsp + 2) + 1];
        stack[(unsigned int)(_rsp + 1) + 1] = stack[(unsigned int)(_rsp + 3) + 1];
        continue;
      case 0xEu:                                // v_notSelf
        stack[(unsigned int)(_rsp + 1) + 1] = ~stack[(unsigned int)(_rsp + 1) + 1];
        continue;
      case 0x14u:                               // v_and
        v16 = (unsigned int)(_rsp + 1);
        stack[v16 + 1] &= stack[_rsp + 1];
        _rsp = (unsigned int)v16;
        save = v16;
        continue;
      case 0x19u:                               // v_exit
        return *(_DWORD *)&insn[_code];
      case 0x32u:
        v7 = insn[_code];                       // v_push_byte
        _rsp = (unsigned int)(_rsp - 1);
        save = _rsp;
        LODWORD(_code) = _code + 1;
        stack[_rsp + 1] = v7;
        continue;
      case 0x49u:                               // v_dup
        _rsp = (unsigned int)(_rsp - 1);
        save = _rsp;
        stack[(unsigned int)_rsp + 1] = stack[(unsigned int)(_rsp + 1) + 1];
        continue;
      case 0x72u:                               // v_not
        stack[_rsp + 1] = ~stack[_rsp + 1];
        continue;
      case 0x7Bu:                               // v_read_chr
        v14 = (char)stack[_rsp + 1];
        v15 = (unsigned int)(_rsp - 7);
        save = v15;
        *(_QWORD *)&stack[v15 + 1] = Buffer;
        gets_s(Buffer, v14);
        goto LABEL_2;
      case 0x7Cu:
        saver = stack[_rsp + 1];                // v_save
        goto LABEL_9;
      case 0x8Du:
        if ( !stack[_rsp + 1] )
          LODWORD(_code) = *(_DWORD *)&stack[_rsp + 2];
        _rsp = (unsigned int)(_rsp + 5);
        save = _rsp;
        continue;
      case 0x8Eu:                               // v_print
        v11 = insn[_code];
        v12 = 0LL;
        _code = (unsigned int)(_code + 1);
        v13 = insn[_code] ^ v11;
        LODWORD(_code) = _code + 1;
        if ( v13 )
        {
          do
          {
            putchar(v11 ^ stack[v13 + (unsigned int)_rsp - v12]);
            LODWORD(_rsp) = save;
            ++v12;
          }
          while ( v12 < v13 );
        }
        save = v13 + (_DWORD)_rsp;
        putchar(10);
        goto LABEL_2;
      case 0x91u:                               // v_push_dword
        v9 = *(_DWORD *)&insn[_code];
        _rsp = (unsigned int)(_rsp - 4);
        save = _rsp;
        LODWORD(_code) = _code + 4;
        *(_DWORD *)&stack[_rsp + 1] = v9;
        continue;
      case 0x99u:
        _rsp = (unsigned int)(_rsp + 4);        // v_add_rsp_4
        save = _rsp;
        continue;
      case 0xADu:
        _rsp = (unsigned int)(_rsp - 1);        // v_push_saver
        save = _rsp;
        stack[(unsigned int)_rsp + 1] = saver;
        continue;
      case 0xB5u:
        _rsp = (unsigned int)(_rsp + 2);        // v_add_rsp_2
        save = _rsp;
        continue;
      case 0xB7u:
        v8 = *(_WORD *)&insn[_code];            // v_push_word
        _rsp = (unsigned int)(_rsp - 2);
        save = _rsp;
        LODWORD(_code) = _code + 2;
        *(_WORD *)&stack[_rsp + 1] = v8;
        continue;
      case 0xB8u:
        stack[_rsp + 1] = *(_BYTE *)(stack[_rsp + 1] + *(_QWORD *)&stack[_rsp + 2]);// v_add
        continue;
      case 0xD3u:
LABEL_9:
        _rsp = (unsigned int)(_rsp + 1);        // v_add_rsp_1
        save = _rsp;
        break;
      case 0xEAu:
        v10 = *(_QWORD *)&insn[_code];          // v_push_qword
        _rsp = (unsigned int)(_rsp - 8);
        save = _rsp;
        LODWORD(_code) = _code + 8;
        *(_QWORD *)&stack[_rsp + 1] = v10;
        break;
      case 0xFBu:
        if ( stack[_rsp + 1] )                  // v_not_not
          stack[_rsp + 1] = 1;
        break;
      case 0xFFu:
        v17 = stack[_rsp + 1];                  // v_not
        if ( (_BYTE)v17 )
        {
          if ( (_BYTE)v17 == 1 )
          {
            if ( (unsigned int)_rsp >= 0x100uLL )
              _report_rangecheckfailure(v17, (unsigned int)_rsp, envp);
            stack[_rsp + 1] = 0;
          }
        }
        else
        {
          stack[_rsp + 1] = 1;
        }
        break;
      default:
        continue;
    }
  }
}
```
可以看到是一个标准化的VM，我们可以写出z3-solver解题脚本。
```moectf{vv1ii?AGENT+1U0_-*7_$[TH/./e]+$_FinAL_v!c70Ry?}```