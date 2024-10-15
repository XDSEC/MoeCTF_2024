# MoeCTF2024 Crypto Official Writeup

Crypto出题组：imoau，sa1varsan，Orac1e

## 前言

MoeCTF2024 Crypto试题 ~~ 落实立德树人根本任务，遵循德智体美劳全面发展要求，贯彻《深化新时代CTF改革总体方案》，体现了MoeCTF改革的方向。试卷突出密码学学科特点，加强基础性与关键能力考查，充分发挥密码学学科的选拔与引导功能。MoeCTF2024 Crypto坚持立德树人，体现CTF文化的育人价值，突出理性思维的价值，注重数学的基础性，引导学生对CTF概念、方法更深刻的认知，在基础性、综合性、应用性、创新性等方面都进行了深入的考查。CTF稳中有变，变中有新，难度设计科学， ~~ 较好的发挥了MoeCTF的选拔功能，对萌新学习密码知识发挥了积极的引导和促进作用。

## 现代密码学入门指北

好好阅读指北内容，然后了解一下RSA Cryptosystem加解密的原理。

求解的代码如下：

```python
from Crypto.Util.number import inverse, long_to_bytes

n = 40600296529065757616876034307502386207424439675894291036278463517602256790833
p = 197380555956482914197022424175976066223
q = 205695522197318297682903544013139543071
c = 36450632910287169149899281952743051320560762944710752155402435752196566406306
e = 65537
assert p*q == n
phi = (p-1)*(q-1)
d = inverse(e, phi)
flag = long_to_bytes(pow(c,d,n))
print(flag)
# moectf{the_way_to_crypto}
```

## Signin

一道正常的RSA加密，我们给了以下数据

```python
pq = (p-1)*(q-2)
qp = (q-1)*(p-2)
p_q = p + q
```

其实关于rsa 的解密只需要计算 $\phi(n)$ 就行了，那么

$$
\phi(n) = (p-1)\cdot(q-1) = p\cdot q - (p+q) + 1
$$

混淆视听的pq和qp，其实知道了p+q就行了

所以就是一个正常的RSA解密

```python
from Crypto.Util.number import*
c = 5654386228732582062836480859915557858019553457231956237167652323191768422394980061906028416785155458721240012614551996577092521454960121688179565370052222983096211611352630963027300416387011219744891121506834201808533675072141450111382372702075488292867077512403293072053681315714857246273046785264966933854754543533442866929316042885151966997466549713023923528666038905359773392516627983694351534177829247262148749867874156066768643169675380054673701641774814655290118723774060082161615682005335103074445205806731112430609256580951996554318845128022415956933291151825345962528562570998777860222407032989708801549746
pq = 
n = 18047017539289114275195019384090026530425758236625347121394903879980914618669633902668100353788910470141976640337675700570573127020693081175961988571621759711122062452192526924744760561788625702044632350319245961013430665853071569777307047934247268954386678746085438134169871118814865536503043639618655569687534959910892789661065614807265825078942931717855566686073463382398417205648946713373617006449901977718981043020664616841303517708207413215548110294271101267236070252015782044263961319221848136717220979435486850254298686692230935985442120369913666939804135884857831857184001072678312992442792825575636200505903
p_q = 279533706577501791569740668595544511920056954944184570513187478007551195831693428589898548339751066551225424790534556602157835468618845221423643972870671556362200734472399328046960316064864571163851111207448753697980178391430044714097464866523838747053135392202848167518870720149808055682621080992998747265496
phi_n = n - (p_q) +1
d = pow(65537,-1,phi_n)
m = pow(c,d,n)
print(long_to_bytes(m))
```

## ez_hash

根据题目描述，该hash加密的是联系方式所以全是数字，那么我们直接进行爆破就好了


```Python
from hashlib import sha256
from tqdm import trange


hash_value = '3a5137149f705e4da1bf6742e62c018e3f7a1784ceebcb0030656a2b42f50b6a'
for i in trange(1000000):
    tmp = sha256(("2100" + str(i).zfill(6)).encode()).hexdigest()
    if tmp == hash_value:
        print(f"{i = }")
```

## big and small

根据代码，这个也是以RSA为基础的加密。但是我们可以看到

```python
e = 3
```

这么小的e，再加上这么大的n，我们猜测n比m**e还要大，所以直接对c开三次根号然后模一下n就行了

```python
from Crypto.Util.number import*
import gmpy2


c = 150409620528288093947185249913242033500530715593845912018225648212915478065982806112747164334970339684262757
e = 3
n = 20279309983698966932589436610174513524888616098014944133902125993694471293062261713076591251054086174169670848598415548609375570643330808663804049384020949389856831520202461767497906977295453545771698220639545101966866003886108320987081153619862170206953817850993602202650467676163476075276351519648193219850062278314841385459627485588891326899019745457679891867632849975694274064320723175687748633644074614068978098629566677125696150343248924059801632081514235975357906763251498042129457546586971828204136347260818828746304688911632041538714834683709493303900837361850396599138626509382069186433843547745480160634787
m = gmpy2.iroot(c,e)[0]
assert pow(m, e, n) == c
print(long_to_bytes(m))
```

## baby_equation

看到这个等式，并且没有任何其他有用条件我们想着化简这个方程

```python
from sage.all import*
a,b = var('a,b')
f = ((a**2 + 1)*(b**2 + 1) - 2*(a - b)*(a*b - 1)) -  4* a*b
f.factor()
#(a + 1)^2*(b - 1)^2
```

发现这个方程可以化成左边是完全平方数的形式，所以右边我们开根号的话，也可以的得到一个整数
我们先对等式两边开根号

```python
form sage.all import*
kk = 27328626951220627460190048548642132653324307668307228356327457544601023614215851384489010012863904153866202151702022400
factor(kk)
2^8 * 5^2 * 23^2 * 29^2 * 47^2 * 1549^2 * 11177^2 * 74383^2 * 123191526986494009^2 * 415493304743186434332409^2
# 注：这里的factor()是sagemath中用于整数分解的内置函数。
```

整理一下

```python
factors = [2,2,2,2,5,23,29,47,1549,11177,74383,123191526986494009,415493304743186434332409]
```

我们现在只需要将这些因子分成两个部分，然后找到以moectf开头的就行了

```Python
from Crypto.Util.number import *
from tqdm import trange
import gmpy2

k = 0x2227e398fc6ffcf5159863a345df85ba50d6845f8c06747769fee78f598e7cb1bcf875fb9e5a69ddd39da950f21cb49581c3487c29b7c61da0f584c32ea21ce1edda7f09a6e4c3ae3b4c8c12002bb2dfd0951037d3773a216e209900e51c7d78a0066aa9a387b068acbd4fb3168e915f306ba40
k0 = gmpy2.isqrt(k)
factors = [2,2,2,2,2,3,3,31,61,223,4013,281317,4151351,339386329,370523737,5404604441993,26798471753993,25866088332911027256931479223,64889106213996537255229963986303510188999911,44979288015186262195355977893442196584868708990742843132296199943173741915484606917929]
print(len(factors))
factors.append(2)

for i in trange(1<<19):
    tmp = bin(int(i))[2:].zfill(19)
    adding_one = prod([factors[i]**(int(tmp[i],2)) for i in range(19)])
    msg = long_to_bytes(adding_one-1)
    if b'moectf{' in msg:
        a = adding_one - 1
        b = 2*k0//a + 1
        flag = long_to_bytes(a) + long_to_bytes(b)
        print(f"{flag = }")
        break

# flag = b'moectf{7he_Fund4m3nt4l_th30r3m_0f_4rithm3tic_i5_p0w4rful!}'
```

## rsa_revenge

题目的核心代码是这个

```python
def emirp(x):
    y = 0
    while x !=0:
        y = y*2 + x%2
        x = x//2
    return y
```

通过代码，我们发现用这个函数生成的p和q他们在二进制上相反的，比如p是1010，那么q就是0101。除此之外，我们会发现p和q的低位乘起来就是n的低位。通过这些性质我们可以直接开始进行爆破。

```python
from Crypto.Util.number import*
from gmpy2 import *


n = 141326884939079067429645084585831428717383389026212274986490638181168709713585245213459139281395768330637635670530286514361666351728405851224861268366256203851725349214834643460959210675733248662738509224865058748116797242931605149244469367508052164539306170883496415576116236739853057847265650027628600443901
c = 47886145637416465474967586561554275347396273686722042112754589742652411190694422563845157055397690806283389102421131949492150512820301748529122456307491407924640312270962219946993529007414812671985960186335307490596107298906467618684990500775058344576523751336171093010950665199612378376864378029545530793597


def blast(a, b, k):
    if k == 256:
        if a*b == n:
            print((a,b))
        return
    for i in range(2):
        for j in range(2):
            a1 = a + i*(2**k) + j*(2**(511-k))
            b1 = b + j*(2**k) + i*(2**(511-k))
            if a1*b1 > n:
                continue
            if (a1+(2**(511-k)))*(b1+(2**(511-k))) < n:
                continue
            if ((a1*b1)%(2**(k+1))) != (n%(2**(k+1))):
                continue
            blast(a1, b1, k+1)


for i in range(2):
    blast(i*(2**256), i*(2**256), 0)

p,q = (12119998731259483292178496920109290754181396164390285597126378297678818779092115139911720576157973310671490865211601201831597946479039132512609504866583931, 11660635291534613230423193509391946961264539191735481147071890944740311229658362673314192872117237108949853531941630122241060679012089130178372253390640871)
assert p*q == n
phi = (p-1)*(q-1)
e = 65537
d = pow(e,-1,phi)
m = pow(c,d,n)
print(long_to_bytes(m))
```

## 大白兔

注意到额外提供了如下两个方程的实际值：

$$
\begin{align*}
c_1 &= (3p + 7q)^{e_1} \bmod N\\
c_2 &= (2p + 5q)^{e_2} \bmod N\\
\end{align*}
$$

对于形如 $c = (a\cdot p + b\cdot q)^e\bmod{N}$ 的方程，我们考虑二项式定理，将其展开，得到：

$$c=\sum_{i=0}^{e}{e \choose i}\cdot (a\cdot p)^{e-i}\cdot (b\cdot q)^{i}\bmod{N}$$

结合模数 $N=p\cdot q$，我们可以化简得到：

$$c = (a\cdot p)^{e}+(b\cdot q)^{e}\bmod{N}$$

有了上面的知识，下面我们开始考虑如何分解模数 $N$。

首先，我们将 $c_{1},c_{2}$ 中的各项调整为齐次：

$$
\begin{align*}
c_1^{e_2} &= (3p)^{e_1\cdot e_{2}} + (7q)^{e_{1}\cdot e_{2}} \bmod{N}\\
c_2^{e_1} &= (2p)^{e_{1}\cdot e_{2}} + (5q)^{e_1\cdot e_2} \bmod{N}\\
\end{align*}
$$

消去 $p^{e_{1}\cdot e_{2}}$ 项，得到：

$$f = (2^{e_{1}\cdot e_{2}}c_{1}^{e_{2}}-3^{e_{1}\cdot e_{2}}c_{2}^{e_{1}})\bmod{N}=(14^{e_{1}\cdot e_{2}}-15^{e_{1}\cdot e_{2}})\cdot q^{e_{1}\cdot e_{2}}\bmod{N}$$

此时，我们已经得到了 $q^{x}\bmod N$ 的值，接下来分析如何分解整数 $N$：

设 $q_{0}=q^{x}\bmod{N}=q^{x}-k\cdot N$，对方程两边分别模 $p,q$，得到：

$$
\begin{align*}
q_{0}\equiv 0\bmod{q}\\
q_{0}\not\equiv 0\bmod{p}\\
\end{align*}
$$

这时，容易看出 $q_{0}$ 中含有素因子 $q$，我们可以通过 $\gcd(q_{0},N)$ 获得 $q$，进而分解 $N$。


```Python
from Crypto.Util.number import *
e1 = 12886657667389660800780796462970504910193928992888518978200029826975978624718627799215564700096007849924866627154987365059524315097631111242449314835868137
e2 = 12110586673991788415780355139635579057920926864887110308343229256046868242179445444897790171351302575188607117081580121488253540215781625598048021161675697
N = 107840121617107284699019090755767399009554361670188656102287857367092313896799727185137951450003247965287300048132826912467422962758914809476564079425779097585271563973653308788065070590668934509937791637166407147571226702362485442679293305752947015356987589781998813882776841558543311396327103000285832158267
c1 = 15278844009298149463236710060119404122281203585460351155794211733716186259289419248721909282013233358914974167205731639272302971369075321450669419689268407608888816060862821686659088366316321953682936422067632021137937376646898475874811704685412676289281874194427175778134400538795937306359483779509843470045
c2 = 21094604591001258468822028459854756976693597859353651781642590543104398882448014423389799438692388258400734914492082531343013931478752601777032815369293749155925484130072691903725072096643826915317436719353858305966176758359761523170683475946913692317028587403027415142211886317152812178943344234591487108474
c = 21770231043448943684137443679409353766384859347908158264676803189707943062309013723698099073818477179441395009450511276043831958306355425252049047563947202180509717848175083113955255931885159933086221453965914552773593606054520151827862155643433544585058451821992566091775233163599161774796561236063625305050
s1 = pow(c1, e2, N)
s2 = pow(c2, e1, N)
comb = pow(2,e1*e2,N)*s1 - pow(3,e1*e2,N)*s2
q = GCD(comb,N)
p = N//q
assert p*q == N
phi = N - (p + q) + 1
d = inverse(0x10001, phi)
flag = long_to_bytes(pow(c,d,N))
print(flag)
# Flag: moectf{Sh4!!0w_deeb4t0_P01arnova}
```

## More_secure_RSA

首先，注意到flag长度为32，那么使用`bytes_to_long()`函数将其编码得到的整数 $m$ 的大小满足： $m<2^{32\cdot8}=2^{128}$。

第二次RSA加密的结果为：

$C = m^e \mod(n\cdot r)$

其中 $r$ 为1024bits的素数。

由于 $\langle n,N\rangle$ 已知，我们可以求出 $r = N/n$。考虑将 $C$ 模 $r$，得到 $C\bmod{r} = m^e\bmod{r}$。由于 $\gcd(e,r-1)=1$，于是我们考虑直接在 $\mathbb{Z}/r\mathbb{Z}$ 上进行解密，得到：
$$m\bmod r = C^{d_{r}}\bmod r,d_{r}=e^{-1}\bmod(r-1)$$

而由于 $m<2^{128}<r$，故实际上 $m=m\bmod r$。

exp

```Python
from Crypto.Util.number import *
assert N1 % n1 == 0
r = N1//n1
assert isPrime(r)
fake_flag = b'moectf{????????????????????????}'
assert bytes_to_long(fake_flag) <= r
dr = inverse(e, r-1)
m = pow(C1,dr,r)
flag = long_to_bytes(m)
```

## ezlegendre

经过欧拉判别法验证， $a$ 是 $p$ 的二次非剩余， 而 $a+1$ 是 $p$ 的二次剩余，我们给定的 $e$ 是一个奇数，根据勒让德符号可知，最后得到的`cipertext[i]`，也会是相对应的二次剩余或者是二次非剩余，遍历一遍通过欧拉判法可以得到最终的结果。

exp

```Python
from sage.all import *
from Crypto.Util.number import *
'''
p = 303597842163255391032954159827039706827
a = 34032839867482535877794289018590990371
ciphertext = [……]
'''
msg_bin = ''
for i in range(len(ciphertext)):
    msg_bin += '1' if pow(ciphertext[i], (p - 1) // 2, p) == 1 else '0'
flag = long_to_bytes(int(msg_bin,2))
print(flag)
# Flag: moectf{minus_one_1s_n0t_qu4dr4tic_r4sidu4_when_p_mod_f0ur_equ41_to_thr33}
```

## new_system

注意到加密函数 $F(x)=a_{i}\cdot x + m_{i}\bmod q$ 具有一种类似加法同态的性质。我们这里考虑两组明密文：

$$
\begin{align*}
a_1 \cdot x + m_1 &= c_1 \bmod q\\
a_2 \cdot x + m_2 &= c_2 \bmod q\\
\end{align*}
$$

两式左右两边分别相加，得到：

$$(a_1 + a_2)\cdot x+(m_1 + m_2) = c_1 + c_2 \bmod q$$

又因为我们有消息 $m_1+m_2$ 对应的密文：

$$a_3\cdot x + (m_1 + m_2)  = c_3 \bmod q$$

显然，我们可以消去 $(m_{1}+m_{2})$，并恢复得到密钥 $x$:

$x = (a_1+a_2-a_3)^{-1} \cdot (c_1+c_2-c_3) \bmod q$

### exp

```python
from Crypto.Util.number import inverse,long_to_bytes


q = 105482865285555225519947662900872028851795846950902311343782163147659668129411
a1,c1 = [48152794364522745851371693618734308982941622286593286738834529420565211572487, 21052760152946883017126800753094180159601684210961525956716021776156447417961]
a2,c2 = [48649737427609115586886970515713274413023152700099032993736004585718157300141, 6060718815088072976566240336428486321776540407635735983986746493811330309844]
a3,c3 = [30099883325957937700435284907440664781247503171217717818782838808179889651361, 85333708281128255260940125642017184300901184334842582132090488518099650581761]

x = inverse(a1+a2-a3,q)*(c1+c2-c3)%q
msg = (c3-a3*x) % q
flag = long_to_bytes(msg)
print(flag)
# b'moectf{gift_1s_present}'
```

## One more bit

简单审计下task.py中的代码，发现如下关键参数：

```python
nbits = 1024
dbits = 258
```

发现这个RSA实例的解密指数较小，只有258bits，于是我们尝试google一下`rsa small private key exposure attack`，可以找到这篇参考文献：[二十年来对RSA密码系统的攻击综述](https://www.ams.org/notices/199902/boneh.pdf)。

发现定理二中提出了如下论断：

"Let $N = pq$ with $q<p<2p$ . Let $d<\frac{1}{3}N^{\frac{1}{4}}$ . Given $\langle N, e\rangle$ with $ed\equiv 1\bmod \phi(N)$, Marvin can efficiently recover $d$ ."（实际上，此即著名的`Wiener's attack`）

简单计算一下，发现如果在本题中运用定理中提出的攻击，私钥 $d$ 的上界大约为 $O(2^{256})$，略小于 $2^{258}$。这说明，仅仅使用`Wiener's attack`是不足够的，我们需要一点额外的策略。继续尝试google，发现这样一篇文章[A variant of Wiener's attack on RSA](https://arxiv.org/abs/0811.0063)，其中第二节提出了The Verheul and van Tilborg attack，通过搜索 形如 $r\cdot q_{m} + s\cdot q_{m+1}$ 的小系数线性组合来提升Wiener's attack中的界。关于Wiener's attack及其简单拓展的具体细节，笔者这里建议读者跟着参考文献的思路推导一遍，而不是仅仅简单地抄个作业。

exp:
```python
from sage.all import *
from Crypto.Util.number import *
from Crypto.Util.Padding import unpad
from time import time
from tqdm import trange


pk = (134133840507194879124722303971806829214527933948661780641814514330769296658351734941972795427559665538634298343171712895678689928571804399278111582425131730887340959438180029645070353394212857682708370490223871309129948337487286534021548834043845658248447393803949524601871557448883163646364233913283438778267, 83710839781828547042000099822479827455150839630087752081720660846682103437904198705287610613170124755238284685618099812447852915349294538670732128599161636818193216409714024856708796982283165572768164303554014943361769803463110874733906162673305654979036416246224609509772196787570627778347908006266889151871)
ciphertext = 73228838248853753695300650089851103866994923279710500065528688046732360241259421633583786512765328703209553157156700672911490451923782130514110796280837233714066799071157393374064802513078944766577262159955593050786044845920732282816349811296561340376541162788570190578690333343882441362690328344037119622750
n,e = pk


d_h = int(n**(0.252))
d_l = int(n**(0.250))

testd = []

def wiener(e, n):
    q0 = 1

    list1 = continued_fraction(Integer(e)/Integer(n))
    conv = list1.convergents()
    for i in conv:
        q1 = i.denominator()

        for r in range(20):
            for s in range(20):
                d = r*q1 + s*q0
                if d <= d_h and d >= d_l:
                    testd.append(d)
        q0 = q1

start_time = time()
wiener(e,n)
m = 3
c = pow(m,e,n)
d = 0
for i in trange(len(testd)):
    if pow(c,testd[i],n) == m:
        d = testd[i]
        end_time = time()
        break


print(f"time used:{end_time-start_time}")
print(len(testd).bit_length())
flag = unpad(long_to_bytes(pow(ciphertext,d,n)),16)
print(flag)
# b'moectf{Ju5t_0n3_st3p_m0r3_th4n_wi3n3r_4ttack!}\x02\x02'
```

## EzMatrix

首先看题目描述：`Can you break my LFSR?`

task中定义了一个128级的线性反馈移位寄存器，其反馈多项式为一未知的本原多项式，寄存器大小为256而初始值未知。我们已知该线性反馈移位寄存器的251个连续输出，需要恢复其反馈多项式和寄存器的初始值。

首先，我们可以将该LFSR的反馈函数表达如下：

$$a_{i+n}=\sum_{j=1}^{n}c_{j}a_{i+n-j}$$

其中 $c_{j}\in\mathbb{F}_{2}$ 

不难看出这是一个 $\mathbb{F}_{2}^{n}$ 上的线性变换，我们使用线性代数的语言将其重新叙述：

$$
(a_{i},a_{i+1},\cdot,a_{i+n-1})\cdot\begin{pmatrix}
0 & 0 & \cdots & 0 & c_{n}\\
1 & 0 & \cdots & 0 & c_{n-1}\\
0 & 1 & \cdots & 0 & c_{n-2}\\
\vdots & \vdots & \ddots & \vdots & \vdots\\
0 & 0 & \cdots & 1 & c_{1}\\
\end{pmatrix} = (a_{i},a_{i+1},\cdots,a_{i+n})(*)
$$

注：关于有限域 $\mathbb{F}_{2}$，可以将其理解为定义了加法和乘法的集合 $\{0,1\}$，其中的加法和乘法分别对应于逻辑运算中的异或运算和与运算。

但是在本题中，反馈多项式是未知的，我们只能尝试其他的办法。
重新考虑反馈函数 $F$ ，我们将其描述为如下形式：

$$(c_{1},c_{2},\cdots,c_{n})\cdot (a_{i+n-1},a_{i+n-2},\cdots,a_{i})^{T} = a_{i+n}$$

这时，我们视 $(c_{1},c_{2},\cdots,c_{n})$ 为变量，则收集足够多的如上形式的方程，便可以得到一个满秩的矩阵方程 $\vec{t}\cdot M = \vec{t}$，对其进行高斯消去即可。具体而言，我们需要 $2\cdot n$ 个连续的输出才能构建出这样的方程。

在求出了反馈多项式之后，我们便可以尝试去恢复寄存器的初始值了：

对于LFSR，我们可以尝试构建反馈多项式的反多项式来逆向递推求解其初始状态，也可以直接求∗式中矩阵的在 $\mathbb{F}_{2}$ 上的逆矩阵，然后通过快速幂恢复寄存器的初始状态。

注：由于我们只有 $251$ 个连续输出，所以求解时需要稍微爆破一下未知的 $5$ 个输出值。


```python
# Sagemath solution
from Crypto.Util.number import *
from sage.all import *


for i in range(32):
    output = "11111110011011010000110110100011110110110101111000101011001010110011110011000011110001101011001100000011011101110000111001100111011100010111001100111101010011000110110101011101100001010101011011101000110001111110100000011110010011010010100100000000110"
    brutebits = bin(i)[2:].zfill(5)
    output += brutebits
    F = GF(2)
    # {0,1}
    n = 128
    V = VectorSpace(F,n)
    vec = V(list(map(int, list(output[n:]))))
    M = []
    for i in range(n-1,2*n-1):
        m = []
        for j in range(n):
            m.append(output[i-j])
        M.append(m)
    M = Matrix(F,M)
    try:
        sol = M.solve_right(vec)
    except ValueError:
        continue
    poly = list(sol)
    B = Matrix(F,n,n)
    for i in range(n):
        B[i,n-1] = poly[n-1-i]
    for i in range(n-1):
        B[i+1,i] = 1
    try:
        B_inv = B**(-1)
        t = V(list(map(int,list(output[:n]))))
        print(long_to_bytes(int("".join(map(str,t*B_inv**(n))),2)))
    except ZeroDivisionError:
        continue
```

## EzPack


```python
from Crypto.Util.number import *
from secret import flag
import random


p = 2050446265000552948792079248541986570794560388346670845037360320379574792744856498763181701382659864976718683844252858211123523214530581897113968018397826268834076569364339813627884756499465068203125112750486486807221544715872861263738186430034771887175398652172387692870928081940083735448965507812844169983643977
assert len(flag) == 42


def encode(msg):
    return bin(bytes_to_long(msg))[2:].zfill(8*len(msg))


def genkey(len):
    sums = 0
    keys = []
    for i in range(len):
        k = random.randint(1,7777)
        x = sums + k
        keys.append(x)
        sums += x
    return keys


key = genkey(42*8)


def enc(m, keys):
    msg = encode(m)
    print(len(keys))
    print(len(msg))
    assert len(msg) == len(keys)
    s = sum((k if (int(p,2) == 1) else 1) for p, k in zip(msg, keys))
    print(msg)
    for p0,k in zip(msg,keys):
        print(int(p0,2))
    return pow(7,s,p)


cipher = enc(flag,key)

with open("output.txt", "w") as fs:
    fs.write(str(key)+'\n')
    fs.write(str(cipher))

```

简单阅读下源码，发现`enc`实现了一个乘积背包加密，具体流程如下：

首先将待加密的消息m编码为二进制比特串`msg`，对于其中的每一个比特，我们采取如下加密方式：

$$
\begin{align*}
g_{i}&=7^{k_{i}}\bmod p\quad m_{i}=1\\
g_{i}&=7^{1}\bmod p\quad m_{i}=0\\
\end{align*}
$$

最终，计算 $g=\prod_{j=1}^{n}g_{j}$。

再看`genkey`中的密钥生成逻辑，发现其生成的密钥序列 $(k_{0},k_{1},\cdots,k_{n-1})$ 为一超递增序列，满足：

$$k_{i}>k_{i-1}+\cdots+k_{2}+k_{1}+k_{0} \text{ for all } 1\leq k\leq n-1$$

根据此性质，我们已推知，由其构造的背包加密方案可以通过简单的贪心策略求解：若 $k_{i}\leq M$，则 $x_{i} = 1$，再从 $M$ 中减去 $k_{i}$。

那么我们现在的关键任务在于从 $g = \prod_{j=1}^{n}g_{j}\bmod{p} = g^{\sum_{j=1}^{n}m_{i}\cdot(k_{i}-1)+1}\bmod{p}$ 中恢复出 $(\sum_{j=1}^{n}m_{i}\cdot(k_{i}-1)+1)\bmod{\frac{p-1}{8}}$，即求解一个离散对数问题。

注: $7$ 在 $\mathbb{F}_{p}^{*}$ 的阶为 $\frac{p-1}{8}$

对 $p-1$ 进行分解，发现其比较光滑：

```python
sage: factor(p-1)
2^3 * 3 * 7 * 636277 * 677857 * 682777 * 735809 * 860059 * 903949 * 908441 * 954851 * 1017139 * 1032341 * 1163131 * 1190737 * 1227157 * 1341323 * 1395671 * 1463611 * 1556201 * 1569401 * 1713749 * 1930931 * 2219563 * 2476283 * 2477281 * 2590633 * 2756587 * 2833643 * 3095713 * 3281449 * 3688063 * 4008793 * 4285993 * 5443981 * 5720053 * 5822981 * 6201869 * 6892217 * 7093841 * 7319857 * 8227237 * 9381107 * 9477463 * 10078729 * 10084297 * 10764907 * 12416167 * 14095651 * 14294663 * 14788051
```

针对具有光滑阶的生成元的离散对数问题，我们可以运用Pohlig-Hellman算法来进行求解，具体可以参[ctfwiki](https://ctf-wiki.org/crypto/asymmetric/discrete-log/discrete-log/)相关内容学习。

exp

```python
from sage.all import *
from Crypto.Util.number import *

keys = 
cipher = 
p = 

F = GF(p)
a = F(7)
X = F(cipher)
n = a.order()
primes = [2^3,3,7,636277,677857,682777,735809,860059,903949,908441,954851, 1017139, 1032341, 1163131, 1190737, 1227157, 1341323, 1395671, 1463611, 1556201, 1569401, 1713749, 1930931, 2219563, 2476283, 2477281, 2590633, 2756587, 2833643, 3095713, 3281449, 3688063, 4008793, 4285993, 5443981, 5720053, 5822981, 6201869, 6892217, 7093841, 7319857, 8227237, 9381107, 9477463, 10078729, 10084297, 10764907, 12416167, 14095651, 14294663,14788051]

dlogs = []
for fac in primes:
    t = int(n//fac)
    dlog = discrete_log(X**t, a**t)
    dlogs += [dlog]
    print("factor:"+str(fac)+",Discrete Log:"+str(dlog))

nc = crt(dlogs,primes)
print(nc)
assert pow(7,nc,p) == cipher
nc = nc % ((p-1)//8)
t = len(keys)
print(t)

x = []
for i in range(t):
    x.append(0)
    
for i in range(1, t+1):
    if nc >= keys[t-i]:
        x[i-1] = 1
        nc = nc - (keys[t-i])
    else:
        x[i-1] = 0    



y = 0
for i in range(1, t+1):
    y += x[i-1] * 2**(i-1)
print(y)

print(long_to_bytes(y))
```

## ezLCG

先读题目描述：“老板，你这瓜（数字签名算法）保熟吗？”

首先我们需要简单了解并学习一下[DSA](https://ctf-wiki.org/crypto/signature/dsa/)（数字签名算法）

接下来分析下task.py中的代码：

```python
from sage.all import *
from random import getrandbits, randint
from secrets import randbelow
from Crypto.Util.number import getPrime,isPrime,inverse
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
from secret import priKey, flag
from hashlib import sha1
import os


q = getPrime(160)
while True:
    t0 = q*getrandbits(864)
    if isPrime(t0+1):
        p = t0 + 1
        break


x = priKey
assert p % q == 1
h = randint(1,p-1)
g = pow(h,(p-1)//q,p)
y = pow(g,x,p)


def sign(z, k):
    r = pow(g,k,p) % q
    s = (inverse(k,q)*(z+r*priKey)) % q
    return (r,s)


def verify(m,s,r):
    z = int.from_bytes(sha1(m).digest(), 'big')
    u1 = (inverse(s,q)*z) % q
    u2 = (inverse(s,q)*r) % q
    r0 = ((pow(g,u1,p)*pow(y,u2,p)) % p) % q
    return r0 == r


def lcg(a, b, q, x):
    while True:
        x = (a * x + b) % q
        yield x


msg = [os.urandom(16) for i in range(5)]

a, b, x = [randbelow(q) for _ in range(3)]
prng = lcg(a, b, q, x)
sigs = []
for m, k in zip(msg,prng):
    z = int.from_bytes(sha1(m).digest(), "big") % q
    r, s = sign(z, k)
    assert verify(m, s, r)
    sigs.append((r,s))


print(f"{g = }")
print(f"{h = }")
print(f"{q = }")
print(f"{p = }")
print(f"{msg = }")
print(f"{sigs = }")
key = sha1(str(priKey).encode()).digest()[:16]
iv = os.urandom(16)
cipher = AES.new(key, AES.MODE_CBC,iv)
ct = cipher.encrypt(pad(flag,16))
print(f"{iv = }")
print(f"{ct = }")

```

对于每一组签名 $(m,r,s)$ ，我们有如下关系式

$$
\begin{align*}
r& \equiv g^k\bmod q\\
s & \equiv k^{-1}\cdot (H(m)+r\cdot d)\bmod q\\
\end{align*}
$$

其中 $H(\cdot)$ 为哈希函数， $d$ 为签名所使用的私钥。

注意到每一次签名时所使用的随机数 $k$ 是由如下函数生成的：

```python
def lcg(a, b, q, x):
    while True:
        x = (a * x + b) % q
        yield x
```

`lcg`，线性同余生成器，是一种非常经典著名的伪随机数生成器。

其核心生成方式如下：

$$x_{i+1}\equiv a\cdot x_{i} + b(\bmod q)$$

任取两组签名，记为 $(m_{0},r_{0},s_{0}),(m_{1},r_{1},s_{1})$，则我们有：

$$
\begin{align*}
k_{0} &= s_{0}^{-1}(H(m_{0})+r_{0}\cdot d)\bmod{q}\\
k_{1} &= s_{1}^{-1}(H(m_{1})+r_{1}\cdot d)\bmod{q}\\
\end{align*}
$$

也是说，对于每一个 $k_{i}$ ，我们都可以将其表达为 $u_{i}\cdot d + v_{i}$，其中 $u,v$ 可以通过已知的签名计算得到。而`lcg`中有三个参数未知：$a,b,x_0$。由于lcg是线性的，我们可以利用其线性关系，结合 $k_{i}=u_{i}\cdot d + v_{i}$ 去尝试恢复私钥 $d$。具体推导如下：

$$k_{i+2}-k_{i+1}=a\cdot (k_{i+1}-k_{i})\bmod q$$

$$k_{i+1}-k_{i}=a\cdot (k_{i}-k_{i-1})\bmod q$$

两式分别乘以 $k_{i}-k_{i-1},k_{i+1}-k_{i}$，然后相减消去未知参数 $a$，得到：

$$(k_{i+2}-k_{i+1})\cdot (k_{i}-k_{i-1})\equiv (k_{i+1}-k_{i})^2\bmod q(*)$$

此时我们得到了一个 $\mathbb{Z}/p\mathbb{Z}$ 上的一元二次方程 $f$，求根即可恢复私钥 $d$，进而解密得到flag。

exp
```python
from sage.all import *
from Crypto.Cipher import AES
from Crypto.Util.number import *
from hashlib import sha1


g = 81569684196645348869992756399797937971436996812346070571468655785762437078898141875334855024163673443340626854915520114728947696423441493858938345078236621180324085934092037313264170158390556505922997447268262289413542862021771393535087410035145796654466502374252061871227164352744675750669230756678480403551
h = 13360659280755238232904342818943446234394025788199830559222919690197648501739683227053179022521444870802363019867146013415532648906174842607370958566866152133141600828695657346665923432059572078189013989803088047702130843109809724983853650634669946823993666248096402349533564966478014376877154404963309438891
q = 1303803697251710037027345981217373884089065173721
p = 135386571420682237420633670579115261427110680959831458510661651985522155814624783887385220768310381778722922186771694358185961218902544998325115481951071052630790578356532158887162956411742570802131927372034113509208643043526086803989709252621829703679985669846412125110620244866047891680775125948940542426381
msg = [b'I\xf0\xccy\xd5~\xed\xf8A\xe4\xdf\x91+\xd4_$', b'~\xa0\x9bCB\xef\xc3SY4W\xf9Aa\rO', b'\xe6\x96\xf4\xac\n9\xa7\xc4\xef\x82S\xe9 XpJ', b'3,\xbb\xe2-\xcc\xa1o\xe6\x93+\xe8\xea=\x17\xd1', b'\x8c\x19PHN\xa8\xbc\xfc\xa20r\xe5\x0bMwJ']
sigs = [(913082810060387697659458045074628688804323008021, 601727298768376770098471394299356176250915124698), (406607720394287512952923256499351875907319590223, 946312910102100744958283218486828279657252761118), (1053968308548067185640057861411672512429603583019, 1284314986796793233060997182105901455285337520635), (878633001726272206179866067197006713383715110096, 1117986485818472813081237963762660460310066865326), (144589405182012718667990046652227725217611617110, 1028458755419859011294952635587376476938670485840)]
iv = b'M\xdf\x0e\x7f\xeaj\x17PE\x97\x8e\xee\xaf:\xa0\xc7'
ct = b"\xa8a\xff\xf1[(\x7f\xf9\x93\xeb0J\xc43\x99\xb25:\xf5>\x1c?\xbd\x8a\xcd)i)\xdd\x87l1\xf5L\xc5\xc5'N\x18\x8d\xa5\x9e\x84\xfe\x80\x9dm\xcc"
hash_msgs = [int.from_bytes(sha1(m).digest(), "big") % q for m in msg]
R = [sigs[i][0] for i in range(len(sigs))]
S = [sigs[i][1] for i in range(len(sigs))]
msinv = [hash_msgs[i] * inverse_mod(S[i],q) % q for i in range(5)]
rsinv = [R[i] * inverse_mod(S[i],q) % q for i in range(5)]

PR = PolynomialRing(GF(q),'d')
d = PR.gen()

k1 = rsinv[1]*d + msinv[1]
k2 = rsinv[2]*d + msinv[2]
k3 = rsinv[3]*d + msinv[3]
k4 = rsinv[4]*d + msinv[4]
g = (k4-k3)*(k2-k1)-(k3-k2)^2
roots = g.roots()
d = roots[1][0]
key = sha1(str(d).encode()).digest()[:16]
cipher = AES.new(key, AES.MODE_CBC,iv)
ct = cipher.decrypt(ct)
print(ct)
# b'moectf{w3ak_n0nce_is_h4rmful_to_h3alth}\t\t\t\t\t\t\t\t\t'
```

## babe-Lifting

首先注意到：

```python
bit_leak = 400
d_leak = d & ((1<<bit_leak)-1)
```

即解密指数 $d$ 的低400比特位的信息已知。

根据RSA的私钥生成方式，我们有 $d\cdot e = 1 + k\cdot \phi(N)$

现在已知 $d\bmod{2^{400}}$，则考虑方程两边模 $t=2^{400}$，得到：

$$d_{l}\cdot e = 1 + k\cdot \phi(N)\bmod{t}$$

由于加密指数 $e=0x1001$ 较小，$k\approx e$，故我们可以尝试遍历区间`[1,e]`，在 $\mathbb{Z}/t\mathbb{Z}$ 上解方程得到 $\phi(N)\bmod{t}$ 的值。此时，我们可以得到 $(p+q)\bmod{t}$ 的值，再考虑 $\mathbb{Z}/t\mathbb{Z}$ 上的二次方程 $x^2 - ((p+q)\bmod{t})\cdot x + n=0$，不难发现，其根分别为 $p\bmod{t},q\bmod{t}$。而当我们已知 $p,q$ 较多低位信息时，可以运用一种名为Coppersmith's method的巧妙方法来分解整数 $n$，更多细节可以参考[van1sh'blog](https://jayxv.github.io/2020/08/13/%E5%AF%86%E7%A0%81%E5%AD%A6%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B0%E4%B9%8Bcoppersmith/)。

exp

```python
from Crypto.Util.number import long_to_bytes
from sage.all import *
from tqdm import trange

def recover_p(p0, n):
    PR = PolynomialRing(Zmod(n),'x')
    x = PR.gen()
    nbits = 1024
    p0bits = 400
    f = 2^(p0bits-2)*x + p0
    f = f.monic()
    roots = f.small_roots(X=2^(nbits//2-p0bits+2), beta=0.49)  
    if roots:
        x0 = roots[0]
        p = gcd(2^(p0bits-2) * int(x0) + p0, n)
        print(f"{p=}")
        return ZZ(p)

    
def find_p0(d0, e, n):
    X = var('X')
    for k in trange(1, e+1):
        results = solve_mod([k*X**2 + (e*d0 - (1+k*(n+1))) * X + k*n==0], 1<<400)
        for x in results:
            p0 = ZZ(x[0])
            p = recover_p(p0, n)
            if p and p != 1:
                return p


n = 53282434320648520638797489235916411774754088938038649364676595382708882567582074768467750091758871986943425295325684397148357683679972957390367050797096129400800737430005406586421368399203345142990796139798355888856700153024507788780229752591276439736039630358687617540130010809829171308760432760545372777123
e = 4097
c = 14615370570055065930014711673507863471799103656443111041437374352195976523098242549568514149286911564703856030770733394303895224311305717058669800588144055600432004216871763513804811217695900972286301248213735105234803253084265599843829792871483051020532819945635641611821829176170902766901550045863639612054
d0 = 1550452349150409256147460237724995145109078733341405037037945312861833198753379389784394833566301246926188176937280242129
p = int(find_p0(d0, e, n))
print("found p: ", p)
q = n//int(p)
d = inverse_mod(e,(p-1)*(q-1))
flag = long_to_bytes(pow(c,d,n))
print(flag)
# b'moectf{7h3_st4rt_0f_c0pp3rsmith!}'
```


## hidden-poly

题目源码如下：

```python
from Crypto.Util.Padding import pad
from Crypto.Util.number import *
from Crypto.Cipher import AES
import os


q = 264273181570520944116363476632762225021
key = os.urandom(16)
iv = os.urandom(16)
root = 122536272320154909907460423807891938232
f = sum([a*root**i for i,a in enumerate(key)])
assert key.isascii()
assert f % q == 0

with open('flag.txt','rb') as f:
    flag = f.read()

cipher = AES.new(key,AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(pad(flag,16)).hex()

with open('output.txt','w') as f:
    f.write(f"{iv = }" + "\n")
    f.write(f"{ciphertext = }" + "\n")
```

$q$ 是一个128位的素数，key为一长度为16的字节，其满足：

```python
assert key.isascii()
```

也就是说key都是由ascii字符构成的。将这16个ascii字符转换为相对应的整数，我们可以得到一个以其为系数的多项式 $f=\sum_{i=0}^{15}a_{i}\cdot x^{i}$ 

此外，我们还可以额外得到 $r_{0}$（即`root`），满足：

$$f(r_{0})\equiv 0\bmod q$$

即，多项式 $f$ 在 $\mathbb{Z}/q\mathbb{Z}$ 上有一根 $r_0$

```python
with open('flag.txt','rb') as f:
    flag = f.read()

cipher = AES.new(key,AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(pad(flag,16)).hex()

with open('output.txt','w') as f:
    f.write(f"{iv = }" + "\n")
    f.write(f"{ciphertext = }" + "\n")
```

这里笔者用AES128-CBC对flag进行了加密，key未知，而iv已知。若我们想要恢复出flag，就必须拿到key。根据题目描述：`Try to recover the unknown coefficients from the polynomial's root? What a crazy idea!`，我们需要设法从多项式 $f$ 的根 $r_0$ 出发，去恢复其系数 $a_{0},a_{1},\cdots,a_{15}$。初遇此题可能会感到有些无从下手。那么，我们不妨泡杯茶，花上100pts购买笔者为大家精心准备的`hint`，看看出题人的葫芦里究竟卖的什么药。

`hint`内容如下：[LLL algorithm's application](https://en.wikipedia.org/wiki/Lenstra%E2%80%93Lenstra%E2%80%93Lov%C3%A1sz_lattice_basis_reduction_algorithm#Applications)

> 以下内容假设读者对于格（Lattice）有一定的初步了解。格的基础知识可以通过ctfwiki上的相关内容进行简单学习。若读者感到有困难，可以先跳过本题。

在wikipedia对LLL算法的介绍中，提到了一种比较简单的应用：
$r = 1.618034$ 为一整系数二次方程的实数根的近似值，方程系数未知。我们可以应用LLL算法恢复其系数。首先注意到 $a\cdot r_{0}^2+b\cdot r_{0} + c=\delta$。其中 $\delta$ 相对较小，大约为2e-8。那么我们考虑由以如下行向量 $(0,0,1,K),(0,1,0,K\cdot r_{0}),(1,0,0,K\cdot r_{0}^2)$ 为基的格 $\mathcal{L}$，其格基矩阵为：

$$
M = \begin{pmatrix}
1 & 0 & 0 & K\\
0 & 1 & 0 & K\cdot r_0\\
0 & 0 & 1 & K\cdot r_0^2\\
\end{pmatrix}
$$

注意到其中有向量 $\vec{v}=(a,b,c)\cdot M = (a,b,c,K\cdot \delta)$

若 $a,b,c,K\cdot \delta$ 均较小的话，那么向量 $v$ 的范数将会足够小。我们可以通过对格基矩阵 $M$ 应用一次LLL算法，即可恢复短向量 $\vec{v}=(a,b,c,K\cdot \delta)$。

example:
```python
from sage.all import *
r=1.618034
K=10000
M = matrix([
    [1,0,0,floor(K*r**2)],
    [0,1,,floor(K*r)],
    [0,0,1,K]
])
v = M.LLL()[0]
print(v)
# (-1, 1, 1, 0)
```

恢复得到 $f=x^2-x-1$，其具有根 $\frac{1+\sqrt{5}}{2}\approx 1.618034$

回看本题，唯一的变化是我们是在 $\mathbb{Z}/q\mathbb{Z}$ 求得了多项式 $f$ 的根 $r_0$，格基的构造稍有不同：

$$
M = \begin{bmatrix}
K\cdot q & O_{1\times n}\\
K\cdot \vec{v}^{T} & I_{n}\\
\end{bmatrix}
$$

其中 $\vec{v}=(1,r,\cdots,r_{n-1}),n=16$

exp:
```python
from Crypto.Util.number import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from sage.all import *


q = 264273181570520944116363476632762225021
x0 = 122536272320154909907460423807891938232
K = 1<<1024
real = [K*ZZ(x0)**i for i in range(16)]
M = block_matrix([
    [Matrix(ZZ,1,1,[K*q]),zero_matrix(1,16)],
    [Matrix(ZZ,16,1,real),identity_matrix(16)]
])
v = M.LLL()
iv = b'Gc\xf2\xfd\x94\xdc\xc8\xbb\xf4\x84\xb1\xfd\x96\xcd6\\'
ciphertext = 'd23eac665cdb57a8ae7764bb4497eb2f79729537e596600ded7a068c407e67ea75e6d76eb9e23e21634b84a96424130e'
cipher0 = bytes.fromhex(ciphertext)
key = "".join([chr(v[0][i]) for i in range(1,17)]).encode()
cipher = AES.new(key,AES.MODE_CBC, iv)
m = cipher.decrypt(cipher0)
print(m)
# b'moectf{th3_first_blood_0f_LLL!@#$}\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e'
```
