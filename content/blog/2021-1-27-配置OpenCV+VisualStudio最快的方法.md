---
title: '配置OpenCV+VisualStudio最快的方法'
date: 2021-01-27T21:35:00+08:00
draft: false
---
本来想用CLion写OpenCV，但是倒腾了好久没弄好，索性换成了OpenCV+VisualStudio

下面是配置OpenCV+VisualStudio的步骤：

首先，安装VS。

记住在安装时要在“语言包”中勾选英语

![image-20210127212233540](https://i.loli.net/2021/01/27/DVkpr4FixBQPAq6.png)

如果你已经安装过VS并且没有安装英语语言包，请打开Visual Studio installer

点击修改![image-20210127212407056](https://i.loli.net/2021/01/27/SFQdZO4gNKWv3me.png)

补充安装英语语言包



接下来安装[vcpkg](https://github.com/microsoft/vcpkg/tree/2020.11-1#quick-start-windows)

你可以自己根据github上的文档安装vcpkg，也可以按照下方的操作安装vcpkg+opencv：

- git clone https://github.com/microsoft/vcpkg
- .\vcpkg\bootstrap-vcpkg.bat
- .\vcpkg\vcpkg install opencv
- .\vcpkg\vcpkg integrate install



接下来打开VS起一个项目

```
#include <opencv2/opencv.hpp>
#include <iostream>

using namespace std;
using namespace cv;

int main()
{
	//读取本地的一张图片便显示出来
	Mat img = imread("D:\\demo.JPG");
	imshow("cat Tom", img);
	//等待用户按键
	waitKey(0);
	return 0;
}
```

Ctrl+F5编译运行，如果有没有翻车就是配置好了