---
title: wordpress、Typecho、zblog和emlog留言自动填写个人信息方法
author: 杨 成锴
type: post
date: 2017-03-11T14:31:12+00:00
url: /?p=817
views:
  - 677
ta-thumbnail:
  - NoMediaFound
wp_player_music_type:
  - xiami
mp3_xiami_type:
  - song
wp_player_lyric_open:
  - close
categories:
  - Wordpress

---
经常，我们要去其他的博客互访，可是有的并不是使用的社会化评论，那么我们就要慢慢输入个人信息，可是访问量的了，慢慢输入同样枯燥的文字总是感觉很烦人的！

前段时间曾经介绍过WordPress自动填充的方法 点击这里查看

一样我们可以通过js来实现自动填写昵称、邮箱和地址。

但是只是支持WordPress 的评论可用 像EMLOG ZBLOG 建站的也有不少总不能那些 自个填写吧，作为一个懒人，我们决计不能这么做的！

但是 在没有留下任何信息的情况下，辨析建站系统也不是一件容易的事情。
所以下面隆重推出下面的新功能！

自动识别 建站系统 对建站系统进行 分别填写

保证多种系统间一个代码搞定！

但是唯一不足的是在emlog中 很多主题的开发者，在主题中改进或XX东西。

导致emlog 中并不能全部完成

```js
var myName = '<你的昵称>';var myEmail = '<你的邮箱地址>';var myUrl = '<你的Blog地址，可不填>'; function fillForm(blogIdSelector, authorSelector, urlSelector, emailSelector) { if (blogIdSelector != null) { var blogId = document.querySelector(blogIdSelector); if (blogId == null) { return false; } } var author = document.querySelector(authorSelector); if (author == null) { return false; } author.setAttribute('value', myName); var url = document.querySelector(urlSelector); if (url != null) { url.setAttribute('value', myUrl); } var email = document.querySelector(emailSelector); if (email == null) { return false; } email.setAttribute('value', myEmail); return true;}var blogList = { 'wordpress': function() {return fillForm('#commentform', '#author', '#url', '#email');}, 'typecho': function() {return fillForm('#comment_form', '#author', '#url', '#mail');}, 'z_blog': function() {return fillForm('#frmSumbit', '#inpName', '#inpHomePage', '#inpEmail');}, 'emlog': function() {return fillForm('#commentform', 'input[name="comname"]', 'input[name="comurl"]', 'input[name="commail"]');}};for (var i in blogList) { if (blogList[i]()) { break; }}
```



使用方法，还是老办法，保存个收藏夹，用的时候一点就好……
使用教程

1、将本页保存为书签。

2、右键刚刚创建的书签，选择“编辑”。

3、将“名称”一栏改为“任意啦”（见名知意即可，名称可换成其它的），并将“网址”一栏原有的信息替换成以下内容：

当然有的浏览器可能不支持，你可以填写后，将js压缩一下。



来自：李明博客