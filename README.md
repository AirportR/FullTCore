# FullTCore
FullTClash的专用代理后端，基于clash内核改动。

## 编译

此项目不提供二进制文件

1、在项目根目录新建名为 build.key 的文件\
2、在该文件中写入你的 buildtoken,编译token可以任意定义。\
3、执行命令:
```shell
go build fulltclash.go
```

## 特性

没有新的特性，把上游项目 Clash的拿来改改了，使之与FullTClash契合。
要说有，就是自带一个简单的通讯解密。

## 使用

输入以下命令查看使用方法
```shell
fulltclash -h 
```