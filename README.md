# FullTCore
FullTClash的专用代理后端，基于clash内核改动。本人不会Golang开发，所以有缺点请及时指出谢谢。

## 分支
* 当前为meta分支，支持更多代理协议。
* 
## 二进制文件

请前往github action页面获取，不会进行分发。

## 编译

1、在项目根目录新建名为 build.key 的文件\
2、在该文件中写入你的 buildtoken,编译token可以任意定义。\
3、执行命令:
```shell
go build -ldflags="-s -w" fulltclash.go
```
提供 gvisor TUN栈支持（wireguard协议要用到）:
```shell
go build -tags with_gvisor -ldflags="-s -w" fulltclash.go
```
## 特性

没有新的特性，把上游项目 Clash的拿来改改了，使之与FullTClash契合。
要说有，就是自带一个简单的通讯解密。

## 使用

输入以下命令查看使用方法
```shell
fulltclash -h 
```

## 致谢

* [Clash](https://github.com/Dreamacro/clash)
* [Clash.Meta](https://github.com/metacubex/clash.meta)
