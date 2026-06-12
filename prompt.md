"任务：
使用Golang语言开发一个网站测绘cli程序，能力为输入IP网段和端口范围，输出该网段该端口范围内的mDNS协议的资产信息（至少有ip port host 深度识别banner），cli程序验证的数据集输出里的banner识别深度至少为示例所示
```text
# 示例响应部分
services:
9/tcp workstation:
Name=slw-nas [24:5e:be:69:a3:13]
IPv4=x.x.x.x
IPv6=fe80::265e:beff:fe69:a313
Hostname=slw-nas.local
TTL=10
5000/tcp http:
Name=slw-nas
IPv4=x.x.x.x
IPv6=fe80::265e:beff:fe69:a313
Hostname=slw-nas.local
TTL=10
path=/
445/tcp smb:
Name=slw-nas
IPv4=x.x.x.x
IPv6=fe80::265e:beff:fe69:a313
Hostname=slw-nas.local
TTL=10
5000/tcp qdiscover:
Name=slw-nas
IPv4=x.x.x.x
IPv6=fe80::265e:beff:fe69:a313
Hostname=slw-nas.local
TTL=10
accessType=https,accessPort=86,model=TS-X64,displayModel=TS-464C,fwVer=5.2.9,fwBuildNum=20260214
device-info:
Name=slw-nas(AFP)
IPv4=x.x.x.x
IPv6=fe80::265e:beff:fe69:a313
Hostname=slw-nas.local
TTL=10
model=Xserve
548/tcp afpovertcp:
Name=slw-nas(AFP)
IPv4=x.x.x.x
IPv6=fe80::265e:beff:fe69:a313
Hostname=slw-nas.local
TTL=10
answers:
PTR:
_workstation._tcp.local
_http._tcp.local
_smb._tcp.local
_qdiscover._tcp.local
_device-info._tcp.local
_afpovertcp._tcp.local
```

