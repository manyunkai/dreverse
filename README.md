# dreverse

DReverse 用于与 LAN 背后的主机建立 TCP 连接通道，从而方便公网到内网的通信，扮演类似于“反向代理”的角色。
本工程是用于学习使用。采用类似的原理并灵活变通，可以实现很多有趣的功能。

访问 https://www.dannysite.com/blog/247/ 以了解更多。

### 运行环境
---
* Python 2.7.3+ 或 Python 3.4+
* 需要 pycrypto 用于 AES 加密

### 如何使用
---
在控制节点（通常是一台运行在公网环境中且具有公网 IP 的设备）运行 master.py，支持的参数：
* -l 或 --local：所要监听的本地端口，如 127.0.0.1:1081
* -e 或 --remote：所要监听的远程端口，用于 slave 与 master 建立连接，如 0.0.0.0:50076
* -s 或 --secret：用于 AES 加密的密钥，需与 slave 的 secret 相对应，必须是 16 位、32 位或 64 位长度，分别对应 AES128、AES256 和 AES 512
* -t：连接超时时间，如 120，则在 120 之内没有数据交互，则断开连接
* --log-level：日志级别，可以是 DEBUG、INFO、WARNING、ERROR 或 CRITICAL

如 python master.py -l 127.0.0.1:1081 -e 0.0.0.0:50067 -s nN31mnOq0ek4UBXxecl4WnLeCoYOfTQJ -t 120 --log-level DEBUG

在反向连接节点（通常是一台运行在内网环境中的设备）运行 slave.py，支持的参数：
* -l 或 --local：目标地址，即远程设备所要通信的“真实”地址，如 127.0.0.1:22
* -e 或 --remote：所要连接的远程端口，即 master 的地址，如 127.0.0.1:50076
* -s 或 --secret：用于 AES 加密的密钥，需与 master 的 secret 相对应，必须是 16 位、32 位或 64 位长度，分别对应 AES128、AES256 和 AES 512
* -t：连接超时时间，如 120，则在 120 之内没有数据交互，则断开连接
* --log-level：日志级别，可以是 DEBUG、INFO、WARNING、ERROR 或 CRITICAL

如 python slaver.py -l 127.0.0.1:22 -e 192.168.204.1:50067  -s nN31mnOq0ek4UBXxecl4WnLeCoYOfTQJ -t 120 --log-level DEBUG

默认情况下，master 和 slave 之间将总是建立并维护 5 个空闲连接，当空闲连接被占用时，会再次补充空闲连接。
