## socks5

[English](README.md)

[![Go Report Card](https://goreportcard.com/badge/github.com/xxtitan/socks5)](https://goreportcard.com/report/github.com/xxtitan/socks5)
[![GoDoc](https://godoc.org/github.com/xxtitan/socks5?status.svg)](https://godoc.org/github.com/xxtitan/socks5)

[🗣 News](https://t.me/s/txthinking_news)
[🩸 Youtube](https://www.youtube.com/txthinking)

SOCKS Protocol Version 5 Library.

完整 TCP/UDP 和 IPv4/IPv6 支持.
目标: KISS, less is more, small API, code is like the original protocol.

❤️ A project by [txthinking.com](https://www.txthinking.com)

### 获取
```
$ go get github.com/xxtitan/socks5
```

### Struct的概念 对标 原始协议里的概念

* Negotiation:
    * `type NegotiationRequest struct`
        * `func NewNegotiationRequest(methods []byte)`, in client
        * `func (r *NegotiationRequest) WriteTo(w io.Writer)`, client writes to server
        * `func NewNegotiationRequestFrom(r io.Reader)`, server reads from client
    * `type NegotiationReply struct`
        * `func NewNegotiationReply(method byte)`, in server
        * `func (r *NegotiationReply) WriteTo(w io.Writer)`, server writes to client
        * `func NewNegotiationReplyFrom(r io.Reader)`, client reads from server
* User and password negotiation:
    * `type UserPassNegotiationRequest struct`
        * `func NewUserPassNegotiationRequest(username []byte, password []byte)`, in client
        * `func (r *UserPassNegotiationRequest) WriteTo(w io.Writer)`, client writes to server
        * `func NewUserPassNegotiationRequestFrom(r io.Reader)`, server reads from client
    * `type UserPassNegotiationReply struct`
        * `func NewUserPassNegotiationReply(status byte)`, in server
        * `func (r *UserPassNegotiationReply) WriteTo(w io.Writer)`, server writes to client
        * `func NewUserPassNegotiationReplyFrom(r io.Reader)`, client reads from server
* Request:
    * `type Request struct`
        * `func NewRequest(cmd byte, atyp byte, dstaddr []byte, dstport []byte)`, in client
        * `func (r *Request) WriteTo(w io.Writer)`, client writes to server
        * `func NewRequestFrom(r io.Reader)`, server reads from client
        * After server gets the client's *Request, processes...
* Reply:
    * `type Reply struct`
        * `func NewReply(rep byte, atyp byte, bndaddr []byte, bndport []byte)`, in server
        * `func (r *Reply) WriteTo(w io.Writer)`, server writes to client
        * `func NewReplyFrom(r io.Reader)`, client reads from server
* Datagram:
    * `type Datagram struct`
        * `func NewDatagram(atyp byte, dstaddr []byte, dstport []byte, data []byte)`
        * `func NewDatagramFromBytes(bb []byte)`
        * `func (d *Datagram) Bytes()`

### 高级 API

> 这可以满足经典场景，特殊场景推荐你选择上面的小API来自定义。

**Server**: 支持UDP和TCP

* `type Server struct`
* `type Handler interface`
    * `TCPHandle(*Server, *net.TCPConn, *Request, *User) error`
    * `UDPHandle(*Server, *net.UDPAddr, *Datagram) error`
* `func NewServer(addr, host, username, password string, bindCidrs []string, tcpTimeout, udpTimeout int) (*Server, error)`
* `func NewClassicServer(addr, host, username, password string, tcpTimeout, udpTimeout int) (*Server, error)`

举例:

```
server, _ := socks5.NewServer(addr, host, username, password, bindCidrs, tcpTimeout, udpTimeout)
server.ListenAndServe(Handler)
```

`bindCidrs` 用于配置出站源 IP 池，支持 IPv4 和 IPv6 CIDR，例如：

```
bindCidrs := []string{"198.18.0.0/15", "2001:db8::/48"}
server, _ := socks5.NewServer("127.0.0.1:1080", "127.0.0.1", "titan", "secret", bindCidrs, 600, 600)
```

当同时配置 IPv4 和 IPv6 CIDR 时，拨号逻辑会根据目标地址支持的 IP 版本选择兼容的目标 IP，并从对应 CIDR 中选择出站源 IP。如果目标只支持某一个 IP 版本，服务端必须配置对应版本的 CIDR。

#### 密码 session 拼接格式

用户名密码认证中的密码字段可以拼接出站 IP session 信息：

* `password`：只使用配置的密码认证。
* `password-session`：使用 `password` 认证，并携带 `session` 作为 session id；不带 `duration` 时不会缓存出站 IP。
* `password-session-duration`：使用 `password` 认证，使用 `session` 作为 session id，并在 `duration` 时间内复用选中的出站 IP。

`duration` 支持 `s`、`m`、`h`、`d`，例如 `30s`、`10m`、`2h`、`1d`。

示例：

```
client, _ := socks5.NewClient("127.0.0.1:1080", "titan", "secret-user1-1h", 600, 600)
```

服务端只校验第一个 `-` 之前的基础密码。以上示例中，服务端配置的密码是 `secret`，session id 是 `user1`，选中的出站 IP 会复用一小时。如果使用 session 后缀，基础密码不要包含 `-`。

**Client**: 支持TCP和UDP, 返回net.Conn

* `type Client struct`

举例:

```
client, _ := socks5.NewClient(server, username, password, tcpTimeout, udpTimeout)
conn, _ := client.Dial(network, addr)
```


### 谁在使用此项目

-   Brook: https://github.com/txthinking/brook
-   Shiliew: https://www.txthinking.com/shiliew.html
-   dismap: https://github.com/zhzyker/dismap
-   emp3r0r: https://github.com/jm33-m0/emp3r0r
-   hysteria: https://github.com/apernet/hysteria
-   mtg: https://github.com/9seconds/mtg
-   trojan-go: https://github.com/p4gefau1t/trojan-go

## 开源协议

基于 MIT 协议开源
