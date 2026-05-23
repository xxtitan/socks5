## socks5

[中文](README_ZH.md)

[![Go Report Card](https://goreportcard.com/badge/github.com/xxtitan/socks5)](https://goreportcard.com/report/github.com/xxtitan/socks5)
[![GoDoc](https://godoc.org/github.com/xxtitan/socks5?status.svg)](https://godoc.org/github.com/xxtitan/socks5)

[🗣 News](https://t.me/s/txthinking_news)
[🩸 Youtube](https://www.youtube.com/txthinking)

SOCKS Protocol Version 5 Library.

Full TCP/UDP and IPv4/IPv6 support.
Goals: KISS, less is more, small API, code is like the original protocol.

❤️ A project by [txthinking.com](https://www.txthinking.com)

### Install

```
$ go get github.com/xxtitan/socks5
```

### Struct is like concept in protocol

-   Negotiation:
    -   `type NegotiationRequest struct`
        -   `func NewNegotiationRequest(methods []byte)`, in client
        -   `func (r *NegotiationRequest) WriteTo(w io.Writer)`, client writes to server
        -   `func NewNegotiationRequestFrom(r io.Reader)`, server reads from client
    -   `type NegotiationReply struct`
        -   `func NewNegotiationReply(method byte)`, in server
        -   `func (r *NegotiationReply) WriteTo(w io.Writer)`, server writes to client
        -   `func NewNegotiationReplyFrom(r io.Reader)`, client reads from server
-   User and password negotiation:
    -   `type UserPassNegotiationRequest struct`
        -   `func NewUserPassNegotiationRequest(username []byte, password []byte)`, in client
        -   `func (r *UserPassNegotiationRequest) WriteTo(w io.Writer)`, client writes to server
        -   `func NewUserPassNegotiationRequestFrom(r io.Reader)`, server reads from client
    -   `type UserPassNegotiationReply struct`
        -   `func NewUserPassNegotiationReply(status byte)`, in server
        -   `func (r *UserPassNegotiationReply) WriteTo(w io.Writer)`, server writes to client
        -   `func NewUserPassNegotiationReplyFrom(r io.Reader)`, client reads from server
-   Request:
    -   `type Request struct`
        -   `func NewRequest(cmd byte, atyp byte, dstaddr []byte, dstport []byte)`, in client
        -   `func (r *Request) WriteTo(w io.Writer)`, client writes to server
        -   `func NewRequestFrom(r io.Reader)`, server reads from client
        -   After server gets the client's \*Request, processes...
-   Reply:
    -   `type Reply struct`
        -   `func NewReply(rep byte, atyp byte, bndaddr []byte, bndport []byte)`, in server
        -   `func (r *Reply) WriteTo(w io.Writer)`, server writes to client
        -   `func NewReplyFrom(r io.Reader)`, client reads from server
-   Datagram:
    -   `type Datagram struct`
        -   `func NewDatagram(atyp byte, dstaddr []byte, dstport []byte, data []byte)`
        -   `func NewDatagramFromBytes(bb []byte)`
        -   `func (d *Datagram) Bytes()`

### Advanced API

> This can satisfy the classic scenario, and it is still recommended that you choose the above small API to customize for special scenarios.

**Server**: support both TCP and UDP

-   `type Server struct`
-   `type Handler interface`
    -   `TCPHandle(*Server, *net.TCPConn, *Request, *User) error`
    -   `UDPHandle(*Server, *net.UDPAddr, *Datagram) error`
-   `func NewServer(addr, host, username, password string, bindCidrs []string, tcpTimeout, udpTimeout int) (*Server, error)`
-   `func NewClassicServer(addr, host, username, password string, tcpTimeout, udpTimeout int) (*Server, error)`

Example:

```
server, _ := socks5.NewServer(addr, host, username, password, bindCidrs, tcpTimeout, udpTimeout)
server.ListenAndServe(Handler)
```

`bindCidrs` controls the outbound source IP pool. It accepts IPv4 and IPv6 CIDRs, for example:

```
bindCidrs := []string{"198.18.0.0/15", "2001:db8::/48"}
server, _ := socks5.NewServer("127.0.0.1:1080", "127.0.0.1", "titan", "secret", bindCidrs, 600, 600)
```

When both IPv4 and IPv6 CIDRs are available, the dialer selects a target IP version that is compatible with the destination and then chooses a source IP from the matching CIDR list. If the destination only supports one IP version, the matching CIDR family must be configured.

#### Password session format

The username/password authentication password may include an outbound-IP session suffix:

-   `password`: authenticate with the configured password only.
-   `password-session`: authenticate with `password` and carry `session` as the session id. The outbound IP is not cached without `duration`.
-   `password-session-duration`: authenticate with `password`, use `session` as the session id, and reuse the selected outbound IP for `duration`.

`duration` supports `s`, `m`, `h`, and `d`, for example `30s`, `10m`, `2h`, or `1d`.

Example:

```
client, _ := socks5.NewClient("127.0.0.1:1080", "titan", "secret-user1-1h", 600, 600)
```

The server validates only the base password before the first `-`. In the example above, the configured server password is `secret`, the session id is `user1`, and the selected outbound IP is reused for one hour. If the session suffix is used, keep the base password free of `-`.

**Client**: support both TCP and UDP and return net.Conn

-   `type Client struct`

Example:

```
client, _ := socks5.NewClient(server, username, password, tcpTimeout, udpTimeout)
conn, _ := client.Dial(network, addr)
```

### Projects using this library

-   Brook: https://github.com/txthinking/brook
-   Shiliew: https://www.txthinking.com/shiliew.html
-   dismap: https://github.com/zhzyker/dismap
-   emp3r0r: https://github.com/jm33-m0/emp3r0r
-   hysteria: https://github.com/apernet/hysteria
-   mtg: https://github.com/9seconds/mtg
-   trojan-go: https://github.com/p4gefau1t/trojan-go


## License

Licensed under The MIT License
