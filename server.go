package socks5

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/txthinking/runnergroup"
)

var (
	// ErrUnsupportCmd is the error when got unsupported command
	ErrUnsupportCmd = errors.New("unsupported command")
	// ErrUserPassAuth is the error when got invalid username or password
	ErrUserPassAuth = errors.New("invalid username or password for auth")
)

// Server is socks5 server wrapper
type Server struct {
	UserName          string
	Password          string
	Method            byte
	SupportedCommands []byte
	Addr              string
	ServerAddr        net.Addr
	UDPConn           *net.UDPConn
	UDPExchanges      *cache.Cache
	TCPTimeout        int
	UDPTimeout        int
	Handle            Handler
	AssociatedUDP     *cache.Cache
	UDPSrc            *cache.Cache
	RunnerGroup       *runnergroup.RunnerGroup
	// RFC: [UDP ASSOCIATE] The server MAY use this information to limit access to the association. Default false, no limit.
	LimitUDP bool
	// bind outgoing cidr
	BindCidrs      []string
	BindCidrsV4    []string // IPv4 CIDRs
	BindCidrsV6    []string // IPv6 CIDRs
	AssociatedIP   *cache.Cache
	AssociatedUser *cache.Cache
}

// UDPExchange used to store client address and remote connection
type UDPExchange struct {
	ClientAddr *net.UDPAddr
	RemoteConn net.Conn
}

// User is the socks user who connect to the server
type User struct {
	Username        string
	Password        string
	RealPassword    string
	SessionID       string
	SessionDuration time.Duration
}

// parsePassword parses password, password-session, or password-session-duration.
func parsePassword(password string) (realPassword, sessionID string, duration time.Duration) {
	parts := strings.Split(password, "-")

	if len(parts) == 1 {
		return password, "", 0
	}

	if len(parts) == 2 {
		return parts[0], parts[1], 0
	}

	realPassword = parts[0]
	durationStr := parts[len(parts)-1]
	sessionID = strings.Join(parts[1:len(parts)-1], "-")

	duration, _ = parseDuration(durationStr)

	return realPassword, sessionID, duration
}

// parseDuration parses durations with s, m, h, or d suffixes.
func parseDuration(s string) (time.Duration, error) {
	if len(s) < 2 {
		return 0, fmt.Errorf("invalid duration format")
	}

	unit := s[len(s)-1:]
	valueStr := s[:len(s)-1]

	value, err := time.ParseDuration(valueStr + unit)
	if err == nil {
		return value, nil
	}

	if unit == "d" {
		var days int
		_, err := fmt.Sscanf(valueStr, "%d", &days)
		if err != nil {
			return 0, err
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}

	return 0, fmt.Errorf("invalid duration format")
}

// NewServer return a server which allow none method and support bind outgoing cidr
func NewServer(addr, host, username, password string, bindCidrs []string, tcpTimeout, udpTimeout int) (*Server, error) {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	saddr, err := Resolve("udp", net.JoinHostPort(host, p))
	if err != nil {
		return nil, err
	}
	m := MethodNone
	if username != "" || password != "" {
		m = MethodUsernamePassword
	}
	v4Cidrs, v6Cidrs := ClassifyCIDRs(bindCidrs)
	s := &Server{
		Method:            m,
		UserName:          username,
		Password:          password,
		SupportedCommands: []byte{CmdConnect, CmdUDP},
		Addr:              addr,
		ServerAddr:        saddr,
		UDPExchanges:      cache.New(cache.NoExpiration, cache.NoExpiration),
		TCPTimeout:        tcpTimeout,
		UDPTimeout:        udpTimeout,
		AssociatedUDP:     cache.New(cache.NoExpiration, cache.NoExpiration),
		UDPSrc:            cache.New(cache.NoExpiration, cache.NoExpiration),
		RunnerGroup:       runnergroup.New(),
		BindCidrs:         bindCidrs,
		BindCidrsV4:       v4Cidrs,
		BindCidrsV6:       v6Cidrs,
		AssociatedUser:    cache.New(time.Minute*1, time.Second*10),
		AssociatedIP:      cache.New(time.Minute*1, time.Second*10),
	}
	return s, nil
}

// NewClassicServer return a server which allow none method
func NewClassicServer(addr, host, username, password string, tcpTimeout, udpTimeout int) (*Server, error) {
	return NewServer(addr, host, username, password, nil, tcpTimeout, udpTimeout)
}

// Negotiate handle negotiate packet.
// This method do not handle gssapi(0x01) method now.
// Error or OK both replied.
func (s *Server) Negotiate(rw io.ReadWriter) (*User, error) {
	rq, err := NewNegotiationRequestFrom(rw)
	if err != nil {
		return nil, err
	}
	var got bool
	var m byte
	for _, m = range rq.Methods {
		if m == s.Method {
			got = true
		}
	}
	if !got {
		rp := NewNegotiationReply(MethodUnsupportAll)
		if _, err := rp.WriteTo(rw); err != nil {
			return nil, err
		}
	}
	rp := NewNegotiationReply(s.Method)
	if _, err := rp.WriteTo(rw); err != nil {
		return nil, err
	}

	if s.Method == MethodUsernamePassword {
		urq, err := NewUserPassNegotiationRequestFrom(rw)
		if err != nil {
			return nil, err
		}
		if s.UserName != "" && string(urq.Uname) != s.UserName {
			urp := NewUserPassNegotiationReply(UserPassStatusFailure)
			if _, err := urp.WriteTo(rw); err != nil {
				return nil, err
			}
			return nil, ErrUserPassAuth
		}

		clientPassword := string(urq.Passwd)
		realPassword, sessionID, duration := parsePassword(clientPassword)

		if s.Password != "" && realPassword != s.Password {
			urp := NewUserPassNegotiationReply(UserPassStatusFailure)
			if _, err := urp.WriteTo(rw); err != nil {
				return nil, err
			}
			return nil, ErrUserPassAuth
		}

		urp := NewUserPassNegotiationReply(UserPassStatusSuccess)
		if _, err := urp.WriteTo(rw); err != nil {
			return nil, err
		}

		return &User{
			Username:        string(urq.Uname),
			Password:        clientPassword,
			RealPassword:    realPassword,
			SessionID:       sessionID,
			SessionDuration: duration,
		}, nil
	}
	return nil, nil
}

// GetRequest get request packet from client, and check command according to SupportedCommands
// Error replied.
func (s *Server) GetRequest(rw io.ReadWriter) (*Request, error) {
	r, err := NewRequestFrom(rw)
	if err != nil {
		return nil, err
	}
	var supported bool
	for _, c := range s.SupportedCommands {
		if r.Cmd == c {
			supported = true
			break
		}
	}
	if !supported {
		var p *Reply
		if r.Atyp == ATYPIPv4 || r.Atyp == ATYPDomain {
			p = NewReply(RepCommandNotSupported, ATYPIPv4, []byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00})
		} else {
			p = NewReply(RepCommandNotSupported, ATYPIPv6, []byte(net.IPv6zero), []byte{0x00, 0x00})
		}
		if _, err := p.WriteTo(rw); err != nil {
			return nil, err
		}
		return nil, ErrUnsupportCmd
	}
	return r, nil
}

// ListenAndServe Run the server
func (s *Server) ListenAndServe(h Handler) error {
	if h == nil {
		s.Handle = &DefaultHandle{}
	} else {
		s.Handle = h
	}
	addr, err := net.ResolveTCPAddr("tcp", s.Addr)
	if err != nil {
		return err
	}
	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return err
	}
	s.RunnerGroup.Add(&runnergroup.Runner{
		Start: func() error {
			for {
				c, err := l.AcceptTCP()
				if err != nil {
					return err
				}
				go func(c *net.TCPConn) {
					defer c.Close()
					u, err := s.Negotiate(c)
					if err != nil {
						log.Println(err)
						return
					}
					r, err := s.GetRequest(c)
					if err != nil {
						log.Println(err)
						return
					}
					if err := s.Handle.TCPHandle(s, c, r, u); err != nil {
						log.Println(err)
					}
				}(c)
			}
		},
		Stop: func() error {
			return l.Close()
		},
	})
	uAddr, err := net.ResolveUDPAddr("udp", s.Addr)
	if err != nil {
		l.Close()
		return err
	}
	s.UDPConn, err = net.ListenUDP("udp", uAddr)
	if err != nil {
		l.Close()
		return err
	}
	s.RunnerGroup.Add(&runnergroup.Runner{
		Start: func() error {
			for {
				b := make([]byte, 65507)
				n, addr, err := s.UDPConn.ReadFromUDP(b)
				if err != nil {
					return err
				}
				go func(addr *net.UDPAddr, b []byte) {
					d, err := NewDatagramFromBytes(b)
					if err != nil {
						log.Println(err)
						return
					}
					if d.Frag != 0x00 {
						log.Println("Ignore frag", d.Frag)
						return
					}
					if err := s.Handle.UDPHandle(s, addr, d); err != nil {
						log.Println(err)
						return
					}
				}(addr, b[0:n])
			}
		},
		Stop: func() error {
			return s.UDPConn.Close()
		},
	})
	return s.RunnerGroup.Wait()
}

// Shutdown Stop the server
func (s *Server) Shutdown() error {
	return s.RunnerGroup.Done()
}

// GetOutgoingIP returns a cached outbound IP or the configured CIDR groups.
func (s *Server) GetOutgoingIP(u *User) (string, []string, []string) {
	if u == nil || u.Username == "" || u.SessionID == "" {
		return "", s.BindCidrsV4, s.BindCidrsV6
	}

	cacheKey := u.Username + u.SessionID

	if u.SessionDuration > 0 {
		if i, ok := s.AssociatedIP.Get(cacheKey); ok {
			return i.(string), nil, nil
		}
	}

	return "", s.BindCidrsV4, s.BindCidrsV6
}

// cacheOutgoingIP caches a session's outbound IP after a successful dial.
func (s *Server) cacheOutgoingIP(u *User, ip string) {
	if u == nil || u.Username == "" || u.SessionID == "" {
		return
	}
	if u.SessionDuration > 0 {
		cacheKey := u.Username + u.SessionID
		s.AssociatedIP.Set(cacheKey, ip, u.SessionDuration)
		log.Printf("Cached IP %s for username: %s, session: %s, duration: %v\n",
			ip, u.Username, u.SessionID, u.SessionDuration)
	}
}

// Handler handle tcp, udp request
type Handler interface {
	// Request has not been replied yet
	TCPHandle(*Server, *net.TCPConn, *Request, *User) error
	UDPHandle(*Server, *net.UDPAddr, *Datagram) error
}

// DefaultHandle implements Handler interface
type DefaultHandle struct {
}

// TCPHandle auto handle request. You may prefer to do yourself.
func (h *DefaultHandle) TCPHandle(s *Server, c *net.TCPConn, r *Request, u *User) error {
	if r.Cmd == CmdConnect {
		rc, err := func(server *Server) (net.Conn, error) {
			ip, v4Cidrs, v6Cidrs := s.GetOutgoingIP(u)
			if ip != "" {
				return r.ConnectWithLaddr(net.JoinHostPort(ip, "0"), c)
			} else if len(v4Cidrs) > 0 || len(v6Cidrs) > 0 {
				return r.ConnectWithCidrs(v4Cidrs, v6Cidrs, u, s, c)
			} else {
				return r.Connect(c)
			}
		}(s)
		if err != nil {
			return err
		}
		defer rc.Close()
		go func() {
			var bf [1024 * 2]byte
			for {
				if s.TCPTimeout != 0 {
					if err := rc.SetDeadline(time.Now().Add(time.Duration(s.TCPTimeout) * time.Second)); err != nil {
						return
					}
				}
				i, err := rc.Read(bf[:])
				if err != nil {
					if err == io.EOF {
						c.CloseWrite()
					}
					return
				}
				if _, err := c.Write(bf[0:i]); err != nil {
					return
				}
			}
		}()
		var bf [1024 * 2]byte
		for {
			if s.TCPTimeout != 0 {
				if err := c.SetDeadline(time.Now().Add(time.Duration(s.TCPTimeout) * time.Second)); err != nil {
					return nil
				}
			}
			i, err := c.Read(bf[:])
			if err != nil {
				if err == io.EOF {
					if tcpConn, ok := rc.(*net.TCPConn); ok {
						tcpConn.CloseWrite()
					}
				}
				return nil
			}
			if _, err := rc.Write(bf[0:i]); err != nil {
				return nil
			}
		}
	}
	if r.Cmd == CmdUDP {
		caddr, err := r.UDP(c, s.ServerAddr)
		if err != nil {
			return err
		}
		ch := make(chan byte)
		defer close(ch)
		s.AssociatedUDP.Set(caddr.String(), ch, cache.DefaultExpiration)
		s.AssociatedUser.Set(caddr.String(), u, cache.DefaultExpiration)
		defer s.AssociatedUDP.Delete(caddr.String())
		io.Copy(io.Discard, c)
		if Debug {
			log.Printf("A tcp connection that udp %#v associated closed\n", caddr.String())
		}
		return nil
	}
	return ErrUnsupportCmd
}

// UDPHandle auto handle packet. You may prefer to do yourself.
func (h *DefaultHandle) UDPHandle(s *Server, addr *net.UDPAddr, d *Datagram) error {
	src := addr.String()
	var ch chan byte
	if s.LimitUDP {
		any, ok := s.AssociatedUDP.Get(src)
		if !ok {
			return fmt.Errorf("this udp address %s is not associated with tcp", src)
		}
		ch = any.(chan byte)
	}
	send := func(ue *UDPExchange, data []byte) error {
		select {
		case <-ch:
			return fmt.Errorf("this udp address %s is not associated with tcp", src)
		default:
			_, err := ue.RemoteConn.Write(data)
			if err != nil {
				return err
			}
			if Debug {
				log.Printf("Sent UDP data to remote. client: %#v server: %#v remote: %#v data: %#v\n", ue.ClientAddr.String(), ue.RemoteConn.LocalAddr().String(), ue.RemoteConn.RemoteAddr().String(), data)
			}
		}
		return nil
	}

	dst := d.Address()
	var ue *UDPExchange
	iue, ok := s.UDPExchanges.Get(src + dst)
	if ok {
		ue = iue.(*UDPExchange)
		return send(ue, d.Data)
	}

	if Debug {
		log.Printf("Call udp: %#v\n", dst)
	}
	var laddr string
	var v4Cidrs, v6Cidrs []string
	srcAddr, ok := s.UDPSrc.Get(src + dst)
	if ok {
		laddr = srcAddr.(string)
	}
	u, uok := s.AssociatedUser.Get(src)
	if uok {
		ip, v4, v6 := s.GetOutgoingIP(u.(*User))
		if ip != "" {
			laddr = net.JoinHostPort(ip, "0")
		} else {
			v4Cidrs = v4
			v6Cidrs = v6
		}
	} else {
		v4Cidrs = s.BindCidrsV4
		v6Cidrs = s.BindCidrsV6
	}
	rc, err := DialUDP("udp", laddr, dst, v4Cidrs, v6Cidrs)
	if err != nil && (len(s.BindCidrsV4) > 0 || len(s.BindCidrsV6) > 0) {
		if !strings.Contains(err.Error(), "address already in use") && !strings.Contains(err.Error(), "can't assign requested address") {
			return err
		}
		laddr = ""
		v4Cidrs = s.BindCidrsV4
		v6Cidrs = s.BindCidrsV6
		rc, err = DialUDP("udp", laddr, dst, v4Cidrs, v6Cidrs)
		if err != nil {
			return err
		}
		if uok {
			user := u.(*User)
			if laddr == "" {
				localAddr := rc.LocalAddr().String()
				host, _, _ := net.SplitHostPort(localAddr)
				laddr = net.JoinHostPort(host, "0")
				s.cacheOutgoingIP(user, host)
			}
		}
	} else if err != nil {
		return err
	} else if uok && laddr == "" {
		user := u.(*User)
		localAddr := rc.LocalAddr().String()
		host, _, _ := net.SplitHostPort(localAddr)
		laddr = net.JoinHostPort(host, "0")
		s.cacheOutgoingIP(user, host)
	}
	s.UDPSrc.Set(src+dst, laddr, -1)
	ue = &UDPExchange{
		ClientAddr: addr,
		RemoteConn: rc,
	}
	if Debug {
		log.Printf("Created remote UDP conn for client. client: %#v server: %#v remote: %#v\n", addr.String(), ue.RemoteConn.LocalAddr().String(), d.Address())
	}
	if err := send(ue, d.Data); err != nil {
		ue.RemoteConn.Close()
		return err
	}
	s.UDPExchanges.Set(src+dst, ue, -1)
	go func(ue *UDPExchange, dst string) {
		defer func() {
			ue.RemoteConn.Close()
			s.UDPExchanges.Delete(ue.ClientAddr.String() + dst)
		}()
		var b [65507]byte
		for {
			select {
			case <-ch:
				if Debug {
					log.Printf("The tcp that udp address %s associated closed\n", ue.ClientAddr.String())
				}
				return
			default:
				if s.UDPTimeout != 0 {
					if err := ue.RemoteConn.SetDeadline(time.Now().Add(time.Duration(s.UDPTimeout) * time.Second)); err != nil {
						log.Println(err)
						return
					}
				}
				n, err := ue.RemoteConn.Read(b[:])
				if err != nil {
					return
				}
				if Debug {
					log.Printf("Got UDP data from remote. client: %#v server: %#v remote: %#v data: %#v\n", ue.ClientAddr.String(), ue.RemoteConn.LocalAddr().String(), ue.RemoteConn.RemoteAddr().String(), b[0:n])
				}
				a, addr, port, err := ParseAddress(dst)
				if err != nil {
					log.Println(err)
					return
				}
				if a == ATYPDomain {
					addr = addr[1:]
				}
				d1 := NewDatagram(a, addr, port, b[0:n])
				if _, err := s.UDPConn.WriteToUDP(d1.Bytes(), ue.ClientAddr); err != nil {
					return
				}
				if Debug {
					log.Printf("Sent Datagram. client: %#v server: %#v remote: %#v data: %#v %#v %#v %#v %#v %#v datagram address: %#v\n", ue.ClientAddr.String(), ue.RemoteConn.LocalAddr().String(), ue.RemoteConn.RemoteAddr().String(), d1.Rsv, d1.Frag, d1.Atyp, d1.DstAddr, d1.DstPort, d1.Data, d1.Address())
				}
			}
		}
	}(ue, dst)
	return nil
}
