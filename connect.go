package socks5

import (
	"io"
	"log"
	"net"
	"strings"
)

// Connect remote conn which u want to connect with your dialer
// Error or OK both replied.
func (r *Request) Connect(w io.Writer) (net.Conn, error) {
	return r.ConnectWithLaddr("", w)
}

// ConnectWithLaddr remote conn which u want to connect with your dialer and specify local address.
// Error or OK both replied.
func (r *Request) ConnectWithLaddr(laddr string, w io.Writer) (net.Conn, error) {
	if Debug {
		log.Printf("Call: %s, localAddr: %s", r.Address(), laddr)
	}
	rc, err := DialTCP("tcp", laddr, r.Address(), nil, nil)
	if err != nil {
		var p *Reply
		if r.Atyp == ATYPIPv4 || r.Atyp == ATYPDomain {
			p = NewReply(RepHostUnreachable, ATYPIPv4, []byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00})
		} else {
			p = NewReply(RepHostUnreachable, ATYPIPv6, []byte(net.IPv6zero), []byte{0x00, 0x00})
		}
		if _, err := p.WriteTo(w); err != nil {
			return nil, err
		}
		return nil, err
	}

	a, addr, port, err := ParseAddress(rc.LocalAddr().String())
	if err != nil {
		rc.Close()
		var p *Reply
		if r.Atyp == ATYPIPv4 || r.Atyp == ATYPDomain {
			p = NewReply(RepHostUnreachable, ATYPIPv4, []byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00})
		} else {
			p = NewReply(RepHostUnreachable, ATYPIPv6, []byte(net.IPv6zero), []byte{0x00, 0x00})
		}
		if _, err := p.WriteTo(w); err != nil {
			return nil, err
		}
		return nil, err
	}
	if a == ATYPDomain {
		addr = addr[1:]
	}
	p := NewReply(RepSuccess, a, addr, port)
	if _, err := p.WriteTo(w); err != nil {
		rc.Close()
		return nil, err
	}

	return rc, nil
}

// ConnectWithCidrs connects with an outbound IP selected from the provided CIDRs.
func (r *Request) ConnectWithCidrs(v4Cidrs, v6Cidrs []string, u *User, s *Server, w io.Writer) (net.Conn, error) {
	if Debug {
		log.Printf("Call: %s, with CIDRs (v4: %d, v6: %d)", r.Address(), len(v4Cidrs), len(v6Cidrs))
	}
	rc, err := DialTCP("tcp", "", r.Address(), v4Cidrs, v6Cidrs)
	if err != nil {
		var p *Reply
		if r.Atyp == ATYPIPv4 || r.Atyp == ATYPDomain {
			p = NewReply(RepHostUnreachable, ATYPIPv4, []byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00})
		} else {
			p = NewReply(RepHostUnreachable, ATYPIPv6, []byte(net.IPv6zero), []byte{0x00, 0x00})
		}
		if _, err := p.WriteTo(w); err != nil {
			return nil, err
		}
		return nil, err
	}

	if u != nil && s != nil {
		localAddr := rc.LocalAddr().String()
		host, _, err := net.SplitHostPort(localAddr)
		if err == nil {
			host = strings.Trim(host, "[]")
			s.cacheOutgoingIP(u, host)
		}
	}

	a, addr, port, err := ParseAddress(rc.LocalAddr().String())
	if err != nil {
		rc.Close()
		var p *Reply
		if r.Atyp == ATYPIPv4 || r.Atyp == ATYPDomain {
			p = NewReply(RepHostUnreachable, ATYPIPv4, []byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00})
		} else {
			p = NewReply(RepHostUnreachable, ATYPIPv6, []byte(net.IPv6zero), []byte{0x00, 0x00})
		}
		if _, err := p.WriteTo(w); err != nil {
			return nil, err
		}
		return nil, err
	}
	if a == ATYPDomain {
		addr = addr[1:]
	}
	p := NewReply(RepSuccess, a, addr, port)
	if _, err := p.WriteTo(w); err != nil {
		rc.Close()
		return nil, err
	}

	return rc, nil
}
