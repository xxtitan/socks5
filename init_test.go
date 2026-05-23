package socks5

import (
	"net"
	"testing"
)

func TestSelectIPByVersion_DirectIPVersionMismatch(t *testing.T) {
	laddr := net.JoinHostPort("2001:db8::1", "0")
	raddr := net.JoinHostPort("1.1.1.1", "53")

	_, err := selectIPByVersion(laddr, raddr)
	if err == nil {
		t.Fatalf("expected version mismatch error, got nil")
	}
}

func TestSelectIPByVersion_DirectIPVersionMatch(t *testing.T) {
	laddr := net.JoinHostPort("2001:db8::1", "0")
	raddr := net.JoinHostPort("2001:4860:4860::8888", "53")

	got, err := selectIPByVersion(laddr, raddr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != raddr {
		t.Fatalf("unexpected address: got %s, want %s", got, raddr)
	}
}

func TestDialTCP_RejectsIPv4TargetWhenOnlyIPv6CIDRs(t *testing.T) {
	_, err := DialTCP("tcp", "", net.JoinHostPort("1.1.1.1", "80"), nil, []string{"2001:db8::/64"})
	if err == nil {
		t.Fatalf("expected error when dialing IPv4 target with only IPv6 CIDRs")
	}
}

func TestDialUDP_RejectsIPv4TargetWhenOnlyIPv6CIDRs(t *testing.T) {
	_, err := DialUDP("udp", "", net.JoinHostPort("1.1.1.1", "53"), nil, []string{"2001:db8::/64"})
	if err == nil {
		t.Fatalf("expected error when dialing IPv4 target with only IPv6 CIDRs")
	}
}
