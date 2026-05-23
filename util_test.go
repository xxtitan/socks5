package socks5

import (
	"net"
	"testing"
)

func TestParseAddress(t *testing.T) {
	t.Log(ParseAddress("127.0.0.1:80"))
	t.Log(ParseAddress("[::1]:80"))
	t.Log(ParseAddress("a.com:80"))
}

func TestGetRandomIPFromCIDR(t *testing.T) {
	tests := []struct {
		name    string
		cidrs   []string
		wantErr bool
	}{
		{
			name:    "IPv4 /24",
			cidrs:   []string{"192.168.1.0/24"},
			wantErr: false,
		},
		{
			name:    "IPv4 /16",
			cidrs:   []string{"10.0.0.0/16"},
			wantErr: false,
		},
		{
			name:    "IPv6 /64",
			cidrs:   []string{"2001:db8::/64"},
			wantErr: false,
		},
		{
			name:    "IPv6 /48",
			cidrs:   []string{"2001:db8::/48"},
			wantErr: false,
		},
		{
			name:    "IPv6 /32",
			cidrs:   []string{"2001:db8::/32"},
			wantErr: false,
		},
		{
			name:    "multiple CIDRs",
			cidrs:   []string{"192.168.0.0/24", "10.0.0.0/8", "2001:db8::/48"},
			wantErr: false,
		},
		{
			name:    "empty CIDR list",
			cidrs:   []string{},
			wantErr: true,
		},
		{
			name:    "invalid CIDR",
			cidrs:   []string{"invalid"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for i := 0; i < 5; i++ {
				ip, err := GetRandomIPFromCidrs(tt.cidrs)
				if (err != nil) != tt.wantErr {
					t.Errorf("GetRandomIPFromCidrs() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if err != nil {
					return
				}

				if len(tt.cidrs) > 0 {
					valid := false
					for _, cidr := range tt.cidrs {
						_, ipNet, _ := net.ParseCIDR(cidr)
						if ipNet.Contains(net.ParseIP(ip)) {
							valid = true
							break
						}
					}
					if !valid {
						t.Errorf("Generated IP %s is not in any of the provided CIDRs", ip)
					}
				}
			}
		})
	}
}
