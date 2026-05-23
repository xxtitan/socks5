package socks5

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"net"
	"strconv"
	"time"
)

// ParseAddress format address x.x.x.x:xx to raw address.
// addr contains domain length
func ParseAddress(address string) (a byte, addr []byte, port []byte, err error) {
	var h, p string
	h, p, err = net.SplitHostPort(address)
	if err != nil {
		return
	}
	ip := net.ParseIP(h)
	if ip4 := ip.To4(); ip4 != nil {
		a = ATYPIPv4
		addr = []byte(ip4)
	} else if ip6 := ip.To16(); ip6 != nil {
		a = ATYPIPv6
		addr = []byte(ip6)
	} else {
		a = ATYPDomain
		addr = []byte{byte(len(h))}
		addr = append(addr, []byte(h)...)
	}
	i, _ := strconv.Atoi(p)
	port = make([]byte, 2)
	binary.BigEndian.PutUint16(port, uint16(i))
	return
}

// bytes to address
// addr contains domain length
func ParseBytesAddress(b []byte) (a byte, addr []byte, port []byte, err error) {
	if len(b) < 1 {
		err = errors.New("invalid address")
		return
	}
	a = b[0]
	if a == ATYPIPv4 {
		if len(b) < 1+4+2 {
			err = errors.New("invalid address")
			return
		}
		addr = b[1 : 1+4]
		port = b[1+4 : 1+4+2]
		return
	}
	if a == ATYPIPv6 {
		if len(b) < 1+16+2 {
			err = errors.New("invalid address")
			return
		}
		addr = b[1 : 1+16]
		port = b[1+16 : 1+16+2]
		return
	}
	if a == ATYPDomain {
		if len(b) < 1+1 {
			err = errors.New("invalid address")
			return
		}
		l := int(b[1])
		if len(b) < 1+1+l+2 {
			err = errors.New("invalid address")
			return
		}
		addr = b[1 : 1+1+l]
		port = b[1+1+l : 1+1+l+2]
		return
	}
	err = errors.New("invalid address")
	return
}

// ToAddress format raw address to x.x.x.x:xx
// addr contains domain length
func ToAddress(a byte, addr []byte, port []byte) string {
	var h, p string
	if a == ATYPIPv4 || a == ATYPIPv6 {
		h = net.IP(addr).String()
	}
	if a == ATYPDomain {
		if len(addr) < 1 {
			return ""
		}
		if len(addr) < int(addr[0])+1 {
			return ""
		}
		h = string(addr[1:])
	}
	p = strconv.Itoa(int(binary.BigEndian.Uint16(port)))
	return net.JoinHostPort(h, p)
}

// Address return request address like ip:xx
func (r *Request) Address() string {
	var s string
	if r.Atyp == ATYPDomain {
		s = bytes.NewBuffer(r.DstAddr[1:]).String()
	} else {
		s = net.IP(r.DstAddr).String()
	}
	p := strconv.Itoa(int(binary.BigEndian.Uint16(r.DstPort)))
	return net.JoinHostPort(s, p)
}

// Address return request address like ip:xx
func (r *Reply) Address() string {
	var s string
	if r.Atyp == ATYPDomain {
		s = bytes.NewBuffer(r.BndAddr[1:]).String()
	} else {
		s = net.IP(r.BndAddr).String()
	}
	p := strconv.Itoa(int(binary.BigEndian.Uint16(r.BndPort)))
	return net.JoinHostPort(s, p)
}

// Address return datagram address like ip:xx
func (d *Datagram) Address() string {
	var s string
	if d.Atyp == ATYPDomain {
		s = bytes.NewBuffer(d.DstAddr[1:]).String()
	} else {
		s = net.IP(d.DstAddr).String()
	}
	p := strconv.Itoa(int(binary.BigEndian.Uint16(d.DstPort)))
	return net.JoinHostPort(s, p)
}

// ClassifyCIDRs splits CIDRs by IP version.
func ClassifyCIDRs(cidrs []string) (v4Cidrs, v6Cidrs []string) {
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if ipNet.IP.To4() != nil {
			v4Cidrs = append(v4Cidrs, cidr)
		} else {
			v6Cidrs = append(v6Cidrs, cidr)
		}
	}
	return v4Cidrs, v6Cidrs
}

func GetRandomIPFromCidrs(cidrs []string) (string, error) {
	if len(cidrs) == 0 {
		return "", fmt.Errorf("no CIDRs provided")
	}

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	selectedCIDR := cidrs[r.Intn(len(cidrs))]

	_, ipNet, err := net.ParseCIDR(selectedCIDR)
	if err != nil {
		return "", fmt.Errorf("invalid CIDR: %v", err)
	}

	networkIP := ipNet.IP
	ones, bits := ipNet.Mask.Size()

	if bits == 128 && ones < 64 {
		networkIP = networkIP.To16()
		subnetBits := 64 - ones
		maxSubnets := new(big.Int).Lsh(big.NewInt(1), uint(subnetBits))
		randomSubnet := new(big.Int).Rand(r, maxSubnets)

		needBytes := (subnetBits + 7) / 8
		subnetBytes := make([]byte, needBytes)
		randomSubnet.FillBytes(subnetBytes)

		startByte := ones / 8
		startBit := ones % 8

		for i := 0; i < needBytes && startByte+i < 8; i++ {
			if i == 0 && startBit > 0 {
				mask := byte(0xFF >> startBit)
				networkIP[startByte+i] = (networkIP[startByte+i] & ^mask) | (subnetBytes[i] & mask)
			} else {
				networkIP[startByte+i] |= subnetBytes[i]
			}
		}

		ones = 64
	}

	hostBits := bits - ones
	maxHosts := new(big.Int).Lsh(big.NewInt(1), uint(hostBits))
	randomHost := new(big.Int).Rand(r, maxHosts)

	randomIP := make(net.IP, len(networkIP))
	copy(randomIP, networkIP)

	needBytes := (hostBits + 7) / 8
	hostBytes := make([]byte, needBytes)
	randomHost.FillBytes(hostBytes)

	startByte := ones / 8
	startBit := ones % 8

	for i := 0; i < needBytes && startByte+i < len(randomIP); i++ {
		if i == 0 && startBit > 0 {
			mask := byte(0xFF >> startBit)
			randomIP[startByte+i] = (randomIP[startByte+i] & ^mask) | (hostBytes[i] & mask)
		} else {
			randomIP[startByte+i] |= hostBytes[i]
		}
	}

	return randomIP.String(), nil
}

// GetRandomIPFromCidrsWithVersion generates a random IP from CIDRs of the preferred IP version.
func GetRandomIPFromCidrsWithVersion(v4Cidrs, v6Cidrs []string, preferIPv6 bool) (string, bool, error) {
	var targetCidrs []string
	var isIPv6 bool

	if preferIPv6 {
		if len(v6Cidrs) > 0 {
			targetCidrs = v6Cidrs
			isIPv6 = true
		} else if len(v4Cidrs) > 0 {
			targetCidrs = v4Cidrs
			isIPv6 = false
		}
	} else {
		if len(v4Cidrs) > 0 {
			targetCidrs = v4Cidrs
			isIPv6 = false
		} else if len(v6Cidrs) > 0 {
			targetCidrs = v6Cidrs
			isIPv6 = true
		}
	}

	if len(targetCidrs) == 0 {
		return "", false, fmt.Errorf("no CIDRs available")
	}

	ip, err := GetRandomIPFromCidrs(targetCidrs)
	if err != nil {
		return "", false, err
	}

	return ip, isIPv6, nil
}
