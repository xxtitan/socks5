package socks5

import (
	"fmt"
	"net"
)

var Debug bool

func init() {
	// log.SetFlags(log.LstdFlags | log.Lshortfile)
}

var Resolve func(network string, addr string) (net.Addr, error) = func(network string, addr string) (net.Addr, error) {
	if network == "tcp" {
		return net.ResolveTCPAddr("tcp", addr)
	}
	return net.ResolveUDPAddr("udp", addr)
}

// selectIPByVersion selects a remote address matching the local bind IP version.
func selectIPByVersion(laddr, raddr string) (string, error) {
	host, port, err := net.SplitHostPort(raddr)
	if err != nil {
		return "", err
	}

	laddrHost, _, _ := net.SplitHostPort(laddr)
	if laddrHost == "" {
		laddrHost = laddr
	}
	localIP := net.ParseIP(laddrHost)
	if localIP == nil {
		return "", net.InvalidAddrError("invalid local address " + laddr)
	}
	localIsIPv6 := localIP.To4() == nil

	if remoteIP := net.ParseIP(host); remoteIP != nil {
		remoteIsIPv6 := remoteIP.To4() == nil
		if localIsIPv6 != remoteIsIPv6 {
			return "", net.InvalidAddrError("target IP version does not match local bind address")
		}
		return raddr, nil
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return "", err
	}

	for _, ip := range ips {
		if localIsIPv6 == (ip.To4() == nil) {
			return net.JoinHostPort(ip.String(), port), nil
		}
	}

	return "", net.InvalidAddrError("no matching IP version for " + host)
}

// selectIPVersionAndGenerate selects a compatible target IP version and outbound IP.
func selectIPVersionAndGenerate(targetHost string, targetPort string, v4Cidrs, v6Cidrs []string) (string, string, error) {
	ips, err := net.LookupIP(targetHost)
	if err != nil {
		return "", "", fmt.Errorf("failed to resolve %s: %v", targetHost, err)
	}

	hasIPv4 := false
	hasIPv6 := false
	for _, ip := range ips {
		if ip.To4() != nil {
			hasIPv4 = true
		} else {
			hasIPv6 = true
		}
	}

	if hasIPv4 && !hasIPv6 && len(v4Cidrs) == 0 && len(v6Cidrs) > 0 {
		return "", "", fmt.Errorf("target %s only supports IPv4, but only IPv6 CIDRs are available", targetHost)
	}
	if hasIPv6 && !hasIPv4 && len(v6Cidrs) == 0 && len(v4Cidrs) > 0 {
		return "", "", fmt.Errorf("target %s only supports IPv6, but only IPv4 CIDRs are available", targetHost)
	}

	preferIPv6 := false
	if (len(v4Cidrs) > 0 && len(v6Cidrs) > 0) || len(v6Cidrs) > 0 {
		if hasIPv6 && len(v6Cidrs) > 0 {
			preferIPv6 = true
		} else if hasIPv4 && len(v4Cidrs) > 0 {
			preferIPv6 = false
		} else {
			if len(v6Cidrs) > 0 {
				preferIPv6 = true
			} else if len(v4Cidrs) > 0 {
				preferIPv6 = false
			}
		}
	} else if len(v4Cidrs) > 0 {
		preferIPv6 = false
	} else {
		return "", "", fmt.Errorf("no CIDRs available")
	}

	outgoingIP, isIPv6, err := GetRandomIPFromCidrsWithVersion(v4Cidrs, v6Cidrs, preferIPv6)
	if err != nil {
		return "", "", err
	}

	var targetIP string
	for _, ip := range ips {
		ipIsV6 := ip.To4() == nil
		if ipIsV6 == isIPv6 {
			targetIP = net.JoinHostPort(ip.String(), targetPort)
			break
		}
	}

	if targetIP == "" {
		return "", "", fmt.Errorf("no matching IP version for target %s", targetHost)
	}

	return outgoingIP, targetIP, nil
}

var DialTCP func(network string, laddr, raddr string, v4Cidrs, v6Cidrs []string) (net.Conn, error) = func(network string, laddr, raddr string, v4Cidrs, v6Cidrs []string) (net.Conn, error) {
	if laddr == "" && (len(v4Cidrs) > 0 || len(v6Cidrs) > 0) {
		host, port, err := net.SplitHostPort(raddr)
		if err != nil {
			return nil, err
		}

		if targetIP := net.ParseIP(host); targetIP != nil {
			isIPv6 := targetIP.To4() == nil
			if isIPv6 && len(v6Cidrs) == 0 {
				return nil, fmt.Errorf("target %s is IPv6, but no IPv6 CIDRs are available", host)
			}
			if !isIPv6 && len(v4Cidrs) == 0 {
				return nil, fmt.Errorf("target %s is IPv4, but no IPv4 CIDRs are available", host)
			}
			outgoingIP, _, err := GetRandomIPFromCidrsWithVersion(v4Cidrs, v6Cidrs, isIPv6)
			if err != nil {
				return nil, err
			}
			laddr = net.JoinHostPort(outgoingIP, "0")
		} else {
			outgoingIP, targetAddr, err := selectIPVersionAndGenerate(host, port, v4Cidrs, v6Cidrs)
			if err != nil {
				return nil, err
			}
			laddr = net.JoinHostPort(outgoingIP, "0")
			raddr = targetAddr
		}
	} else if laddr != "" {
		var err error
		raddr, err = selectIPByVersion(laddr, raddr)
		if err != nil {
			return nil, err
		}
	}

	la, err := net.ResolveTCPAddr(network, laddr)
	if err != nil && laddr != "" {
		return nil, err
	}

	ra, err := net.ResolveTCPAddr(network, raddr)
	if err != nil {
		return nil, err
	}

	return net.DialTCP(network, la, ra)
}

var DialUDP func(network string, laddr, raddr string, v4Cidrs, v6Cidrs []string) (net.Conn, error) = func(network string, laddr, raddr string, v4Cidrs, v6Cidrs []string) (net.Conn, error) {
	if laddr == "" && (len(v4Cidrs) > 0 || len(v6Cidrs) > 0) {
		host, port, err := net.SplitHostPort(raddr)
		if err != nil {
			return nil, err
		}

		if targetIP := net.ParseIP(host); targetIP != nil {
			isIPv6 := targetIP.To4() == nil
			if isIPv6 && len(v6Cidrs) == 0 {
				return nil, fmt.Errorf("target %s is IPv6, but no IPv6 CIDRs are available", host)
			}
			if !isIPv6 && len(v4Cidrs) == 0 {
				return nil, fmt.Errorf("target %s is IPv4, but no IPv4 CIDRs are available", host)
			}
			outgoingIP, _, err := GetRandomIPFromCidrsWithVersion(v4Cidrs, v6Cidrs, isIPv6)
			if err != nil {
				return nil, err
			}
			laddr = net.JoinHostPort(outgoingIP, "0")
		} else {
			outgoingIP, targetAddr, err := selectIPVersionAndGenerate(host, port, v4Cidrs, v6Cidrs)
			if err != nil {
				return nil, err
			}
			laddr = net.JoinHostPort(outgoingIP, "0")
			raddr = targetAddr
		}
	} else if laddr != "" {
		var err error
		raddr, err = selectIPByVersion(laddr, raddr)
		if err != nil {
			return nil, err
		}
	}

	la, err := net.ResolveUDPAddr(network, laddr)
	if err != nil && laddr != "" {
		return nil, err
	}

	ra, err := net.ResolveUDPAddr(network, raddr)
	if err != nil {
		return nil, err
	}

	return net.DialUDP(network, la, ra)
}
