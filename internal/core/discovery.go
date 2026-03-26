package core

import (
	"net"
	"strings"
	"time"
)

// DiscoveredHost holds a host found via local network discovery.
type DiscoveredHost struct {
	IP     string
	Source string // "ssdp" or "mdns"
}

// SSDPDiscover sends an M-SEARCH probe to 239.255.255.250:1900 and collects
// responding UPnP device IPs on the local network.
func SSDPDiscover(timeout time.Duration) ([]DiscoveredHost, error) {
	conn, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	msg := []byte("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n")
	dst, _ := net.ResolveUDPAddr("udp4", "239.255.255.250:1900")
	if _, err := conn.WriteTo(msg, dst); err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var hosts []DiscoveredHost
	buf := make([]byte, 2048)

	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			break
		}
		_ = n
		ip := addr.(*net.UDPAddr).IP.String()
		if !seen[ip] {
			seen[ip] = true
			hosts = append(hosts, DiscoveredHost{IP: ip, Source: "ssdp"})
		}
	}
	return hosts, nil
}

// MDNSDiscover sends a PTR query to 224.0.0.251:5353 and collects responding
// mDNS/Bonjour device IPs on the local network.
func MDNSDiscover(timeout time.Duration) ([]DiscoveredHost, error) {
	conn, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// Minimal mDNS PTR query for _services._dns-sd._udp.local
	query := []byte{
		0x00, 0x00, // Transaction ID
		0x00, 0x00, // Flags: standard query
		0x00, 0x01, // Questions: 1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Answer/Auth/Additional RRs
		// _services._dns-sd._udp.local
		0x09, '_', 's', 'e', 'r', 'v', 'i', 'c', 'e', 's',
		0x07, '_', 'd', 'n', 's', '-', 's', 'd',
		0x04, '_', 'u', 'd', 'p',
		0x05, 'l', 'o', 'c', 'a', 'l',
		0x00,
		0x00, 0x0c, // Type: PTR
		0x00, 0x01, // Class: IN
	}

	dst, _ := net.ResolveUDPAddr("udp4", "224.0.0.251:5353")
	if _, err := conn.WriteTo(query, dst); err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var hosts []DiscoveredHost
	buf := make([]byte, 4096)

	for {
		_, addr, err := conn.ReadFrom(buf)
		if err != nil {
			break
		}
		ip := addr.(*net.UDPAddr).IP.String()
		// Skip multicast group address itself
		if !seen[ip] && !strings.HasPrefix(ip, "224.") {
			seen[ip] = true
			hosts = append(hosts, DiscoveredHost{IP: ip, Source: "mdns"})
		}
	}
	return hosts, nil
}

// LocalNetworkDiscover runs both SSDP and mDNS probes and returns deduplicated results.
func LocalNetworkDiscover(timeout time.Duration) []DiscoveredHost {
	seen := make(map[string]bool)
	var all []DiscoveredHost

	add := func(hosts []DiscoveredHost) {
		for _, h := range hosts {
			if !seen[h.IP] {
				seen[h.IP] = true
				all = append(all, h)
			}
		}
	}

	if hosts, err := SSDPDiscover(timeout); err == nil {
		add(hosts)
	}
	if hosts, err := MDNSDiscover(timeout); err == nil {
		add(hosts)
	}
	return all
}
