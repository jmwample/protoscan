package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"sync"

	"github.com/google/gopacket/routing"
)

var stats *sendStats = &sendStats{}

type sendStats struct {
	// packets per epoch
	ppe int64
	// bytes per epoch
	bpe int64
	// packets total
	pt int64
	// bytes total
	bt int64

	mu sync.Mutex
}

func (s *sendStats) incPacketPerSec() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ppe++
	s.pt++
}

func (s *sendStats) incBytesPerSec(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bpe += int64(n)
	s.bt += int64(n)
}

func (s *sendStats) epochReset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bpe = 0
	s.ppe = 0
}

// getSrcIP allows us to check that there is a route to the dest with our
// suggested source address and interface. This also allows the program to
// automatically recover from an ipv4 source address specified for an IPv6
// target address by using the preferred source address provided by the call to
// RouteWithSource. That way we don't have to support v4 and v6 local address
// cli options. Also allows for empty or bad source from cli.
func getSrcIP(localIface *net.Interface, lAddr string, dstIP net.IP) (net.IP, error) {
	var useV4 = dstIP.To4() != nil

	var localIP = net.ParseIP(lAddr)
	if useV4 && localIP.To4() == nil {
		localIP = nil
	} else if !useV4 && localIP.To4() != nil {
		localIP = nil
	}

	router, err := routing.New()
	if err != nil {
		return nil, fmt.Errorf("failed to init routing: %s", err)
	}

	// ignore gateway, but adopt preferred source if unsuitable lAddr was specified.
	_, _, preferredSrc, err := router.RouteWithSrc(localIface.HardwareAddr, localIP, dstIP)
	if err != nil {
		return nil, fmt.Errorf("failed to get remote iface: %s", err)
	}

	// If the specified local IP is unset or the wrong IP version for the target
	// substitute the preferred source.
	if localIP == nil {
		localIP = preferredSrc
	}

	return localIP, nil
}


func decodeOrPanic(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
