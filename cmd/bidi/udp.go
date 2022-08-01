package main

import (
	"fmt"
	"net"
)

type udpSender struct {
	lAddr4, lAddr6 string
}

func newUDPSender(lAddr4, lAddr6 string) (*udpSender, error) {
	return &udpSender{lAddr4, lAddr6}, nil
}

func (u *udpSender) sendUDP(dst string, payload []byte, verbose bool) error {
	var d net.Dialer

	useV4 := net.ParseIP(dst).To4() != nil
	if useV4 {
		if u.lAddr4 == "" {
			return fmt.Errorf("no IPv4 address available")
		}
		d.LocalAddr, _ = net.ResolveUDPAddr("ip", u.lAddr4)

	} else if !useV4 {
		if u.lAddr6 == "" {
			return fmt.Errorf("no IPv6 address available")
		}
		d.LocalAddr, _ = net.ResolveUDPAddr("ip", u.lAddr6)
	}

	conn, err := d.Dial("udp", dst)
	if err != nil {
		return fmt.Errorf("%s - error creating UDP socket(?): %v", dst, err)
	}
	defer conn.Close()

	n, err := conn.Write(payload)
	if err == nil {
		stats.incPacketPerSec()
		stats.incBytesPerSec(n)
	}

	return err
}
