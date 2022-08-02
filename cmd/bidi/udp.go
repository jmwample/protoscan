package main

import (
	"fmt"
	"log"
	"net"
	"strconv"
)

type udpSender struct {
	lAddr4, lAddr6 string
}

func newUDPSender(device, lAddr4, lAddr6 string) (*udpSender, error) {
	localIface, err := net.InterfaceByName(device)
	if err != nil {
		return nil, fmt.Errorf("bad device name: \"%s\"", device)
	}

	localIP4, err := getSrcIP(localIface, lAddr4, net.ParseIP("1.2.3.4"))
	if err != nil {
		return nil, err
	}

	localIP6, err := getSrcIP(localIface, lAddr6, net.ParseIP("2606:4700::"))
	if err != nil {
		log.Println("failed to init IPv6 - likely not supported")
	}

	return &udpSender{lAddr4: localIP4.String(), lAddr6: localIP6.String()}, nil
}

//
// if sport is 0 (unset) then the Dial should generate a random source port.
func (u *udpSender) sendUDP(dst string, sport int, payload []byte, verbose bool) (string, error) {
	var d net.Dialer

	host, _, err := net.SplitHostPort(dst)
	if err != nil {
		return "", fmt.Errorf("failed to parse \"ip:port\": %s - %s", dst, err)
	}

	useV4 := net.ParseIP(host).To4() != nil
	if useV4 {
		if u.lAddr4 == "" {
			return "", fmt.Errorf("no IPv4 address available")
		}
		d.LocalAddr, err = net.ResolveUDPAddr("udp", net.JoinHostPort(u.lAddr4, strconv.Itoa(sport)))
		if err != nil {
			log.Println(err)
		}
	} else if !useV4 {
		if u.lAddr6 == "" {
			return "", fmt.Errorf("no IPv6 address available")
		}
		d.LocalAddr, _ = net.ResolveUDPAddr("ip", net.JoinHostPort(u.lAddr6, strconv.Itoa(sport)))
	}

	conn, err := d.Dial("udp", dst)
	if err != nil {
		return "", fmt.Errorf("%s - error creating UDP socket(?): %v", dst, err)
	}
	defer conn.Close()

	n, err := conn.Write(payload)
	if err != nil {
		return "", err
	}
	stats.incPacketPerSec()
	stats.incBytesPerSec(n)

	h := conn.LocalAddr().String()
	_, p, err := net.SplitHostPort(h)

	return p, err
}
