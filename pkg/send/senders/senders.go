package senders

import (
	"fmt"
	"net"
	"os"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/routing"
)

func SendPkt(sockFd int, payload []byte, addr syscall.Sockaddr) error {
	err := syscall.Sendto(sockFd, payload, 0, addr)
	if err != nil {
		return os.NewSyscallError("sendto", err)
	}

	IncStats(len(payload))

	return nil
}

func IncStats(bytes int) {
	Stats.incPacketPerSec()
	Stats.incBytesPerSec(bytes)
}

// getSrcIP allows us to check that there is a route to the dest with our
// suggested source address and interface. This also allows the program to
// automatically recover from an ipv4 source address specified for an IPv6
// target address by using the preferred source address provided by the call to
// RouteWithSource. That way we don't have to support v4 and v6 local address
// cli options. Also allows for empty or bad source from cli.
func GetSrcIP(localIface *net.Interface, lAddr string, dstIP net.IP) (net.IP, error) {
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

type NetLayer interface {
	gopacket.SerializableLayer
	gopacket.NetworkLayer
}
