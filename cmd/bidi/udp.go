package main

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type udpSender struct {
	lAddr4, lAddr6 string

	//--- Raw send options ---
	sendRaw bool
	src4    net.IP
	src6    net.IP

	checksums bool

	device  string
	sockFd4 int
	sockFd6 int
}

func newUDPSender(device, lAddr4, lAddr6 string, sendRaw, checksums bool) (*udpSender, error) {
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

	fd4, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return nil, os.NewSyscallError("socket", err)
	}

	fd6, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return nil, os.NewSyscallError("socket", err)
	}

	var u *udpSender
	if sendRaw {
		u = &udpSender{
			lAddr4: localIP4.String(),
			lAddr6: localIP6.String(),

			sendRaw: sendRaw,
			device:  device,
			src4:    localIP4,
			src6:    localIP6,

			checksums: checksums,

			sockFd4: fd4,
			sockFd6: fd6,
		}
	} else {
		u = &udpSender{
			lAddr4:  localIP4.String(),
			lAddr6:  localIP6.String(),
			sendRaw: sendRaw,
		}
	}

	return u, nil
}

func (u *udpSender) clean() {
	if u.sendRaw {
		// if were sending using raw sockets close those sockets
		syscall.Close(u.sockFd4)
		syscall.Close(u.sockFd6)
	}
}

// if sport is 0 (unset) then the Dial should generate a random source port.
func (u *udpSender) sendUDP(dst string, sport int, payload []byte, verbose bool) (string, error) {

	if u.sendRaw {
		return u.sendUDPRaw(dst, sport, payload, verbose)
	}

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

func (u *udpSender) sendUDPRaw(dst string, sport int, payload []byte, verbose bool) (string, error) {
	host, portStr, err := net.SplitHostPort(dst)
	if err != nil {
		return "", fmt.Errorf("failed to parse \"ip:port\": %s - %s", dst, err)
	}
	port, _ := strconv.Atoi(portStr)

	ip := net.ParseIP(host)

	var useV4 = ip.To4() != nil
	if useV4 && u.src4 == nil {
		return "", fmt.Errorf("no IPv4 address available")
	} else if !useV4 && u.src6 == nil {
		return "", fmt.Errorf("no IPv6 address available")
	}

	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: u.checksums,
	}

	if sport == 0 {
		// If no sport provided pick a random source port between 1000 and 65535
		// and a random value for ack
		sport = int((rand.Int31() % 64535) + 1000)
	}

	// Fill UDP  Payload layer details
	udpLayer := layers.UDP{
		SrcPort: layers.UDPPort(sport),
		DstPort: layers.UDPPort(port),
	}

	// Fill out gopacket IP header with source and dest JUST for Data layer checksums
	var networkLayer netLayer
	if useV4 {
		ipLayer4 := &layers.IPv4{
			SrcIP:    u.src4,
			DstIP:    ip,
			Version:  4,
			TTL:      64,
			Id:       uint16(rand.Uint32()),
			Protocol: layers.IPProtocolUDP,
		}
		networkLayer = ipLayer4
	} else {
		ipLayer6 := &layers.IPv6{
			SrcIP:      u.src6,
			DstIP:      ip,
			Version:    6,
			HopLimit:   64,
			FlowLabel:  rand.Uint32(),
			NextHeader: layers.IPProtocolUDP,
		}
		networkLayer = ipLayer6
	}

	udpLayer.SetNetworkLayerForChecksum(networkLayer)

	udpPayloadBuf := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(udpPayloadBuf, options, networkLayer, &udpLayer, gopacket.Payload(payload))
	if err != nil {
		return "", err
	}
	// XXX end of packet creation

	// XXX send packet
	var addr syscall.Sockaddr
	var sockFd int
	if useV4 {
		sockFd = u.sockFd4
		addr = &syscall.SockaddrInet4{
			Port: 0,
			Addr: *(*[4]byte)(ip.To4()),
		}
	} else {
		sockFd = u.sockFd6
		addr = &syscall.SockaddrInet6{
			Port: 0,
			Addr: *(*[16]byte)(ip.To16()),
		}
	}

	err = sendPkt(sockFd, udpPayloadBuf.Bytes(), addr)
	if err != nil {
		return "", err
	}

	return strconv.Itoa(sport), nil
}
