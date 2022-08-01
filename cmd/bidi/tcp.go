package main

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type tcpSender struct {
	src4 net.IP
	src6 net.IP

	device  string
	sockFd4 int
	sockFd6 int
}

// newTCPSender builds and inits new tcp sender. Gets source addresses
// for public v4 and v6 IPs (or uses locals if provided).
//
// Make sure to defer cleanup to // avoid leaving hanging sockets.
func newTCPSender(device, lAddr4, lAddr6 string) (*tcpSender, error) {
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

	t := &tcpSender{
		src4:   localIP4,
		src6:   localIP6,
		device: device,

		sockFd4: fd4,
		sockFd6: fd6,
	}

	return t, nil
}

func (t *tcpSender) cleanTCPSender() {
	syscall.Close(t.sockFd4)
	syscall.Close(t.sockFd6)
}

func (t *tcpSender) sendTCP(dst string, payload []byte, synDelay time.Duration, sendSynAck, checksums, verbose bool) (string, error) {

	host, portStr, err := net.SplitHostPort(dst)
	if err != nil {
		return "", fmt.Errorf("failed to parse \"ip:port\": %s - %s", dst, err)
	}
	port, _ := strconv.Atoi(portStr)

	ip := net.ParseIP(host)

	var useV4 = ip.To4() != nil
	if useV4 && t.src4 == nil {
		return "", fmt.Errorf("no IPv4 address available")
	} else if !useV4 && t.src6 == nil {
		return "", fmt.Errorf("no IPv6 address available")
	}

	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: checksums,
	}

	// Pick a random source port between 1000 and 65535
	randPort := (rand.Int31() % 64535) + 1000
	seq := rand.Uint32()
	ack := rand.Uint32()

	// Fill TCP  Payload layer details
	tcpLayer := layers.TCP{
		SrcPort: layers.TCPPort(randPort),
		DstPort: layers.TCPPort(port),
		PSH:     true,
		ACK:     true,
		Window:  502,
		Seq:     seq + 1,
		Ack:     ack,
	}
	seqAck := fmt.Sprintf("%x %x", seq+1, ack)

	// Fill out gopacket IP header with source and dest JUST for Data layer checksums
	var networkLayer netLayer
	if useV4 {
		ipLayer4 := &layers.IPv4{
			SrcIP:    t.src4,
			DstIP:    ip,
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolTCP,
		}
		networkLayer = ipLayer4
	} else {
		ipLayer6 := &layers.IPv6{
			SrcIP:      t.src6,
			DstIP:      ip,
			Version:    6,
			HopLimit:   64,
			NextHeader: layers.IPProtocolTCP,
		}
		networkLayer = ipLayer6
	}

	tcpLayer.SetNetworkLayerForChecksum(networkLayer)

	// build syn, ack, and data payloads
	synBuf, err := getSyn(uint32(randPort), uint32(port), seq, options, networkLayer)
	if err != nil {
		return "", err
	}
	ackBuf, err := getAck(uint32(randPort), uint32(port), seq+1, ack, options, networkLayer)
	if err != nil {
		return "", err
	}

	tcpPayloadBuf := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(tcpPayloadBuf, options, networkLayer, &tcpLayer, gopacket.Payload(payload))
	if err != nil {
		return "", err
	}
	// XXX end of packet creation

	// XXX send packet
	var addr syscall.Sockaddr
	var sockFd int
	if useV4 {
		sockFd = t.sockFd4
		addr = &syscall.SockaddrInet4{
			Port: 0,
			Addr: *(*[4]byte)(ip.To4()),
		}
	} else {
		sockFd = t.sockFd6
		addr = &syscall.SockaddrInet6{
			Port: 0,
			Addr: *(*[16]byte)(ip.To16()),
		}
	}

	if sendSynAck {
		err = sendPkt(sockFd, synBuf, addr)
		if err != nil {
			return "", err
		}

		time.Sleep(synDelay)

		err = sendPkt(sockFd, ackBuf, addr)
		if err != nil {
			return "", err
		}
	}

	err = sendPkt(sockFd, tcpPayloadBuf.Bytes(), addr)
	if err != nil {
		return "", err
	}

	return seqAck, nil
}

type netLayer interface {
	gopacket.SerializableLayer
	gopacket.NetworkLayer
}

func sendPkt(sockFd int, payload []byte, addr syscall.Sockaddr) error {
	err := syscall.Sendto(sockFd, payload, 0, addr)
	if err != nil {
		return os.NewSyscallError("sendto", err)
	}
	stats.incPacketPerSec()
	stats.incBytesPerSec(len(payload))

	return nil
}

func getSyn(srcPort, dstPort, seq uint32, options gopacket.SerializeOptions, ipLayer netLayer) ([]byte, error) {
	synLayer := layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		SYN:     true,
		Window:  28800,
		Seq:     seq,
		Ack:     0,
		Options: []layers.TCPOption{
			layers.TCPOption{
				OptionType:   layers.TCPOptionKindMSS,
				OptionLength: 4,
				OptionData:   []byte{0x05, 0xa0},
			},
			layers.TCPOption{
				OptionType:   layers.TCPOptionKindSACKPermitted,
				OptionLength: 2,
			},
			layers.TCPOption{
				OptionType: layers.TCPOptionKindNop,
			},
			layers.TCPOption{
				OptionType:   layers.TCPOptionKindWindowScale,
				OptionLength: 3,
				OptionData:   []byte{0x07},
			},
		},
	}

	synLayer.SetNetworkLayerForChecksum(ipLayer)

	tcpPayloadBuf := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(tcpPayloadBuf, options, ipLayer, &synLayer)
	if err != nil {
		return nil, err
	}
	return tcpPayloadBuf.Bytes(), nil
}
func getAck(srcPort, dstPort, seq, ack uint32, options gopacket.SerializeOptions, ipLayer netLayer) ([]byte, error) {

	ackLayer := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		ACK:     true,
		Window:  225,
		Seq:     seq,
		Ack:     ack,
		Options: []layers.TCPOption{
			layers.TCPOption{
				OptionType: layers.TCPOptionKindNop,
			},
			layers.TCPOption{
				OptionType: layers.TCPOptionKindNop,
			},
		},
	}

	ackLayer.SetNetworkLayerForChecksum(ipLayer)

	tcpPayloadBuf := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(tcpPayloadBuf, options, ipLayer, ackLayer)
	if err != nil {
		return nil, err
	}
	return tcpPayloadBuf.Bytes(), nil
}
