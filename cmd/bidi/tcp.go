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
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type tcpSender struct {
	src4 net.IP
	src6 net.IP

	device string
	sockFd int
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

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return nil, os.NewSyscallError("socket", err)
	}

	t := &tcpSender{
		src4:   localIP4,
		src6:   localIP6,
		device: device,

		sockFd: fd,
	}

	return t, nil
}

func (t *tcpSender) cleanTCPSender() {
	syscall.Close(t.sockFd)
}

func (t *tcpSender) sendTCP(dst string, payload []byte, synDelay time.Duration, sendSynAck, checksums, verbose bool) (string, error) {

	host, portStr, err := net.SplitHostPort(dst)
	if err != nil {
		return "", fmt.Errorf("failed to parse \"ip:port\": %s - %s", dst, err)
	}
	port, _ := strconv.Atoi(portStr)

	ip := net.ParseIP(host)

	var useV4 = ip.To4() != nil
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
	var ipLayer gopacket.SerializableLayer
	var networkLayer gopacket.NetworkLayer
	if useV4 {
		ipLayer4 := &layers.IPv4{
			SrcIP:    t.src4,
			DstIP:    ip,
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolTCP,
		}
		networkLayer = ipLayer4
		ipLayer = ipLayer4
	} else {
		ipLayer6 := &layers.IPv6{
			SrcIP:      t.src6,
			DstIP:      ip,
			Version:    6,
			HopLimit:   64,
			NextHeader: layers.IPProtocolTCP,
		}
		networkLayer = ipLayer6
		ipLayer = ipLayer6
	}

	tcpLayer.SetNetworkLayerForChecksum(networkLayer)

	// serialize IP header buf
	ipHeaderBuf := gopacket.NewSerializeBuffer()
	err = ipLayer.SerializeTo(ipHeaderBuf, options)
	if err != nil {
		return "", err
	}

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
	err = gopacket.SerializeLayers(tcpPayloadBuf, options, &tcpLayer, gopacket.Payload(payload))
	if err != nil {
		return "", err
	}
	// XXX end of packet creation

	// XXX send packet
	if useV4 {
		var err error
		h := ipv4.Header{
			Version:  4,
			Len:      20,
			TotalLen: 20 + len(tcpPayloadBuf.Bytes()),
			TTL:      64,
			Protocol: int(layers.IPProtocolTCP), // TCP
			Dst:      ip,
			Src:      t.src4,
			// ID and Checksum will be set for us by the kernel
		}
		out, err := h.Marshal()
		if err != nil {
			log.Fatal(err)
		}

		// if sendSynAck {
		// 	// err = rawConn.WriteTo(ipHeader, synBuf, nil)
		// 	// if err != nil {
		// 	// 	return "", fmt.Errorf("failed to write syn: %s", err)
		// 	// }
		// 	// stats.incPacketPerSec()
		// 	// stats.incBytesPerSec(ipHeader.TotalLen + len(synBuf))

		// 	// time.Sleep(synDelay)

		// 	// err = rawConn.WriteTo(ipHeader, ackBuf, nil)
		// 	// if err != nil {
		// 	// 	return "", fmt.Errorf("failed to write ack: %s", err)
		// 	// }
		// 	// stats.incPacketPerSec()
		// 	// stats.incBytesPerSec(ipHeader.TotalLen + len(ackBuf))
		// }

		addr := syscall.SockaddrInet4{
			Port: 0,
			Addr: *(*[4]byte)(ip.To4()),
		}

		p := append(out, tcpPayloadBuf.Bytes()...)
		err = syscall.Sendto(t.sockFd, p, 0, &addr)
		if err != nil {
			return "", os.NewSyscallError("sendto", err)
		}

		stats.incPacketPerSec()
		stats.incBytesPerSec(len(p))
	} else {
		// golang/x/net/ipv6 does not provide a RawConn option because: " Unlike
		// system calls and primitives for IPv4 facilities, tweaking IPv6
		// headers on outgoing packets from userspace must use per-packet basis
		// ancillary data and a very few sticky socket options, and that's the
		// reason why ipv6.RawConn doesn't exist; see RFC 3542"
		// - https://github.com/golang/go/issues/18633
		//
		// So we set sock opts on the conn and provide addresses.
		cm := new(ipv6.ControlMessage)
		cm.Src = t.src6
		cm.Dst = ip

		addr, _ := net.ResolveIPAddr("ip6", host)

		packetConn, err := net.ListenPacket("ip6:tcp", "")
		if err != nil {
			return "", fmt.Errorf("failed to listen on ipv6: %s", err)
		}
		defer packetConn.Close()

		pktConn := ipv6.NewPacketConn(packetConn)
		if pktConn == nil {
			return "", fmt.Errorf("unable to create IPv6 packet conn")
		}

		err = pktConn.SetControlMessage(ipv6.FlagDst|ipv6.FlagSrc, true)
		if err != nil {
			return "", fmt.Errorf("failed to set control flags: %s", err)
		}

		if sendSynAck {
			n, err := pktConn.WriteTo(synBuf, cm, addr)
			if err != nil {
				return "", fmt.Errorf("failed to write syn: %s", err)
			}
			stats.incPacketPerSec()
			stats.incBytesPerSec(n)

			time.Sleep(synDelay)

			n, err = pktConn.WriteTo(ackBuf, cm, addr)
			if err != nil {
				return "", fmt.Errorf("failed to write ack: %s", err)
			}
			stats.incPacketPerSec()
			stats.incBytesPerSec(n)
		}

		n, err := pktConn.WriteTo(tcpPayloadBuf.Bytes(), cm, addr)
		if err != nil {
			return "", fmt.Errorf("failed to write payload: %s", err)
		}
		stats.incPacketPerSec()
		stats.incBytesPerSec(n)
		// time.Sleep(60 * time.Second)
	}

	return seqAck, nil
}

func getSyn(srcPort, dstPort, seq uint32, options gopacket.SerializeOptions, ipLayer gopacket.NetworkLayer) ([]byte, error) {
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
	err := gopacket.SerializeLayers(tcpPayloadBuf, options, &synLayer)
	if err != nil {
		return nil, err
	}
	return tcpPayloadBuf.Bytes(), nil
}
func getAck(srcPort, dstPort, seq, ack uint32, options gopacket.SerializeOptions, ipLayer gopacket.NetworkLayer) ([]byte, error) {

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
	err := gopacket.SerializeLayers(tcpPayloadBuf, options, ackLayer)
	if err != nil {
		return nil, err
	}
	return tcpPayloadBuf.Bytes(), nil
}
