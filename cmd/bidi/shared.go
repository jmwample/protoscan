package main

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/routing"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

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

func sendUDP(dst string, payload []byte, lAddr string, verbose bool) error {
	var d net.Dialer
	if lAddr != "" {
		d.LocalAddr, _ = net.ResolveUDPAddr("ip", lAddr)
	}

	conn, err := d.Dial("udp", dst)
	if err != nil {
		return fmt.Errorf("%s - error creating UDP socket(?): %v", dst, err)
	}
	defer conn.Close()

	conn.Write(payload)
	return nil
}

func sendTCP(dst string, payload []byte, lAddr, device string, synDelay time.Duration, sendSynAck, checksums, verbose bool) (string, error) {

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

	localIface, err := net.InterfaceByName(device)
	if err != nil {
		return "", fmt.Errorf("bad device name: \"%s\"", device)
	}

	localIP, err := getSrcIP(localIface, lAddr, ip)
	if err != nil {
		return "", err
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

	// Fill out IP header with source and dest
	var ipLayer gopacket.SerializableLayer
	var networkLayer gopacket.NetworkLayer
	if useV4 {
		if localIP.To4() == nil {
			return "", fmt.Errorf("v6 src for v4 dst")
		}
		ipLayer4 := &layers.IPv4{
			SrcIP:    localIP,
			DstIP:    ip,
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolTCP,
		}
		networkLayer = ipLayer4
		ipLayer = ipLayer4
	} else {
		if localIP.To4() != nil {
			return "", fmt.Errorf("v4 src for v6 dst")
		}
		ipLayer6 := &layers.IPv6{
			SrcIP:      localIP,
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
		packetConn, err := net.ListenPacket("ip4:tcp", "")
		if err != nil {
			return "", fmt.Errorf("failed to listen on ipv4: %s", err)
		}
		defer packetConn.Close()

		ipHeader, err := ipv4.ParseHeader(ipHeaderBuf.Bytes())
		if err != nil {
			return "", fmt.Errorf("failed to parse ipv4 header: %s", err)
		}
		rawConn, err := ipv4.NewRawConn(packetConn)
		if err != nil {
			return "", fmt.Errorf("failed to create ipv4 rawconn: %s", err)
		}

		if sendSynAck {
			err = rawConn.WriteTo(ipHeader, synBuf, nil)
			if err != nil {
				return "", fmt.Errorf("failed to write syn: %s", err)
			}
			time.Sleep(synDelay)

			err = rawConn.WriteTo(ipHeader, ackBuf, nil)
			if err != nil {
				return "", fmt.Errorf("failed to write ack: %s", err)
			}
		}

		err = rawConn.WriteTo(ipHeader, tcpPayloadBuf.Bytes(), nil)
		if err != nil {
			return "", fmt.Errorf("failed to write payload: %s", err)
		}
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
		cm.Src = localIP
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
			_, err = pktConn.WriteTo(synBuf, cm, addr)
			if err != nil {
				return "", fmt.Errorf("failed to write syn: %s", err)
			}
			time.Sleep(synDelay)

			_, err = pktConn.WriteTo(ackBuf, cm, addr)
			if err != nil {
				return "", fmt.Errorf("failed to write ack: %s", err)
			}
		}

		_, err = pktConn.WriteTo(tcpPayloadBuf.Bytes(), cm, addr)
		if err != nil {
			return "", fmt.Errorf("failed to write payload: %s", err)
		}
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

func decodeOrPanic(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
