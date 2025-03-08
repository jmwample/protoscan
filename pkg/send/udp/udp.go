package udp

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strconv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/jmwample/protoscan/pkg/send/raw"
	"github.com/jmwample/protoscan/pkg/shared"
)

// Options includes options that are applied to ach packet sent using this prober
// if no Options are provided in the SendPkt function
type Options struct {
	Checksums bool
}

var defaultOPtions = Options{
	Checksums: true,
}

// Sender allows for rapid sending of UDP packets using either golang UDP Dial
// or a wrapper around raw sockets.
type Sender struct {
	lAddr4, lAddr6 string

	//--- Raw send options ---
	sendRaw bool
	*raw.Sender

	src4 net.IP
	src6 net.IP

	checksums bool

	device string
}

// NewSender builds and inits new udp sender. Gets source addresses
// for public v4 and v6 IPs (or uses locals if provided).
//
// Make sure to defer Close() to avoid leaving hanging sockets. Good practice
// even if not using sendRaw.
func NewSender(device, lAddr4, lAddr6 string, sendRaw bool) (*Sender, error) {
	localIface, err := net.InterfaceByName(device)
	if err != nil {
		return nil, fmt.Errorf("bad device name: \"%s\"", device)
	}

	localIP4, err := shared.GetSrcIP(localIface, lAddr4, net.ParseIP("1.2.3.4"))
	if err != nil {
		return nil, err
	}

	localIP6, err := shared.GetSrcIP(localIface, lAddr6, net.ParseIP("2606:4700::"))
	if err != nil {
		log.Println("failed to init IPv6 - likely not supported")
	}
	var u *Sender
	if sendRaw {

		rs, err := raw.NewSender(context.Background(), device, 20)
		if err != nil {
			return nil, err
		}

		u = &Sender{
			sendRaw: sendRaw,
			Sender:  rs,

			lAddr4: localIP4.String(),
			lAddr6: localIP6.String(),

			device: device,
			src4:   localIP4,
			src6:   localIP6,
		}
	} else {
		u = &Sender{
			lAddr4:  localIP4.String(),
			lAddr6:  localIP6.String(),
			sendRaw: sendRaw,
		}
	}

	return u, nil
}

// FromRaw builds a new udp sender from an existing RawSender so as to re-use
// and existing pool of raw sockets. Gets source addresses for public v4 and v6
// IPs (or uses locals if provided).
//
// Make sure to defer Close() to // avoid leaving hanging sockets.
func FromRaw(rs *raw.Sender, device, lAddr4, lAddr6 string) (*Sender, error) {
	localIface, err := net.InterfaceByName(device)
	if err != nil {
		return nil, fmt.Errorf("bad device name: \"%s\"", device)
	}

	localIP4, err := shared.GetSrcIP(localIface, lAddr4, net.ParseIP("1.2.3.4"))
	if err != nil {
		return nil, err
	}

	localIP6, err := shared.GetSrcIP(localIface, lAddr6, net.ParseIP("2606:4700::"))
	if err != nil {
		log.Println("failed to init IPv6 - likely not supported")
	}

	u := &Sender{
		sendRaw: true,
		Sender:  rs,

		lAddr4: localIP4.String(),
		lAddr6: localIP6.String(),

		device: device,
		src4:   localIP4,
		src6:   localIP6,
	}

	return u, nil
}

// Close shuts down and cleans up after the raw socket sender
func (u *Sender) Close() {
	if u.sendRaw {
		u.Sender.Close()
	}
}

// SendUDP if sport is 0 (unset) then the Dial should generate a random source port.
func (u *Sender) SendUDP(dst string, sport int, payload []byte, verbose bool) (string, error) {

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

	// n, err := conn.Write(payload)
	_, err = conn.Write(payload)
	if err != nil {
		return "", err
	}
	// TODO jmwample: fix stats
	// stats.incPacketPerSec()
	// stats.incBytesPerSec(n)

	h := conn.LocalAddr().String()
	_, p, err := net.SplitHostPort(h)

	return p, err
}

func (u *Sender) sendUDPRaw(dst string, sport int, payload []byte, verbose bool) (string, error) {
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
	var networkLayer shared.NetLayer
	if useV4 {
		ipLayer4 := &layers.IPv4{
			SrcIP:    u.src4,
			DstIP:    ip,
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolUDP,
		}
		networkLayer = ipLayer4
	} else {
		ipLayer6 := &layers.IPv6{
			SrcIP:      u.src6,
			DstIP:      ip,
			Version:    6,
			HopLimit:   64,
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
	u.SendPkt(&ip, udpPayloadBuf.Bytes())

	return strconv.Itoa(sport), nil
}
