package tcp

import (
	"context"
	"fmt"
	"hash/crc32"
	"log"
	"math/rand"
	"net"
	"strconv"
	"time"
	"unsafe"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/jmwample/protoscan/pkg/send/raw"
	"github.com/jmwample/protoscan/pkg/shared"
)

// Sender implements a wrap around raw sockets that allows for rapid sending of TCP packets.
type Sender struct {
	*raw.Sender

	src4 net.IP
	src6 net.IP

	device string
}

// Options includes options that are applied to ach packet sent using this prober
// if no Options are provided in the SendPkt function
type Options struct {
	// Syn sends a syn as a pseudo prelude to a TCP session in order to trigger censorship responses
	// from middle-boxes expecting and tracking some subset of the TCP flow state.If both Syn and
	// Ack are true, SYN is send before ACK as it would be in a regular TCP handshake
	Syn       bool
	Ack       bool
	SynDelay  time.Duration
	Checksums bool
}

var defaultOPtions = Options{
	Syn:       true,
	Ack:       true,
	SynDelay:  2 * time.Millisecond,
	Checksums: true,
}

// DefaultOptions  returns the default options used for TCP if none are provided. Sends syn & ack
// with a delay of 2ms between syn and ack + data
func DefaultOptions() interface{} {
	opt := new(Options)
	opt.Syn = defaultOPtions.Syn
	opt.Ack = defaultOPtions.Ack
	opt.SynDelay = defaultOPtions.SynDelay
	opt.Checksums = defaultOPtions.Checksums
	return &opt
}

// NewSender builds and inits new tcp sender. Gets source addresses
// for public v4 and v6 IPs (or uses locals if provided).
//
// Make sure to defer Close() to // avoid leaving hanging sockets.
func NewSender(device, lAddr4, lAddr6 string) (*Sender, error) {

	rs, err := raw.NewSender(context.Background(), device, 20)
	if err != nil {
		return nil, err
	}

	return FromRaw(rs, device, lAddr4, lAddr6)
}

// FromRaw builds a new tcp sender from an existing RawSender so as to re-use and existing pool of
// raw sockets. Gets source addresses for public v4 and v6 IPs (or uses locals if provided).
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

	t := &Sender{
		Sender: rs,
		src4:   localIP4,
		src6:   localIP6,
		device: device,
	}

	return t, nil
}

func (t *Sender) Send(dst string, sport int, payload []byte, tcpOpts interface{}) (string, int, error) {

	var tcpOpt *Options
	if optTmp, ok := tcpOpts.(*Options); tcpOpts == nil || !ok {
		tcpOpt = &defaultOPtions
	} else {
		tcpOpt = optTmp
	}

	host, portStr, err := net.SplitHostPort(dst)
	if err != nil {
		return "", -1, fmt.Errorf("failed to parse \"ip:port\": %s - %s", dst, err)
	}
	port, _ := strconv.Atoi(portStr)

	ip := net.ParseIP(host)

	var useV4 = ip.To4() != nil
	if useV4 && t.src4 == nil {
		return "", -1, fmt.Errorf("no IPv4 address available")
	} else if !useV4 && t.src6 == nil {
		return "", -1, fmt.Errorf("no IPv6 address available")
	}

	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: tcpOpt.Checksums,
	}

	var seq = rand.Uint32()
	var ack uint32
	if sport == 0 {
		// If no sport provided pick a random source port between 1000 and 65535
		// and a random value for ack
		sport = int((rand.Int31() % 64535) + 1000)
		ack = rand.Uint32()
	} else {
		// set the ack value to be the CRC of the source port, the destination
		// IP. This should allow a validation that the packet is related to a
		// probe we sent.
		ipByteSlice := (*[4]byte)(unsafe.Pointer(&sport))[:] // sport to []byte
		ipByteSlice = append(ipByteSlice, ip.To16()...)      // append ip bytes
		// ipByteSlice = append(ipByteSlice, (*[4]byte)(unsafe.Pointer(&seq))[:]...) // append seq as []byte
		ack = crc32.ChecksumIEEE(ipByteSlice)

		// See TestTCPTagValidate in shared_test.go. This tag can be validated
		// with the source ip, destination port, and seq number fields of
		// response packets. RST packets generally don't set their ACK value :(
	}

	// Fill TCP  Payload layer details
	tcpLayer := layers.TCP{
		SrcPort: layers.TCPPort(sport),
		DstPort: layers.TCPPort(port),
		PSH:     true,
		ACK:     true,
		Window:  502,
		Seq:     seq + 1,
		Ack:     ack,
	}
	seqAck := fmt.Sprintf("%x %x", seq+1, ack)

	// Fill out gopacket IP header with source and dest JUST for Data layer checksums
	var networkLayer shared.NetLayer
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
	synBuf, err := getSyn(uint32(sport), uint32(port), seq, options, networkLayer)
	if err != nil {
		return "", -1, err
	}
	ackBuf, err := getAck(uint32(sport), uint32(port), seq+1, ack, options, networkLayer)
	if err != nil {
		return "", -1, err
	}

	tcpPayloadBuf := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(tcpPayloadBuf, options, networkLayer, &tcpLayer, gopacket.Payload(payload))
	if err != nil {
		return "", -1, err
	}
	// XXX end of packet creation

	// XXX send packet(s)
	if tcpOpt.Syn {
		// send syn and ack if enabled
		t.SendPkt(&ip, synBuf)
		time.Sleep(tcpOpt.SynDelay)
	}
	if tcpOpt.Ack {
		t.SendPkt(&ip, ackBuf)
		time.Sleep(tcpOpt.SynDelay)
	}

	t.SendPkt(&ip, tcpPayloadBuf.Bytes())

	return seqAck, int(sport), nil
}

func getSyn(srcPort, dstPort, seq uint32, options gopacket.SerializeOptions, ipLayer shared.NetLayer) ([]byte, error) {
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
func getAck(srcPort, dstPort, seq, ack uint32, options gopacket.SerializeOptions, ipLayer shared.NetLayer) ([]byte, error) {

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
