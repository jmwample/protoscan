/*
Allows use of .pcap or .pcap.gz for input

see:
- https://github.com/google/gopacket/pull/214
-
*/
package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type PacketDetails struct {
	IPv4           bool
	IPv6           bool
	TcpFlags       byte
	IpTTL          uint8
	ContainsHTTP   bool
	TlsServerHello bool
	TlsAlert       bool
	TcpPayloadLen  int
}

type Probe struct {
	Target string
	Domain string
}

func (p *Probe) String() string {
	return fmt.Sprintf("%s:%s", p.Target, p.Domain)
}

type Data struct {
	NonZeroPackets []*PacketDetails
	AllPackets     []*PacketDetails
	PacketsByProbe map[string][]*PacketDetails
}

func (d *Data) PrintTTLs(exclude func(*PacketDetails) *PacketDetails) {
	for _, packet := range d.AllPackets {

		if exclude != nil {
			packet = exclude(packet)
			if packet == nil {
				continue
			}
		}
		fmt.Println(packet.IpTTL)
	}
}

func (d *Data) PrintFlags(exclude func(*PacketDetails) *PacketDetails) {
	for _, packet := range d.AllPackets {

		if exclude != nil {
			packet = exclude(packet)
			if packet == nil {
				continue
			}
		}
		fmt.Printf("0x%02x\n", packet.TcpFlags)
	}
}

func (d *Data) PrintStats() error {

	// nprobes := make([]int, len(d.PacketsByProbe))
	var total float64 = 0
	var ntot float64 = 0
	for _, detailsArr := range d.PacketsByProbe {
		// if len(detailsArr) == 1 {
		// 	continue
		// }
		// nprobes = append(nprobes, len(detailsArr))
		total += float64(len(detailsArr))
		ntot++

		fmt.Println(len(detailsArr))
	}

	// f64d := stats.LoadRawData(nprobes)

	// mean, err := f64d.Mean()
	// if err != nil {
	// 	return err
	// }
	// std, err := f64d.StandardDeviation()
	// if err != nil {
	// 	return err
	// }
	// var m1 float64 = total / ntot
	// fmt.Printf("n: %d, %f, avg: %f, std: %f, avg1 %f\n", len(d.PacketsByProbe), ntot, mean, std, m1)

	// b, err := json.Marshal(data.AllPackets)
	// if err != nil {
	// 	return err
	// }
	// fmt.Println(string(b))

	return nil
}

func handlePacket(d *Data, packet gopacket.Packet) {

	p := &Probe{}
	details := &PacketDetails{}

	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		p.Target = ip.SrcIP.String()
		details.IpTTL = ip.TTL
		details.TcpFlags = ip.Payload[13] & 0x3F
		details.IPv4 = true
		details.IPv6 = false
	} else if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv6)
		p.Target = ip.SrcIP.String()
		details.IpTTL = ip.HopLimit
		details.TcpFlags = ip.Payload[13] & 0x3F
		details.IPv4 = false
		details.IPv6 = true
	} else {
		return
	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		p.Domain = strconv.Itoa(int(tcp.DstPort))

		details.TcpPayloadLen = len(tcp.Payload)
		if details.TcpPayloadLen > 3 {
			details.TlsAlert = string(tcp.Payload[:3]) == string([]byte{0x16, 0x03, 0x03})
			details.TlsServerHello = string(tcp.Payload[:3]) == string([]byte{0x15, 0x03, 0x03})
			details.ContainsHTTP = strings.Contains(string(tcp.Payload), "HTTP")
			d.NonZeroPackets = append(d.NonZeroPackets, details)
		}
	}

	// fmt.Printf("%s:%s\n", p.Target, p.Domain)

	d.AllPackets = append(d.AllPackets, details)

	ps := p.String()
	if d.PacketsByProbe[ps] == nil {
		d.PacketsByProbe[ps] = []*PacketDetails{}
	}
	d.PacketsByProbe[ps] = append(d.PacketsByProbe[ps], details)
}

var data *Data

func main() {

	data = &Data{
		NonZeroPackets: make([]*PacketDetails, 0),
		AllPackets:     make([]*PacketDetails, 0),
		PacketsByProbe: make(map[string][]*PacketDetails),
	}

	var pcapPath string
	if len(os.Args[1:]) > 0 {
		pcapPath = os.Args[1]
	} else {
		panic("no file provided")
	}

	f, err := os.Open(pcapPath)
	if err != nil {
		panic("could not open file")
	}
	defer f.Close()

	r, err := pcapgo.NewReader(f)
	if err != nil {
		panic("error reading pcap")
	}

	// packetCount := 0
	packetSource := gopacket.NewPacketSource(r, r.LinkType()) // construct using pcap or pfring
	for packet := range packetSource.Packets() {

		handlePacket(data, packet)
		// packetCount += 1 // do something with each packet
		// if packetCount > 1000 {
		// 	break
		// }
	}

	// err = data.PrintStats()
	// if err != nil {
	// panic(err)
	// }

	filters := []func(*PacketDetails) *PacketDetails{selectIPv4, selectHTTP}
	data.PrintTTLs(cf(filters))

	// data.PrintFlags(selectRSTACK)
}

// composeFilters
func cf(fs []func(*PacketDetails) *PacketDetails) func(*PacketDetails) *PacketDetails {

	defaultF := func(pd *PacketDetails) *PacketDetails {
		return pd
	}

	if len(fs) == 0 {
		return defaultF
	}

	return func(pd *PacketDetails) *PacketDetails {
		for _, f := range fs {
			pd = f(pd)
		}
		return pd
	}
}

func selectSYNACK(p *PacketDetails) *PacketDetails {
	if p == nil || p.TcpFlags != 0x12 {
		return nil
	}
	return p
}

func selectRST(p *PacketDetails) *PacketDetails {
	if p == nil || p.TcpFlags != 0x04 {
		return nil
	}
	return p
}

func selectRSTACK(p *PacketDetails) *PacketDetails {
	if p == nil || p.TcpFlags != 0x14 {
		return nil
	}
	return p
}

func selectHTTP(p *PacketDetails) *PacketDetails {
	if p == nil || !p.ContainsHTTP {
		return nil
	}
	return p
}

func selectIPv6(p *PacketDetails) *PacketDetails {
	if p == nil || !p.IPv6 {
		return nil
	}
	return p
}

func selectIPv4(p *PacketDetails) *PacketDetails {
	if p == nil || !p.IPv4 {
		return nil
	}
	return p
}
