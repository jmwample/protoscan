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
	"sort"
	"strconv"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type PacketDetails struct {
	IPv4           bool
	IPv6           bool
	TcpFlags       uint8
	IpTTL          uint8
	IpID           uint16
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

func (d *Data) getU8F(f u8f, exclude packetFilter) []uint8 {
	r := make([]uint8, 0, 10)
	for _, packet := range d.AllPackets {

		if exclude != nil {
			packet = exclude(packet)
			if packet == nil {
				continue
			}
		}
		r = append(r, f(packet))
	}
	return r
}

func (d *Data) printU8F(f u8f, exclude packetFilter) {
	fs := d.getU8F(f, exclude)
	for _, f := range fs {
		fmt.Println(f)
	}
}

func (d *Data) printU8FCounts(f u8f, exclude packetFilter) {
	fs := d.getU8F(f, exclude)
	fCounts := uniqueCountsU8(fs)

	keys := make([]uint8, 0, len(fCounts))
	for k := range fCounts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })

	for _, k := range keys {
		fmt.Println(k, fCounts[k])
	}
}

func (d *Data) getTTLs(exclude packetFilter) []uint8 {
	return d.getU8F(u8fTTL, exclude)
}

func (d *Data) printTTLs(exclude packetFilter) {
	d.printU8F(u8fTTL, exclude)
}

func (d *Data) printTTLCounts(exclude packetFilter) {
	d.printU8FCounts(u8fTTL, exclude)
}

func (d *Data) printFlags(exclude packetFilter) {
	flags := d.getU8F(u8fFlags, exclude)
	for _, f := range flags {
		fmt.Printf("0x%02x\n", f)
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
		details.IpID = ip.Id
		details.TcpFlags = ip.Payload[13] & 0x3F
		details.IPv4 = true
		details.IPv6 = false
	} else if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv6)
		p.Target = ip.SrcIP.String()
		details.IpTTL = ip.HopLimit
		details.IpID = 0
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

func main() {

	data := &Data{
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

	filters := []packetFilter{selectIPv4, selectSYNACK}
	data.printU8FCounts(u8fIPIDUpper, cf(filters))

	// filters := []packetFilter{selectIPv4, newSelectIPID(0)}
	// data.printU8FCounts(u8fFlags, cf(filters))

	// data.printFlags(cf(filters))
}
