package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// const httpUserAgent = "curl/7.81.0"
const httpUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
const httpProbeTypeName = "http"
const httpFmtStr = "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\n\r\n"

type httpProber struct {
	sender *tcpSender

	dkt *KeyTable

	outDir      string
	CaptureICMP bool
}

func (p *httpProber) registerFlags() {
}

func (p *httpProber) buildPayload(name string) ([]byte, error) {
	// Fill out request bytes
	return []byte(fmt.Sprintf(httpFmtStr, name, httpUserAgent)), nil

}

func (p *httpProber) sendProbe(ip net.IP, name string, verbose bool) error {
	out, err := p.buildPayload(name)
	if err != nil {
		return fmt.Errorf("failed to build tls payload: %s", err)
	}

	sport, _ := p.dkt.get(name)

	addr := net.JoinHostPort(ip.String(), "80")
	seqAck, sport, err := p.sender.sendTCP(addr, sport.(int), name, out, verbose)
	if err == nil && verbose {
		log.Printf("Sent :%d -> %s %s %s\n", sport, addr, name, seqAck)
	}

	return err
}

func (p *httpProber) handlePcap(iface string, exit chan struct{}, wg *sync.WaitGroup) {
	pcapName := httpProbeTypeName + ".pcap"
	bpfFilter := "tcp src port 80"

	f, _ := os.Create(filepath.Join(p.outDir, pcapName))
	filename := filepath.Join(p.outDir, pcapName)
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(1600, layers.LinkTypeEthernet)
	if p.CaptureICMP {
		defer f.Close()
		bpfFilter = "icmp or icmp6 or " + bpfFilter
	}
	capturePcap(iface, filename, bpfFilter, exit, wg)
}

// func (p *httpProber) handlePcap(iface string) {
// 	f, _ := os.Create(filepath.Join(p.outDir, "http.pcap"))
// 	w := pcapgo.NewWriter(f)
// 	w.WriteFileHeader(1600, layers.LinkTypeEthernet)
// 	defer f.Close()

// 	if handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever); err != nil {
// 		panic(err)
// 	} else if err := handle.SetBPFFilter("icmp or tcp src port 80"); err != nil { // optional
// 		panic(err)
// 	} else {
// 		defer handle.Close()

// 		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
// 		for packet := range packetSource.Packets() {
// 			// p.handlePacket(packet)
// 			w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
// 		}
// 	}
// }

func (p *httpProber) handlePacket(packet gopacket.Packet) {

	var ipAddr net.IP
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		ip6Layer := packet.Layer(layers.LayerTypeIPv6)
		if ip6Layer == nil {
			return
		}
		ip6, _ := ip6Layer.(*layers.IPv6)
		ipAddr = ip6.SrcIP
	} else {
		ip4, _ := ipLayer.(*layers.IPv4)
		ipAddr = ip4.SrcIP
	}

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}
	tcp, _ := tcpLayer.(*layers.TCP)

	// log.Printf("RESULT %s %s, %s %d answers: %s\n",
	// 	ipAddr, questions[0].Name, dns.ResponseCode, len(answers), hex.EncodeToString(tcp.Payload))

	if tcp.NextLayerType() != 0 {
		log.Printf("RESULT HTTP %s %v", ipAddr, tcp.RST)
	} else {
		log.Printf("RESULT HTTP")
	}
}
