package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

const dtlsProbeTypeName = "dtls"

type portRange struct {
	min uint16
	max uint16
}

type dtlsProber struct {
	sender *udpSender

	randDestinationPort bool
	randPortRange       portRange

	noSNI bool

	outDir string
}

func (p *dtlsProber) registerFlags() {
	flag.BoolVar(&p.randDestinationPort, "rdrstport", false, "[DTLS] randomize destination port")
	flag.BoolVar(&p.noSNI, "no-sni", false, "[DTLS] Don't send the SNI extension")
}

func (p *dtlsProber) sendProbe(ip net.IP, name string, verbose bool) error {

	out, err := p.buildPayload(name)
	if err != nil {
		return fmt.Errorf("failed to build udp payload: %s", err)
	}

	addr := net.JoinHostPort(ip.String(), "443")
	sport, err := p.sender.sendUDP(addr, 0, out, verbose)
	if err == nil && verbose {
		log.Printf("Sent :%s -> %s %s %s\n", sport, addr, name, hex.EncodeToString(out))
	}

	return err
}

func (p *dtlsProber) buildPayload(name string) ([]byte, error) {
	return nil, fmt.Errorf("not implemented yet")
}

func (p *dtlsProber) handlePcap(iface string) {
	f, _ := os.Create(filepath.Join(p.outDir, "dtls.pcap"))
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(1600, layers.LinkTypeEthernet)
	defer f.Close()

	if handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter("icmp or udp src port 443"); err != nil { // optional
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
			// p.handlePacket(packet)
		}
	}

}

// handlePacket used for parsing results specific to DTLS.
//
// unused for DTLS as we just pcap for now.
func (p *dtlsProber) handlePacket(packet gopacket.Packet) {
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

	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		// could happen with ICMP packets. Ignore in processing.
		return
	}
	udp, _ := udpLayer.(*layers.UDP)

	if udp.NextLayerType() != 0 {
		log.Printf("RESULT DTLS %s %v", ipAddr, udp.Length)
	} else {
		log.Printf("RESULT DTLS")
	}
}
