package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/miekg/dns"
)

const dnsProbeTypeName = "dns"

type dnsProber struct {
	qType uint
}

func (p *dnsProber) registerFlags() {
	flag.UintVar(&p.qType, "qtype", 1, "[DNS] Type of Query to send (1 = A / 28 = AAAA)")
}

func (p *dnsProber) sendProbe(ip net.IP, name string, lAddr string, verbose bool) error {

	out, err := p.buildPayload(name)
	if err != nil {
		return fmt.Errorf("failed to build udp payload: %s", err)
	}

	addr := net.JoinHostPort(ip.String(), "53")
	return sendUDP(addr, out, lAddr, verbose)
}

func (p *dnsProber) buildPayload(name string) ([]byte, error) {
	m := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Authoritative:     false,
			AuthenticatedData: false,
			CheckingDisabled:  false,
			RecursionDesired:  true,
			Opcode:            dns.OpcodeQuery,
		},
		Question: make([]dns.Question, 1),
	}
	m.Question[0] = dns.Question{
		Name:   dns.Fqdn(name),
		Qtype:  uint16(p.qType),
		Qclass: uint16(0x0001), // IN
	}
	m.Id = dns.Id()

	out, err := m.Pack()
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (p *dnsProber) handlePcap(iface string) {

	if handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter("udp src port 53"); err != nil { // optional
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			p.handlePacket(packet)
		}
	}

}

func (p *dnsProber) handlePacket(packet gopacket.Packet) {
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return
	}
	udp, _ := udpLayer.(*layers.UDP)

	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return
	}
	dns, _ := dnsLayer.(*layers.DNS)
	questions := dns.Questions
	answers := dns.Answers
	if len(questions) < 1 {
		return
	}

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
	log.Printf("RESULT %s %s, %s %d answers: %s\n",
		ipAddr, questions[0].Name, dns.ResponseCode, len(answers), hex.EncodeToString(udp.Payload))
}
