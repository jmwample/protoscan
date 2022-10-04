package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"path/filepath"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/miekg/dns"
)

const dnsProbeTypeName = "dns"

type dnsProber struct {
	sender *udpSender
	qType  uint

	dkt *KeyTable

	outDir      string
	CaptureICMP bool
}

func (p *dnsProber) registerFlags() {
	flag.UintVar(&p.qType, "qtype", 1, "[DNS] Type of Query to send (1 = A / 28 = AAAA)")
}

func (p *dnsProber) sendProbe(ip net.IP, name string, verbose bool) error {
	sport, _ := p.dkt.get(name)

	out, err := p.buildPayload(name)
	if err != nil {
		return fmt.Errorf("failed to build udp payload: %s", err)
	}

	addr := net.JoinHostPort(ip.String(), "53")
	srcPort, err := p.sender.sendUDP(addr, sport.(int), out, verbose)
	if err == nil && verbose {
		log.Printf("Sent :%s -> %s %s %s\n", srcPort, addr, name, hex.EncodeToString(out))
	}

	return err
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

	// We don't need crypto random and we don't want to block
	dns.Id = func() uint16 { return uint16(rand.Uint32()) }
	m.Id = dns.Id()

	out, err := m.Pack()
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (p *dnsProber) handlePcap(iface string, exit chan struct{}, wg *sync.WaitGroup) {
	filename := filepath.Join(p.outDir, "dns.pcap")
	bpfFilter := "udp src port 53"
	if p.CaptureICMP {
		bpfFilter = "icmp or icmp6 or " + bpfFilter
	}
	capturePcap(iface, filename, bpfFilter, exit, wg)
}

func (p *dnsProber) handlePacket(packet gopacket.Packet) {
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		// could happen with ICMP packets. Ignore in processing.
		return
	}

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
	log.Printf("RESULT %s %s, %s %d answers\n",
		ipAddr, questions[0].Name, dns.ResponseCode, len(answers))
}
