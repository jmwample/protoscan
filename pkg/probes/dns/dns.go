package dns

import (
	"context"
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

	"github.com/jmwample/protoscan/pkg/send/udp"
	"github.com/jmwample/protoscan/pkg/shared"
)

const (
	// ProbeTypeName DNS probe name
	ProbeTypeName = "dns"

	// BPFFilter provides a filter for traffic expected by in response to this probe
	BPFFilter = "udp src port 53"
)

// Prober implements the Probe interface for a UDP DNS probe.
type Prober struct {
	Sender *udp.Sender
	QType  uint

	// Options passed to the sender on each send. Useful for when more than one
	// prober is using a sender and may want packets sent with different options
	SenderOptions interface{}

	OutDir      string
	CaptureICMP bool
}

// RegisterFlags adds any flags specific to this particular probe type as part
// of the Prober interface
func (p *Prober) RegisterFlags() {
	flag.UintVar(&p.QType, "qtype", 1, "[DNS] Type of Query to send (1 = A / 28 = AAAA)")
}

// SendProbe generates a payload and sends a probe (can be more than one packet)
// as part of the Prober interface
func (p *Prober) SendProbe(ip net.IP, name string, verbose bool) error {

	out, err := p.buildPayload(name)
	if err != nil {
		return fmt.Errorf("failed to build udp payload: %s", err)
	}

	addr := net.JoinHostPort(ip.String(), "53")
	sport, err := p.Sender.SendUDP(addr, 0, out, verbose)
	if err == nil && verbose {
		log.Printf("Sent :%s -> %s %s %s\n", sport, addr, name, hex.EncodeToString(out))
	}

	return err
}

func (p *Prober) buildPayload(name string) ([]byte, error) {
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
		Qtype:  uint16(p.QType),
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

// HandlePcap deals with response traffic in a way specific to this probe type
// as part of the Prober interface. Callback disabled for This capture
func (p *Prober) HandlePcap(ctx context.Context, iface string, wg *sync.WaitGroup) {
	pcapName := ProbeTypeName + ".pcap"
	pcapPath := filepath.Join(p.OutDir, pcapName)
	bpfFilter := BPFFilter

	if p.CaptureICMP {
		bpfFilter = "icmp or icmp6 or " + bpfFilter
	}
	shared.CapturePcap(ctx, iface, pcapPath, bpfFilter, nil, wg)
}

// RecvCallback is the function called by the pcap handler
func (p *Prober) RecvCallback(packet gopacket.Packet) {
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
