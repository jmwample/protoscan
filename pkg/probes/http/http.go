package http

import (
	"context"
	"fmt"
	"log"
	"net"
	"path/filepath"
	"sync"

	"github.com/google/gopacket"

	"github.com/jmwample/protoscan/pkg/send/tcp"
	"github.com/jmwample/protoscan/pkg/shared"
	"github.com/jmwample/protoscan/pkg/track"
)

const (
	// ProbeTypeName HTTP probe name
	ProbeTypeName = "http"

	// BPFFilter provides a filter for traffic expected by in response to this probe
	BPFFilter = "tcp src port 443"

	// const httpUserAgent = "curl/7.81.0"
	httpUserAgent     = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
	httpProbeTypeName = "http"
	httpFmtStr        = "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\n\r\n"
)

// Prober implements the Probe interface for a UDP DNS probe.
type Prober struct {
	Sender *tcp.Sender

	DKT *track.KeyTable

	// Options passed to the sender on each send. Useful for when more than one
	// prober is using a sender and may want packets sent with different options
	SenderOptions interface{}

	OutDir      string
	CaptureICMP bool
}

// RegisterFlags adds any flags specific to this particular probe type as part
// of the Prober interface.
func (p *Prober) RegisterFlags() {}

// SendProbe generates a payload and sends a probe (can be more than one packet)
// as part of the Prober interface
func (p *Prober) SendProbe(ip net.IP, name string, verbose bool) error {
	out, err := p.buildPayload(name)
	if err != nil {
		return fmt.Errorf("failed to build tls payload: %s", err)
	}

	sport, _ := p.DKT.Get(name)

	addr := net.JoinHostPort(ip.String(), "80")

	seqAck, sport, err := p.Sender.Send(addr, sport.(int), out, p.SenderOptions)
	if err == nil && verbose {
		log.Printf("Sent :%d -> %s %s %s\n", sport, addr, name, seqAck)
	}

	return err
}

func (p *Prober) buildPayload(name string) ([]byte, error) {
	// Fill out request bytes
	return []byte(fmt.Sprintf(httpFmtStr, name, httpUserAgent)), nil

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

// RecvCallback is the function called by the pcap handler if we want to do unique tracking
// and feedback for the probe orchestration or output. None implemented yet.
func (p *Prober) RecvCallback(packet gopacket.Packet) {
	return
}
