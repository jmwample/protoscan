package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"path/filepath"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

const tlsProbeTypeName = "tls"

type tlsProber struct {
	sender *tcpSender

	dkt *KeyTable

	outDir string
}

func (p *tlsProber) registerFlags() {
}

func (p *tlsProber) sendProbe(ip net.IP, name string, verbose bool) error {

	out, err := p.buildPayload(name)
	if err != nil {
		return fmt.Errorf("failed to build tls payload: %s", err)
	}

	sport, _ := p.dkt.get(name)

	addr := net.JoinHostPort(ip.String(), "443")
	seqAck, sport, err := p.sender.sendTCP(addr, sport.(int), name, out, verbose)
	if err == nil && verbose {
		log.Printf("Sent :%d -> %s %s %s\n", sport, addr, name, seqAck)
	}

	return err
}

// buildPayload builds a tls payload
//
// As demonstrated by the GeneratePayloads perf benchmark lots (~30%) of tls
// payload build time is spent on hex.Decode which is avoidable. However, for
// now generating payload is really fast anyways and hex is a convenient format
// in which to interact with the payload. It might make sense to do hex.Decode
// calls as some sort of init if speed matters in the future. Or move to using
// slice init with bytes. But for now it doesn't matter.
func (p *tlsProber) buildPayload(name string) ([]byte, error) {
	return buildTLS1_2(name)
}

func (p *tlsProber) handlePcap(iface string) {
	f, _ := os.Create(filepath.Join(p.outDir, "tls.pcap"))
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(1600, layers.LinkTypeEthernet)
	defer f.Close()

	if handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter("icmp or tcp src port 443"); err != nil { // optional
		panic(err)
	} else {
		defer handle.Close()

		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			// p.handlePacket(packet)
			w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		}
	}
}

func (p *tlsProber) handlePacket(packet gopacket.Packet) {

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
		log.Printf("RESULT TLS %s %v", ipAddr, tcp.RST)
	} else {
		log.Printf("RESULT TLS")
	}
}

func buildTLS1_2(name string) ([]byte, error) {
	// Record headder
	var rh = "160301"

	// dynamic - bytes of handshake to follow
	var packetLen = fmt.Sprintf("%04x", len(name)+0xc8)

	// Handshake header and client version
	var hh = "01" + fmt.Sprintf("%06x", len(name)+0xc4) + "0303"

	// dynamic - client Rand (32 generated bytes)
	buf := make([]byte, 32)
	n, err := rand.Read(buf)
	if err != nil || n != 32 {
		return nil, fmt.Errorf("failed rand read: %s", err)
	}
	// var clientRandom = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	var clientRandom = hex.EncodeToString(buf)

	// dynamic - session ID (33 bytes 32 generated)
	n, err = rand.Read(buf)
	if err != nil || n != 32 {
		return nil, fmt.Errorf("failed rand read: %s", err)
	}
	// var sessionID = "20e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
	var sessionID = "20" + hex.EncodeToString(buf)

	// Ciphersuites & Compression methods
	var csAndCM = "001cc02bc02fcca9cca8c02cc030c00ac009c013c014009c009d002f00350100"

	// dynamic - Extensions lenggth (00a3)
	var extensionsLen = fmt.Sprintf("%04x", len(name)+0x5f)

	var extSNIID = "0000"
	// dynamic - Extension lenggth (0018)
	var extSNIDataLen = fmt.Sprintf("%04x", len(name)+5)
	// dynamic - Extension lenggth (0016)
	var extSNIEntryLen = fmt.Sprintf("%04x", len(name)+3)
	var extSNIEntryType = "00"
	// dynamic - Extension lenggth (0013)
	var hostnameLen = fmt.Sprintf("%04x", len(name))
	var hostname = hex.EncodeToString([]byte(name))

	var otherExtensions = "000b000403000102000a00160014001d0017001e0019001801000101010201030104002300000016000000170000000d001e001c040305030603080708080809080a080b080408050806040105010601002d00020101"

	fulldata := rh + packetLen + hh + clientRandom + sessionID + csAndCM + extensionsLen + extSNIID + extSNIDataLen + extSNIEntryLen + extSNIEntryType + hostnameLen + hostname + otherExtensions
	return hex.DecodeString(fulldata)
}

func buildTLS1_3(name string) ([]byte, error) {
	// var fulldata = "16030100f8010000f40303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000813021303130100ff010000a30000001800160000136578616d706c652e756c666865696d2e6e6574000b000403000102000a00160014001d0017001e0019001801000101010201030104002300000016000000170000000d001e001c040305030603080708080809080a080b080408050806040105010601002b0003020304002d00020101003300260024001d0020358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254"

	// Record headder
	var rh = "160301"

	// dynamic - bytes of handshake to follow
	var packetLen = fmt.Sprintf("%04x", len(name)+0xe5)

	// Handshake header and client version
	var hh = "01" + fmt.Sprintf("%06x", len(name)+0xe1) + "0303"

	// dynamic - client Rand (32 generated bytes)
	buf := make([]byte, 32)
	n, err := rand.Read(buf)
	if err != nil || n != 32 {
		return nil, fmt.Errorf("failed rand read: %s", err)
	}
	// var clientRandom = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	var clientRandom = hex.EncodeToString(buf)

	// dynamic - session ID (33 bytes 32 generated)
	n, err = rand.Read(buf)
	if err != nil || n != 32 {
		return nil, fmt.Errorf("failed rand read: %s", err)
	}
	// var sessionID = "20e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
	var sessionID = "20" + hex.EncodeToString(buf)

	// Ciphersuites & Compression methods
	var csAndCM = "000813021303130100ff0100"

	// dynamic - Extensions lenggth (00a3)
	var extensionsLen = fmt.Sprintf("%04x", len(name)+0x90)

	var extSNIID = "0000"
	// dynamic - Extension lenggth (0018)
	var extSNIDataLen = fmt.Sprintf("%04x", len(name)+5)
	// dynamic - Extension lenggth (0016)
	var extSNIEntryLen = fmt.Sprintf("%04x", len(name)+3)
	var extSNIEntryType = "00"
	// dynamic - Extension lenggth (0013)
	var hostnameLen = fmt.Sprintf("%04x", len(name))
	var hostname = hex.EncodeToString([]byte(name))

	// dynamic(random) - Client KeyShare extension public key
	buf = make([]byte, 32)
	n, err = rand.Read(buf)
	if err != nil || n != 32 {
		return nil, fmt.Errorf("failed rand read: %s", err)
	}
	var extKeySharePubkey = hex.EncodeToString(buf)
	var extKeyShare = "003300260024001d0020" + extKeySharePubkey

	var otherExtensions = extKeyShare + "000b000403000102000a00160014001d0017001e0019001801000101010201030104002300000016000000170000000d001e001c040305030603080708080809080a080b080408050806040105010601002b0003020304002d00020101"

	fulldata := rh + packetLen + hh + clientRandom + sessionID + csAndCM + extensionsLen + extSNIID + extSNIDataLen + extSNIEntryLen + extSNIEntryType + hostnameLen + hostname + otherExtensions
	return hex.DecodeString(fulldata)
}
