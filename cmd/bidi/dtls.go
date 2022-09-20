package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

const dtlsProbeTypeName = "dtls"

type portRange struct {
	min int
	max int
}

type dtlsProber struct {
	sender *udpSender

	randDestinationPort bool
	portRangeString     string
	randPortRange       portRange

	noSNI bool

	dkt *KeyTable

	outDir string
}

func (p *dtlsProber) registerFlags() {
	flag.BoolVar(&p.randDestinationPort, "rdport", false, "[DTLS] randomize destination port")
	flag.StringVar(&p.portRangeString, "dstPortRange", "1000-65535", "[DTLS] Destination port range if randomized")
	flag.BoolVar(&p.noSNI, "no-sni", false, "[DTLS] Don't send the SNI extension")
}

func (p *dtlsProber) sendProbe(ip net.IP, name string, verbose bool) error {
	sport, _ := p.dkt.get(name)

	out, err := p.buildPayload(name)
	if err != nil {
		return fmt.Errorf("failed to build udp payload: %s", err)
	}

	var addr string
	if p.randDestinationPort {
		port := rand.Intn(p.randPortRange.max-p.randPortRange.min+1) + p.randPortRange.min
		addr = net.JoinHostPort(ip.String(), strconv.Itoa(port))
	} else {
		addr = net.JoinHostPort(ip.String(), "443")
	}
	sport, err = p.sender.sendUDP(addr, sport.(int), out, verbose)
	if err == nil && verbose {
		log.Printf("Sent :%s -> %s %s %s\n", sport, addr, name, hex.EncodeToString(out))
	}

	return err
}

func (p *dtlsProber) buildPayload(name string) ([]byte, error) {
	return buildDTLS1_2(name, !p.noSNI)
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

func buildDTLS1_3(name string, sendSNI bool) ([]byte, error) {
	// dynamic(random) - Client KeyShare extension public key
	buf := make([]byte, 32)
	n, err := rand.Read(buf)
	if err != nil || n != 32 {
		return nil, fmt.Errorf("failed rand read: %s", err)
	}
	var extKeySharePubkey = hex.EncodeToString(buf)
	var extKeyShare = "003300260024001d0020" + extKeySharePubkey

	var otherExtensions = extKeyShare + "002b000302fefc000d0020001e06030503040302030806080b0805080a080408090601050104010301020100160000000a00040002001d"

	// dynamic - Extensions lenggth
	var extensionsLen = "0061"
	var extLen = 0x61
	// var extensionsLen = fmt.Sprintf("%04x", len(name)+0x5f)

	var extSNI = ""
	if sendSNI {
		// len name + len SNI extension header + len other extensions.
		extensionsLen = fmt.Sprintf("%04x", len(name)+9+0x61)
		extLen += len(name) + 9
		var extSNIID = "0000"
		// dynamic - Extension lenggth (0018)
		var extSNIDataLen = fmt.Sprintf("%04x", len(name)+5)
		// dynamic - Extension lenggth (0016)
		var extSNIEntryLen = fmt.Sprintf("%04x", len(name)+3)
		var extSNIEntryType = "00"
		// dynamic - Extension lenggth (0013)
		var hostnameLen = fmt.Sprintf("%04x", len(name))
		var hostname = hex.EncodeToString([]byte(name))
		extSNI = extSNIID + extSNIDataLen + extSNIEntryLen + extSNIEntryType + hostnameLen + hostname
	}

	// Ciphersuites & Compression methods
	var csAndCM = "00061301130213030100"

	// cookie - legacy, not used in DTLS
	var cookie = "00"

	// session ID - legacy, not used in DTLS
	var sessionID = "00"

	// dynamic(random) - client Rand (32 generated bytes)
	buf = make([]byte, 32)
	n, err = rand.Read(buf)
	if err != nil || n != 32 {
		return nil, fmt.Errorf("failed rand read: %s", err)
	}
	var clientRandom = hex.EncodeToString(buf)

	// client version - legacy, supported versions extension used now
	var cv = "fefd"

	// dynamic - handshake reconstruction data sequence #, offset, and fragment len
	var rd = "0000" + "000000" + fmt.Sprintf("%06x", extLen+0x30)

	// dynamic - Handshake record type and len ClientHello data in this record
	var hh = "01" + fmt.Sprintf("%06x", extLen+0x30)
	// var hh = "01" + fmt.Sprintf("%06x", len(name)+0xc4) + "0303"

	// dynamic - bytes of handshake to follow
	var packetLen = fmt.Sprintf("%04x", extLen+0x3c)
	// var packetLen = fmt.Sprintf("%04x", len(name)+0xc8)

	// Record headder
	var rh = "16fefd0000000000000000"

	fulldata := rh + packetLen + hh + rd + cv + clientRandom + sessionID + cookie + csAndCM + extensionsLen + extSNI + otherExtensions
	return hex.DecodeString(fulldata)
}

func buildDTLS1_2(name string, sendSNI bool) ([]byte, error) {
	var otherExtensions = "00170000ff01000100000a00080006001d00170018000b0002010000230000000d00140012040308040401050308050501080606010201000e0009000600010008000700"

	// dynamic - Extensions lenggth
	var extensionsLen = "0044"
	var extLen = 0x44
	// var extensionsLen = fmt.Sprintf("%04x", len(name)+0x5f)

	var extSNI = ""
	if sendSNI {
		// len name + len SNI extension header + len other extensions.
		extLen += len(name) + 9
		extensionsLen = fmt.Sprintf("%04x", extLen)
		var extSNIID = "0000"
		// dynamic - Extension lenggth (0018)
		var extSNIDataLen = fmt.Sprintf("%04x", len(name)+5)
		// dynamic - Extension lenggth (0016)
		var extSNIEntryLen = fmt.Sprintf("%04x", len(name)+3)
		var extSNIEntryType = "00"
		// dynamic - Extension lenggth (0013)
		var hostnameLen = fmt.Sprintf("%04x", len(name))
		var hostname = hex.EncodeToString([]byte(name))
		extSNI = extSNIID + extSNIDataLen + extSNIEntryLen + extSNIEntryType + hostnameLen + hostname
	}

	// Ciphersuites & Compression methods
	var csAndCM = "0016c02bc02fcca9cca8c009c013c00ac014009c002f0035" + "0100"

	// cookie - legacy, not used in DTLS
	var cookie = "00"

	// session ID - legacy, not used in DTLS
	var sessionID = "00"

	// dynamic(random) - client Rand (32 generated bytes)
	buf := make([]byte, 32)
	n, err := rand.Read(buf)
	if err != nil || n != 32 {
		return nil, fmt.Errorf("failed rand read: %s", err)
	}
	var clientRandom = hex.EncodeToString(buf)

	// client version - legacy, supported versions extension used now
	var cv = "fefd"

	// dynamic - handshake reconstruction data sequence #, offset, and fragment len
	var rd = "0000" + "000000" + fmt.Sprintf("%06x", extLen+0x40)

	// dynamic - Handshake record type and len ClientHello data in this record
	var hh = "01" + fmt.Sprintf("%06x", extLen+0x40)
	// var hh = "01" + fmt.Sprintf("%06x", len(name)+0xc4) + "0303"

	// dynamic - bytes of handshake to follow
	var packetLen = fmt.Sprintf("%04x", extLen+0x4c)
	// var packetLen = fmt.Sprintf("%04x", len(name)+0xc8)

	// Record headder
	var rh = "16feff0000000000000000"

	fulldata := rh + packetLen + hh + rd + cv + clientRandom + sessionID + cookie + csAndCM + extensionsLen + extSNI + otherExtensions
	return hex.DecodeString(fulldata)
}

func parseRandRange(r string) (int, int, error) {

	s := strings.Split(r, "-")
	if len(s) < 2 {
		return -1, -1, fmt.Errorf("mal-formatted port range - must be format \"X-Y\" (e.g \"1000-65535\")  ")
	}

	min, err := strconv.Atoi(s[0])
	if err != nil {
		return -1, -1, err
	}

	max, err := strconv.Atoi(s[1])
	if err != nil {
		return -1, -1, err
	}

	return min, max, nil
}
