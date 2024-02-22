package main

import (
	"encoding/binary"
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
	tls "github.com/refraction-networking/utls"
)

const utlsProbeTypeName = "utls"

var tlsHeader, _ = hex.DecodeString("1603010")

type utlsProber struct {
	sender *tcpSender

	dkt *KeyTable

	outDir string

	pipeConn bool
	// PubClientHelloMsg -> used to generate new client hellos without calling generateECDHEParameters
	pchm *tls.PubClientHelloMsg
}

func (p *utlsProber) registerFlags() {
}

func (p *utlsProber) sendProbe(ip net.IP, name string, verbose bool) error {

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

func (p *utlsProber) generateCHM(name string) (*tls.PubClientHelloMsg, error) {
	tlsConfig := tls.Config{ServerName: name}
	uconn := tls.UClient(nil, &tlsConfig, tls.HelloCustom)

	clientHelloSpec := getSpec()
	uconn.ApplyPreset(&clientHelloSpec)

	err := uconn.BuildHandshakeState()
	if err != nil {
		return nil, fmt.Errorf("error building handshake state: %v", err)
	}

	return uconn.HandshakeState.Hello, nil
}

// buildPayload builds a tls payload with a specific TLS clientHello fingerprint
//
// If the template clientHello has not been set it will attempt to create
// the template ClientHello. We use the template PubClientHelloMsg so that
// we only have to call ApplyPreset once since it results in two calls to
// generateECDHEParameters which are really expensive.
func (p *utlsProber) buildPayload(name string) ([]byte, error) {
	if p.pchm == nil {
		chm, err := p.generateCHM(name)
		if err != nil {
			return nil, err
		}

		p.pchm = chm
	}

	pub := p.pchm
	_, err := rand.Read(pub.Random)
	if err != nil {
		return nil, err
	}
	_, err = rand.Read(pub.SessionId)
	if err != nil {
		return nil, err
	}

	pub.ServerName = name

	msg := pub.Marshal()

	bs := make([]byte, 2)
	binary.BigEndian.PutUint16(bs, uint16(len(msg)))
	header := append(tlsHeader, bs...)

	return append(header, msg...), nil
}

func (p *utlsProber) handlePcap(iface string) {
	f, _ := os.Create(filepath.Join(p.outDir, "utls.pcap"))
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

func (p *utlsProber) handlePacket(packet gopacket.Packet) {

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

func getSpec() tls.ClientHelloSpec {
	return tls.ClientHelloSpec{
		CipherSuites: []uint16{
			tls.GREASE_PLACEHOLDER,
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		CompressionMethods: []byte{
			0x00, // compressionNone
		},
		Extensions: []tls.TLSExtension{
			&tls.UtlsGREASEExtension{},
			&tls.SNIExtension{},
			&tls.UtlsExtendedMasterSecretExtension{},
			&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
			&tls.SupportedCurvesExtension{[]tls.CurveID{
				tls.CurveID(tls.GREASE_PLACEHOLDER),
				tls.X25519,
				tls.CurveP256,
				tls.CurveP384,
			}},
			&tls.SupportedPointsExtension{SupportedPoints: []byte{
				0x00, // pointFormatUncompressed
			}},
			&tls.SessionTicketExtension{},
			&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			&tls.StatusRequestExtension{},
			&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.PSSWithSHA256,
				tls.PKCS1WithSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.PSSWithSHA384,
				tls.PKCS1WithSHA384,
				tls.PSSWithSHA512,
				tls.PKCS1WithSHA512,
			}},
			&tls.SCTExtension{},
			&tls.KeyShareExtension{[]tls.KeyShare{
				{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
				{Group: tls.X25519},
			}},
			&tls.PSKKeyExchangeModesExtension{[]uint8{
				tls.PskModeDHE,
			}},
			&tls.SupportedVersionsExtension{[]uint16{
				tls.GREASE_PLACEHOLDER,
				tls.VersionTLS13,
				tls.VersionTLS12,
			}},
			&tls.UtlsCompressCertExtension{},
			&tls.GenericExtension{Id: 0x4469}, // WARNING: UNKNOWN EXTENSION, USE AT YOUR OWN RISK
			&tls.UtlsGREASEExtension{},
			&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
		},
	}

}
