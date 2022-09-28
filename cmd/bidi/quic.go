package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash/crc64"
	"log"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"unsafe"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/hkdf"
)

const quicProbeTypeName = "quic"

type quicProber struct {
	sender *udpSender

	dkt *KeyTable

	outDir string
}

func (p *quicProber) registerFlags() {
}

func (p *quicProber) sendProbe(ip net.IP, name string, verbose bool) error {
	sport, _ := p.dkt.get(name)

	out, clientID, err := p.buildPayload(name, ip, sport.(int))
	if err != nil {
		return fmt.Errorf("failed to build quic payload: %s", err)
	}

	addr := net.JoinHostPort(ip.String(), "443")
	sport, err = p.sender.sendUDP(addr, sport.(int), out, verbose)
	if err == nil && verbose {
		log.Printf("Sent :%s -> %s %s %s\n", sport, addr, name, clientID)
	}

	return err
}

func (p *quicProber) buildPayload(name string, target net.IP, sport int) ([]byte, string, error) {
	// var fullData = "cd0000000108000102030405060705635f636964004103981c36a7ed78716be9711ba498b7ed868443bb2e0c514d4d848eadcc7a00d25ce9f9afa483978088de836be68c0b32a24595d7813ea5414a9199329a6d9f7f760dd8bb249bf3f53d9a77fbb7b395b8d66d7879a51fe59ef9601f79998eb3568e1fdc789f640acab3858a82ef2930fa5ce14b5b9ea0bdb29f4572da85aa3def39b7efafffa074b9267070d50b5d07842e49bba3bc787ff295d6ae3b514305f102afe5a047b3fb4c99eb92a274d244d60492c0e2e6e212cef0f9e3f62efd0955e71c768aa6bb3cd80bbb3755c8b7ebee32712f40f2245119487021b4b84e1565e3ca31967ac8604d4032170dec280aeefa095d08b3b7241ef6646a6c86e5c62ce08be099"
	headerByteAndVersion := "c000000001"

	// dynamic - client ID used for HKDF key schedule generation
	//
	// set the client ID to be the CRC64-ECMA of the source port, the
	// destination IP. This should allow a validation that the packet is related
	// to a probe we sent.
	ipByteSlice := (*[4]byte)(unsafe.Pointer(&sport))[:] // sport to []byte
	ipByteSlice = append(ipByteSlice, target.To16()...)  // append ip bytes

	// The ECMA polynomial, defined in ECMA 182.
	cid := crc64.Checksum(ipByteSlice, crc64.MakeTable(crc64.ECMA))
	clientID := (*[8]byte)(unsafe.Pointer(&cid))[:] // convert u64 to []byte
	dstConnID := "08" + hex.EncodeToString(clientID)

	// dynamic - source ID
	buf := make([]byte, 5)
	n, err := rand.Read(buf)
	if err != nil || n != 5 {
		return nil, "", fmt.Errorf("failed rand read: %s", err)
	}
	srcConnID := "05" + hex.EncodeToString(buf)

	token := "00"

	// dynamic - packet length
	packetLen := "4" + fmt.Sprintf("%03x", 0xfa+len(name))

	var packetNum uint64 = 0
	packetNumStr := fmt.Sprintf("%02x", packetNum)

	paylaod, err := p.buildCryptoFramePaylaod(name)
	if err != nil {
		return nil, "", err
	}

	header := headerByteAndVersion + dstConnID + srcConnID + token + packetLen + packetNumStr
	headerData, err := hex.DecodeString(header)
	if err != nil {
		return nil, "", err
	}

	km, err := generateKeyMaterial(clientID)
	if err != nil {
		return nil, "", err
	}

	cipherPayload, err := quicEncryptInitial(km, paylaod, headerData, packetNum)
	if err != nil {
		return nil, "", err
	}

	// Computer header protection info
	sample := cipherPayload[3 : 3+16]
	headerData, err = quicHeaderProtect(km, headerData, sample)
	if err != nil {
		return nil, "", err
	}

	// re-parse the updated header and create the full packet
	fullData := hex.EncodeToString(headerData) + hex.EncodeToString(cipherPayload)

	// TODO enable padding
	padLen := (1200*2 - len(fullData)) / 2

	out, err := hex.DecodeString(fullData + hex.EncodeToString(make([]byte, padLen)))
	if err != nil {
		return nil, "", err
	}

	return out, hex.EncodeToString(clientID), err
}

func (p *quicProber) buildCryptoFramePaylaod(name string) ([]byte, error) {

	// var fulldata = "060040ee010000f40303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000813021303130100ff010000a30000001800160000136578616d706c652e756c666865696d2e6e6574000b000403000102000a00160014001d0017001e0019001801000101010201030104002300000016000000170000000d001e001c040305030603080708080809080a080b080408050806040105010601002b0003020304002d00020101003300260024001d0020358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254"

	//
	var ch = "06004" + fmt.Sprintf("%03x", len(name)+0xe5)

	// dynamic - Handshake header and client version
	var hh = "01" + fmt.Sprintf("%06x", len(name)+0xe1) + "0303"

	// dynamic - client Rand (32 generated bytes)
	buf := make([]byte, 32)
	n, err := rand.Read(buf)
	if err != nil || n != 32 {
		return nil, fmt.Errorf("failed rand read: %s", err)
	}
	var clientRandom = hex.EncodeToString(buf)

	// dynamic - session ID (33 bytes 32 generated)
	n, err = rand.Read(buf)
	if err != nil || n != 32 {
		return nil, fmt.Errorf("failed rand read: %s", err)
	}
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

	var otherExtensions = "000b000403000102000a00160014001d0017001e0019001801000101010201030104002300000016000000170000000d001e001c040305030603080708080809080a080b080408050806040105010601002b0003020304002d00020101003300260024001d0020358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254"
	fulldata := ch + hh + clientRandom + sessionID + csAndCM + extensionsLen + extSNIID + extSNIDataLen + extSNIEntryLen + extSNIEntryType + hostnameLen + hostname + otherExtensions

	return hex.DecodeString(fulldata)
}

func (p *quicProber) handlePcap(iface string) {
	f, _ := os.Create(filepath.Join(p.outDir, "quic.pcap"))
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(1600, layers.LinkTypeEthernet)
	defer f.Close()

	if handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter("icmp or icmp6 or udp src port 443"); err != nil { // optional
		panic(err)
	} else {
		defer handle.Close()

		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
			// p.handlePacket(packet)
		}
	}
}

func (p *quicProber) handlePacket(packet gopacket.Packet) {

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
		log.Printf("RESULT QUIC %s %v", ipAddr, tcp.RST)
	} else {
		log.Printf("RESULT QUIC")
	}
}

// quicEncryptInitialHandshake encrypts the incoming bytestream using the
// specified initial client handshake parameters and returns the encrypted
// stream of data as well as the computed auth tag - or an error if one occurred.
func quicEncryptInitial(km *keyMaterial, frameData, headerData []byte, packetNum uint64) ([]byte, error) {
	// gcmIVLen := 12
	// gcmTagLen := 16
	// aesKeyLen := 16

	// 16 by key indicates AES 128
	block, err := aes.NewCipher(km.key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// TODO
	ciphertext := aesgcm.Seal(nil, km.iv, frameData, headerData)
	return ciphertext, nil
}

type keyMaterial struct {
	secret, key, iv, hpk []byte
}

func generateKeyMaterial(clientID []byte) (*keyMaterial, error) {
	initialSalt, _ := hex.DecodeString("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")

	km := &keyMaterial{}
	// // TODO
	initialSecret := hkdf.Extract(sha256.New, clientID, initialSalt)
	_ = initialSecret
	km.secret = expandLabel(initialSecret, "client in", nil, 32)
	km.key = expandLabel(km.secret, "quic key", nil, 16)
	km.iv = expandLabel(km.secret, "quic iv", nil, 12)
	km.hpk = expandLabel(km.secret, "quic hp", nil, 16)

	return km, nil
}

func expandLabel(secret []byte, label string, context []byte, length int) []byte {

	var hkdfLabel cryptobyte.Builder
	hkdfLabel.AddUint16(uint16(length))
	hkdfLabel.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes([]byte("tls13 "))
		b.AddBytes([]byte(label))
	})

	hkdfLabel.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(context)
	})

	out := make([]byte, length)
	n, err := hkdf.Expand(sha256.New, secret, hkdfLabel.BytesOrPanic()).Read(out)
	if err != nil || n != length {
		panic("tls: HKDF-Expand-Label invocation failed unexpectedly")
	}

	return out
}

func quicHeaderProtect(km *keyMaterial, headerData, sample []byte) ([]byte, error) {
	newHeaderData := headerData
	// 16 by key indicates AES 128
	block, err := aes.NewCipher(km.hpk)
	if err != nil {
		return nil, err
	}
	mask := make([]byte, 16)
	block.Encrypt(mask, sample)
	newHeaderData[0] ^= (mask[0] & 0x0f)
	newHeaderData[len(newHeaderData)-1] ^= mask[1]

	return newHeaderData, nil
}
