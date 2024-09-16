package shared

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/gopacket/routing"
)

var stats *sendStats = &sendStats{}

type sendStats struct {
	// packets per epoch
	ppe int64
	// bytes per epoch
	bpe int64
	// packets total
	pt int64
	// bytes total
	bt int64

	mu sync.Mutex
}

func (s *sendStats) incPacketPerSec() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ppe++
	s.pt++
}

func (s *sendStats) incBytesPerSec(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bpe += int64(n)
	s.bt += int64(n)
}

func (s *sendStats) epochReset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bpe = 0
	s.ppe = 0
}

// GetSrcIP allows us to check that there is a route to the dest with our
// suggested source address and interface. This also allows the program to
// automatically recover from an ipv4 source address specified for an IPv6
// target address by using the preferred source address provided by the call to
// RouteWithSource. That way we don't have to support v4 and v6 local address
// cli options. Also allows for empty or bad source from cli.
func GetSrcIP(localIface *net.Interface, lAddr string, dstIP net.IP) (net.IP, error) {
	var useV4 = dstIP.To4() != nil

	var localIP = net.ParseIP(lAddr)
	if useV4 && localIP.To4() == nil {
		localIP = nil
	} else if !useV4 && localIP.To4() != nil {
		localIP = nil
	}

	router, err := routing.New()
	if err != nil {
		return nil, fmt.Errorf("failed to init routing: %s", err)
	}

	// ignore gateway, but adopt preferred source if unsuitable lAddr was specified.
	_, _, preferredSrc, err := router.RouteWithSrc(localIface.HardwareAddr, localIP, dstIP)
	if err != nil {
		return nil, fmt.Errorf("failed to get remote iface: %s", err)
	}

	// If the specified local IP is unset or the wrong IP version for the target
	// substitute the preferred source.
	if localIP == nil {
		localIP = preferredSrc
	}

	return localIP, nil
}

func DecodeOrPanic(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

type NetLayer interface {
	gopacket.SerializableLayer
	gopacket.NetworkLayer
}

func CapturePcap(ctx context.Context, iface, pcapPath, bpfFilter string, callback func(p gopacket.Packet), wg *sync.WaitGroup) {
	defer wg.Done()

	pcapDir := path.Dir(pcapPath)
	if _, err := os.Stat(pcapDir); errors.Is(err, os.ErrNotExist) {
		// directory to store pcap doesn't exist - create it
		err = os.MkdirAll(pcapDir, os.ModePerm)
		if err != nil {
			log.Println(err)
			return
		}
	}

	f, err := os.OpenFile(pcapPath+".gz", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	// Required otherwise io doesn't flush properly on deferred close
	outWriter := bufio.NewWriter(f)
	defer outWriter.Flush()

	// Write PCAP in compressed format.
	filename := path.Base(pcapPath)
	archiver := gzip.NewWriter(outWriter)
	archiver.Name = filename
	defer archiver.Close()

	// Write PCAP
	w := pcapgo.NewWriter(archiver)
	if err := w.WriteFileHeader(1600, layers.LinkTypeEthernet); err != nil {
		panic(err)
	}

	if handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter(bpfFilter); err != nil { // optional
		panic(err)
	} else {
		defer handle.Close()

		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
			select {
			case <-ctx.Done():
				log.Println("Closing pcap handler")
				return
			default:
				if err := w.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
					log.Printf("pcap.WritePacket() error: %v", err)
					return
				}
				if callback != nil {
					callback(packet)
				}
			}
		}
	}
}
