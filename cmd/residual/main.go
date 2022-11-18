package main

import (
	"bufio"
	"context"
	"flag"
	"log"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/jmwample/protoscan/pkg/probes"
	"github.com/jmwample/protoscan/pkg/probes/dns"
	"github.com/jmwample/protoscan/pkg/probes/http"
	"github.com/jmwample/protoscan/pkg/probes/tls"
	"github.com/jmwample/protoscan/pkg/send/raw"
	"github.com/jmwample/protoscan/pkg/send/tcp"
	"github.com/jmwample/protoscan/pkg/send/udp"
	"github.com/jmwample/protoscan/pkg/track"
)

var wrapUpDuration = 10 * time.Second

func getDomains(fname string) ([]string, error) {

	f, err := os.Open(fname)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func getIPs(fPath string) ([]string, error) {
	var ips []string
	var scanner *bufio.Scanner

	if fPath == "" {
		// if no filename is provided read ips from stdin
		scanner = bufio.NewScanner(os.Stdin)
	} else {
		file, err := os.Open(fPath)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()

		scanner = bufio.NewScanner(file)
	}

	for scanner.Scan() {
		line := scanner.Text()
		ips = append(ips, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return ips, nil
}

func main() {

	// only probe types planned for residual measurement. Added here for Flags
	var probers = map[string]probes.Prober{
		dns.ProbeTypeName:  &dns.Prober{},
		http.ProbeTypeName: &http.Prober{},
		tls.ProbeTypeName:  &tls.Prober{},
	}

	nWorkers := flag.Uint("workers", 50, "Number worker threads")

	verbose := flag.Bool("verbose", false, "Verbose prints sent/received DNS packets/info")
	seed := flag.Int64("seed", -1, "[HTTP/TLS/QUIC/DTLS] seed for random elements of generated packets. default seeded with time.Now.Nano")

	domainf := flag.String("domains", "domains.txt", "File with a list of domains to test")
	ctrlf := flag.String("controls", "ctrls.txt", "File with a list of control domains")
	ipFName := flag.String("ips", "", "File with a list of target ip to test. Empty string reads from stdin")
	outDir := flag.String("d", "out/", "output directory for log files")

	iface := flag.String("iface", "eth0", "Interface to listen on")
	lAddr4 := flag.String("laddr", "", "Local address to send packets from - unset uses default interface")
	lAddr6 := flag.String("laddr6", "", "Local address to send packets from - unset uses default interface")

	noChecksums := flag.Bool("no-checksums", false, "[HTTP/TLS] fix checksums on injected packets for TCP protocols")
	synDelay := flag.Duration("syn-delay", 1*time.Millisecond, "[HTTP/TLS] when syn ack is enabled delay between syn and data")

	pps := flag.String("pps", "", "Human readable string of packet per second limit on send")
	bps := flag.String("bps", "", "Human readable string of bytes per second limit on send")

	for _, p := range probers {
		p.RegisterFlags()
	}

	flag.Parse()

	err := os.MkdirAll(*outDir, os.ModePerm)
	if err != nil {
		log.Fatalln(err)
	}

	logFile, err := os.OpenFile(filepath.Join(*outDir, "log.out"), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer logFile.Close()
	log.SetOutput(logFile)

	if *seed == -1 {
		*seed = int64(time.Now().Nanosecond())
	}
	log.Println("Using seed:", *seed)
	rand.Seed(*seed)

	// Parse domains
	domains, err := getDomains(*domainf)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Read %d domains\n", len(domains))

	// Parse domains
	controls, err := getDomains(*ctrlf)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Read %d controls\n", len(controls))

	// Get IPs
	ips, err := getIPs(*ipFName)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Read %d ips\n", len(ips))

	allKeys := append(domains, controls...)
	dkt, err := track.NewDomainKeyTable(allKeys)
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		// dump dkt to file for reference
		dktFile, err := os.OpenFile(filepath.Join(*outDir, "dkt.json"), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			log.Fatalf("error opening dkt file: %v", err)
		}
		defer dktFile.Close()
		err = dkt.Marshal(dktFile)
		if err != nil {
			log.Fatalf("error writing domain key table: %v", err)
		}
	}()

	ctx := context.Background()
	rawSender, err := raw.NewSenderLimited(ctx, *iface, int(*nWorkers), *pps, *bps)
	if err != nil {
		log.Fatal(err)
	}
	defer rawSender.Close()

	tcpSender, err := tcp.FromRaw(rawSender, *iface, *lAddr4, *lAddr6)
	if err != nil {
		log.Fatal(err)
	}

	udpSender, err := udp.FromRaw(rawSender, *iface, *lAddr4, *lAddr6)
	if err != nil {
		log.Fatal(err)
	}

	optDNS := udp.Options{
		Checksums: !*noChecksums,
	}

	optTCPNSA := tcp.Options{
		Checksums: !*noChecksums,
		Ack:       false,
		Syn:       false,
		SynDelay:  *synDelay,
	}

	optTCP := tcp.Options{
		Checksums: !*noChecksums,
		Ack:       true,
		Syn:       true,
		SynDelay:  *synDelay,
	}

	probers = map[string]probes.Prober{
		dns.ProbeTypeName: &dns.Prober{
			Sender:        udpSender,
			OutDir:        *outDir + "/dns",
			SenderOptions: optDNS,
		},
		http.ProbeTypeName: &http.Prober{
			Sender:        tcpSender,
			DKT:           dkt,
			OutDir:        *outDir + "/http",
			SenderOptions: optTCP,
		},
		http.ProbeTypeName + "nsa": &http.Prober{
			Sender:        tcpSender,
			DKT:           dkt,
			OutDir:        *outDir + "/http-nsa",
			SenderOptions: optTCPNSA,
		},
		tls.ProbeTypeName: &tls.Prober{
			Sender:        tcpSender,
			DKT:           dkt,
			OutDir:        *outDir + "/tls",
			SenderOptions: optTCP,
		},
		tls.ProbeTypeName + "nsa": &tls.Prober{
			Sender:        tcpSender,
			DKT:           dkt,
			OutDir:        *outDir + "/tls-nsa",
			SenderOptions: optTCPNSA,
		},
	}

	// go func(c context.Context) {
	// 	ticker := time.NewTicker(5 * time.Second)
	// 	for {
	// 		select {
	// 		case <-c.Done():
	// 			return
	// 		case <-ticker.C:
	// 			rawSender.PrintAndReset()
	// 		}
	// 	}
	// }(ctx)

	// serial wait times - cumulative in comments
	wait1 := []time.Duration{
		0 * time.Second,
		1 * time.Second,
		3 * time.Second, // 4
		5 * time.Second, // 9
		// 20 * time.Second, // 29
		// 30 * time.Second, // 59
		// 30 * time.Second, // 89
		// 30 * time.Second, // 119
		// 60 * time.Second, // 179
		// 60 * time.Second, // 239
		// 60 * time.Second, // 299
	}

	// wait2 := []time.Duration{

	// }

	for pName, p := range probers {

		log.Println("starting ", pName)
		pcapWg := new(sync.WaitGroup)

		// Measure and capture for the control domains first
		ctrlCtx, ctrlFinished := context.WithCancel(context.Background())
		pcapWg.Add(1)
		go p.HandlePcap(ctrlCtx, *iface, "ctrl", pcapWg)

		for _, ctrl := range controls {
			for _, ip := range ips {
				target := net.ParseIP(ip)
				err := p.SendProbe(target, ctrl, 0, *verbose)
				if err != nil {
					log.Printf("Result %s,%s - error: %v\n", ip, ctrl, err)
					continue
				}
			}
		}
		ctrlFinished()
		log.Println("completed ctrl", pName)
		pcapWg.Wait()

		// Measure for sensitive domains and control domains w/ backoff
		probeCtx, probeFinished := context.WithCancel(context.Background())
		pcapWg.Add(1)
		go p.HandlePcap(probeCtx, *iface, "", pcapWg)

		for _, domain := range domains {
			for _, ip := range ips {
				target := net.ParseIP(ip)
				err := p.SendProbe(target, domain, 0, *verbose)
				if err != nil {
					log.Printf("Result %s,%s - error: %v\n", ip, domain, err)
					continue
				}
			}

			for i, backoff := range wait1 {
				time.Sleep(backoff)

				for _, ctrl := range controls {
					for _, ip := range ips {
						// Wait here for rate limiting

						target := net.ParseIP(ip)
						err := p.SendProbe(target, ctrl, i, *verbose)
						if err != nil {
							log.Printf("Result %s,%s - error: %v\n", ip, domain, err)
							continue
						}
					}
				}

			}
		}

		// time.Sleep(wrapUpDuration)
		probeFinished()
		log.Println("completed probing", pName)
		pcapWg.Wait()
	}
}
