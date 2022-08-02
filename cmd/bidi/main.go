package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"log"
	"math/rand"
	"net"
	"os"
	"sync"
	"time"
)

type prober interface {
	registerFlags()

	sendProbe(ip net.IP, name string, verbose bool) error

	handlePcap(iface string)
}

type job struct {
	domain string
	ip     string
}

func worker(p prober, wait time.Duration, verbose bool, ips <-chan *job, wg *sync.WaitGroup) {
	defer wg.Done()

	for job := range ips {
		addr := net.ParseIP(job.ip)
		err := p.sendProbe(addr, job.domain, verbose)
		if err != nil {
			log.Printf("Result %s,%s - error: %v\n", job.ip, job.domain, err)
			continue
		}

		// Wait here
		time.Sleep(wait)
	}
}

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

	var probers = map[string]prober{
		dnsProbeTypeName:  &dnsProber{},
		httpProbeTypeName: &httpProber{},
		tlsProbeTypeName:  &tlsProber{},
		quicProbeTypeName: &quicProber{},
	}

	nWorkers := flag.Uint("workers", 50, "Number worker threads")
	wait := flag.Duration("wait", 5*time.Second, "Duration a worker waits after sending a probe")
	verbose := flag.Bool("verbose", true, "Verbose prints sent/received DNS packets/info")
	domainf := flag.String("domains", "domains.txt", "File with a list of domains to test")
	ipFName := flag.String("ips", "", "File with a list of target ip to test. Empty string reads from stdin")
	iface := flag.String("iface", "eth0", "Interface to listen on")
	lAddr4 := flag.String("laddr", "", "Local address to send packets from - unset uses default interface")
	lAddr6 := flag.String("laddr6", "", "Local address to send packets from - unset uses default interface")
	proberType := flag.String("type", "dns", "probe type to send")
	seed := flag.Int64("seed", -1, "[HTTP/TLS/QUIC] seed for random elements of generated packets. default seeded with time.Now.Nano")
	noSynAck := flag.Bool("nsa", false, "[HTTP/TLS] No Syn Ack (nsa) disable syn, and ack warm up packets for tcp probes")
	synDelay := flag.Duration("syn-delay", 2*time.Millisecond, "[HTTP/TLS] when syn ack is enabled delay between syn and data")
	noChecksums := flag.Bool("no-checksums", false, "[HTTP/TLS] fix checksums on injected packets for TCP protocols")

	for _, p := range probers {
		p.registerFlags()
	}

	flag.Parse()

	var p prober
	var ok bool
	if p, ok = probers[*proberType]; !ok {
		panic("unknown probe type")
	}

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

	// Get IPs
	ips, err := getIPs(*ipFName)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Read %d ips\n", len(ips))

	dkt, err := createDomainKeyTable(domains)
	if err != nil {
		log.Fatal(err)
	}

	dktJSON, err := json.Marshal(dkt)
	if err != nil {
		log.Fatal(err)
	}
	log.Println(string(dktJSON))

	switch prober := p.(type) {
	case *httpProber:
		t, err := newTCPSender(*iface, *lAddr4, *lAddr6, !*noSynAck, *synDelay, !*noChecksums)
		if err != nil {
			log.Fatal(err)
		}
		prober.sender = t
		prober.dkt = dkt
	case *tlsProber:
		t, err := newTCPSender(*iface, *lAddr4, *lAddr6, !*noSynAck, *synDelay, !*noChecksums)
		if err != nil {
			log.Fatal(err)
		}
		prober.sender = t
		prober.dkt = dkt
	case *quicProber:
		u, err := newUDPSender(*iface, *lAddr4, *lAddr6)
		if err != nil {
			log.Fatal(err)
		}
		prober.sender = u
		prober.dkt = dkt
	case *dnsProber:
		u, err := newUDPSender(*iface, *lAddr4, *lAddr6)
		if err != nil {
			log.Fatal(err)
		}
		prober.sender = u
	}

	jobs := make(chan *job, *nWorkers*10)
	var wg sync.WaitGroup

	for w := uint(0); w < *nWorkers; w++ {
		wg.Add(1)
		// go dnsWorker(*wait, *verbose, false, *lAddr, ips, domains, &wg)
		go worker(p, *wait, *verbose, jobs, &wg)
	}

	go p.handlePcap(*iface)

	go func() {
		if *verbose {
			start := time.Now()
			epochStart := time.Now()
			for {
				time.Sleep(5 * time.Second)
				epochDur := time.Since(epochStart).Milliseconds()
				log.Printf("stats %d %d %d %d %d %d",
					time.Since(start).Milliseconds(),
					epochDur,
					stats.pt,
					stats.bt,
					stats.ppe*1000/epochDur,
					stats.bpe*1000/epochDur)

				stats.epochReset()
				epochStart = time.Now()
			}
		}
	}()

	nJobs := 0
	for _, domain := range domains {
		for _, ip := range ips {
			jobs <- &job{domain: domain, ip: ip}
			nJobs++
		}
	}
	close(jobs)

	wg.Wait()
}
