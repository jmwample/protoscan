package main

import (
	"bufio"
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

	sendProbe(ip net.IP, name string, lAddr string, verbose bool) error

	buildPayload(name string) ([]byte, error)

	handlePcap(iface string)
}

func worker(p prober, wait time.Duration, verbose bool, lAddr string, ips <-chan string, domains []string, wg *sync.WaitGroup) {
	defer wg.Done()

	for ip := range ips {
		addr := net.ParseIP(ip)
		if verbose {
			log.Printf("Sending to %v...\n", addr)
		}

		for _, domain := range domains {
			err := p.sendProbe(addr, domain, lAddr, verbose)
			if err != nil {
				log.Printf("Result %s,%s - error: %v\n", ip, domain, err)
				continue
			}

			// Wait here
			time.Sleep(wait)
		}
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
	iface := flag.String("iface", "eth0", "Interface to listen on")
	lAddr := flag.String("laddr", "", "Local address to send packets from - unset uses default interface")
	proberType := flag.String("type", "dns", "probe type to send")
	seed := flag.Int64("seed", -1, "[HTTP/TLS/QUIC] seed for random elements of generated packets. default seeded with time.Now.Nano")
	noSynAck := flag.Bool("nsa", false, "[HTTP/TLS] No Syn Ack (nsa) disable syn, and ack warm up packets for tcp probes")
	synDelay := flag.Duration("syn-delay", 2*time.Millisecond, "[HTTP/TLS] when syn ack is enabled delay between syn and data")

	for _, p := range probers {
		p.registerFlags()
	}

	flag.Parse()

	var p prober
	var ok bool
	if p, ok = probers[*proberType]; !ok {
		panic("unknown probe type")
	}

	switch prober := p.(type) {
	case *httpProber:
		prober.device = *iface
		if *seed == -1 {
			prober.seed = int64(time.Now().Nanosecond())
		} else {
			prober.seed = *seed
		}
		prober.r = rand.New(rand.NewSource(prober.seed))
		prober.sendSynAndAck = !*noSynAck
		prober.synDelay = *synDelay
	case *tlsProber:
		prober.device = *iface
		if *seed == -1 {
			prober.seed = int64(time.Now().Nanosecond())
		} else {
			prober.seed = *seed
		}
		prober.r = rand.New(rand.NewSource(prober.seed))
		prober.sendSynAndAck = !*noSynAck
		prober.synDelay = *synDelay
	case *quicProber:
		prober.device = *iface
		if *seed == -1 {
			prober.seed = int64(time.Now().Nanosecond())
		} else {
			prober.seed = *seed
		}
		prober.r = rand.New(rand.NewSource(prober.seed))
	}

	// Parse domains
	domains, err := getDomains(*domainf)
	if err != nil {
		log.Println(err)
		return
	}
	log.Printf("Read %d domains\n", len(domains))

	ips := make(chan string, *nWorkers*10)
	var wg sync.WaitGroup

	for w := uint(0); w < *nWorkers; w++ {
		wg.Add(1)
		// go dnsWorker(*wait, *verbose, false, *lAddr, ips, domains, &wg)
		go worker(p, *wait, *verbose, *lAddr, ips, domains, &wg)
	}

	go p.handlePcap(*iface)

	nJobs := 0
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		ips <- line
		nJobs++
	}
	close(ips)

	if err := scanner.Err(); err != nil {
		log.Println(err)
	}

	wg.Wait()
}
