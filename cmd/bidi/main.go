package main

import (
	"bufio"
	"flag"
	"log"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/jmwample/protoscan/pkg/send/probes/dns"
	"github.com/jmwample/protoscan/pkg/send/probes/http"
	"github.com/jmwample/protoscan/pkg/send/probes/quic"
	"github.com/jmwample/protoscan/pkg/send/probes/tls"
	"github.com/jmwample/protoscan/pkg/send/senders"
	"github.com/jmwample/protoscan/pkg/send/senders/tcp"
	"github.com/jmwample/protoscan/pkg/send/senders/udp"
)

type prober interface {
	RegisterFlags()

	SendProbe(ip net.IP, name string, verbose bool) error

	HandlePcap(iface string)
}

type job struct {
	domain string
	ip     string
}

func worker(p prober, wait time.Duration, verbose bool, ips <-chan *job, wg *sync.WaitGroup) {
	defer wg.Done()

	for job := range ips {
		addr := net.ParseIP(job.ip)
		err := p.SendProbe(addr, job.domain, verbose)
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
		dns.ProbeTypeName:  &dns.Prober{},
		http.ProbeTypeName: &http.Prober{},
		tls.ProbeTypeName:  &tls.Prober{},
		quic.ProbeTypeName: &quic.Prober{},
	}

	nWorkers := flag.Uint("workers", 50, "Number worker threads")
	wait := flag.Duration("wait", 5*time.Second, "Duration a worker waits after sending a probe")
	verbose := flag.Bool("verbose", false, "Verbose prints sent/received DNS packets/info")
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
	outDir := flag.String("d", "out/", "output directory for log files")

	for _, p := range probers {
		p.RegisterFlags()
	}

	flag.Parse()

	err := os.MkdirAll(*outDir, os.ModePerm)
	if err != nil {
		log.Println(err)
	}

	logFile, err := os.OpenFile(filepath.Join(*outDir, "log.out"), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer logFile.Close()
	log.SetOutput(logFile)

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

	switch prober := p.(type) {
	case *http.Prober:
		t, err := tcp.NewSender(*iface, *lAddr4, *lAddr6, !*noSynAck, *synDelay, !*noChecksums)
		if err != nil {
			log.Fatal(err)
		}
		prober.Sender = t
		prober.Dkt = dkt
		prober.OutDir = *outDir
		defer t.Clean()
	case *tls.Prober:
		t, err := tcp.NewSender(*iface, *lAddr4, *lAddr6, !*noSynAck, *synDelay, !*noChecksums)
		if err != nil {
			log.Fatal(err)
		}
		prober.Sender = t
		prober.Dkt = dkt
		prober.OutDir = *outDir
		defer t.Clean()
	case *quic.Prober:
		u, err := udp.NewSender(*iface, *lAddr4, *lAddr6, true, !*noChecksums)
		if err != nil {
			log.Fatal(err)
		}
		prober.Sender = u
		prober.Dkt = dkt
		prober.OutDir = *outDir
		defer u.Clean()
	case *dns.Prober:
		u, err := udp.NewSender(*iface, *lAddr4, *lAddr6, true, !*noChecksums)
		if err != nil {
			log.Fatal(err)
		}
		prober.Sender = u
		prober.OutDir = *outDir
		defer u.Clean()
	}

	jobs := make(chan *job, *nWorkers*10)
	var wg sync.WaitGroup

	for w := uint(0); w < *nWorkers; w++ {
		wg.Add(1)
		// go dnsWorker(*wait, *verbose, false, *lAddr, ips, domains, &wg)
		go worker(p, *wait, *verbose, jobs, &wg)
	}

	go p.HandlePcap(*iface)

	go func() {
		start := time.Now()
		epochStart := time.Now()
		for {
			time.Sleep(5 * time.Second)
			epochDur := time.Since(epochStart).Milliseconds()
			log.Printf("stats %d %d %s ", time.Since(start).Milliseconds(),
				epochDur,
				senders.Stats.GetEpochStats(epochDur))
			senders.Stats.EpochReset()
			epochStart = time.Now()
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

	// sleep for 15 seconds while HandlePcap still runs in case of delayed responses
	// time.Sleep(15 * time.Second)
}
