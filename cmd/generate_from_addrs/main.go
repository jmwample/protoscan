package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"time"

	"github.com/oschwald/geoip2-golang"
	"github.com/oschwald/maxminddb-golang"
	"github.com/timartiny/v4vsv6/pkg/gen"
)

var pathASN = "GeoLite2-ASN/"
var pathCC = "GeoLite2-Country/"
var maxGenerationRetries = 100

func main() {
	var dbDir, outfile, filterLiveFile string
	var seed, nAddrs int

	flag.StringVar(&dbDir, "d", "./GeoLite2/", "Database directory path")
	flag.StringVar(&outfile, "o", "./generated_out", "Output file path")
	flag.StringVar(&filterLiveFile, "filter", "", "File containing list of addresses known to respond on UDP 53")
	flag.IntVar(&seed, "s", -1, "PRNG seed (default seeded with time in ns)")
	flag.IntVar(&nAddrs, "n", 2, "Number of addresses per IP-version per input address")

	// parse flags from command line
	flag.Parse()

	var rdr io.Reader
	if seed == -1 {
		rdr = rand.New(rand.NewSource(time.Now().UnixNano()))
	} else {
		rdr = rand.New(rand.NewSource(int64(seed)))
	}

	mmdbReader, err := maxminddb.Open(dbDir + pathASN + "GeoLite2-ASN.mmdb")
	if err != nil {
		log.Fatal(err)
	}
	defer mmdbReader.Close()

	forwardCCDB, err := geoip2.Open(dbDir + pathCC + "GeoLite2-Country.mmdb")
	if err != nil {
		log.Fatal(err)
	}
	defer forwardCCDB.Close()

	outFile, err := os.Create(outfile)
	if err != nil {
		log.Fatal(err)
	}
	defer outFile.Close()

	selectedAddrs := make(map[string]struct{})
	respondingAddrs, err := gen.ParseRespongindAddrs(filterLiveFile)
	if err != nil {
		log.Fatalln(err)
	}

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		// fmt.Println(scanner.Text())

		retries := 0
		addr := scanner.Text()
		// make sure that we aren't randomly selecting addresses already in our list
		selectedAddrs[addr] = struct{}{}

		ip := net.ParseIP(addr)
		record, err := forwardCCDB.Country(ip)
		if err != nil {
			log.Println(addr, err)
			continue
		}

		cc := record.Country.IsoCode

	GenAddrs:
		if retries > maxGenerationRetries {
			log.Println("too many retries generating for", addr, cc)
			continue
		}
		randAddrs, err := getAddrs(addr, rdr, nAddrs, mmdbReader)
		if err != nil {
			log.Println(addr, err)
			continue
		}

		if len(randAddrs) == 0 {
			log.Printf("WEIRD no addresses selected for %s\n", addr)
			continue
		}

		for _, newAddr := range randAddrs {
			if _, ok := selectedAddrs[newAddr.String()]; ok {
				log.Println("generated addr already selected", addr, newAddr)
				retries++
				goto GenAddrs
			}
			if _, ok := respondingAddrs[newAddr.String()]; ok {
				log.Println("generated addr responds on UDP 53", newAddr)
				retries++
				goto GenAddrs
			}

		}

		// set of addresses succeeds or fails as a whole since we generated them
		// as a block -- if one fails we regenerate the block.
		for _, newAddr := range randAddrs {
			selectedAddrs[newAddr.String()] = struct{}{}
			outFile.WriteString(fmt.Sprintf("%s %s %s\n", newAddr, addr, cc))
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Println(err)
	}
}

func getAddrs(original string, rdr io.Reader, nAddrs int, db *maxminddb.Reader) ([]*net.IP, error) {
	ip := net.ParseIP(original)

	var record interface{}

	subnet, ok, err := db.LookupNetwork(ip, &record)
	if err != nil {
		return nil, err
	} else if !ok || subnet == nil {
		return nil, fmt.Errorf("address not found")
	}

	// addrs := make([]*net.IP, 0)
	addrs := make(map[*net.IP]struct{})

	for len(addrs) < nAddrs {
		newAddr := gen.RandomAddr(rdr, subnet)
		if newAddr == nil {
			return nil, fmt.Errorf("unable to generate address - check your random generator")
		}
		if _, ok := addrs[newAddr]; ok {
			// linear time lookups for inclusion instead of polynomial to make
			// sure we done generate duplicate addresses in a returned set.
			continue
		}

		addrs[newAddr] = struct{}{}
	}

	out := make([]*net.IP, len(addrs))
	i := 0
	for a := range addrs {
		out[i] = a
		i++
	}

	return out, nil
}
