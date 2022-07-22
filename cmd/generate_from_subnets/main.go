package main

import (
	"flag"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"time"

	"github.com/timartiny/v4vsv6/pkg/gen"
)

var pathCC = "GeoLite2-Country/"
var maxGenerationRetries = 100

func main() {
	var dbDir, outfile, filterLiveFile string
	var seed, nAddrs int
	var all bool

	var ccList = []string{"AE", "AF", "BR", "CA", "CN", "CU", "FR", "IN", "IR", "HK", "MM", "PK", "RU", "SA", "TH", "TM", "UA", "VN", "US"}

	flag.StringVar(&dbDir, "d", "./GeoLite2/", "Database directory path")
	flag.StringVar(&filterLiveFile, "filter", "", "File containing list of addresses known to respond on UDP 53")
	flag.StringVar(&outfile, "o", "./generated_out", "Output file path")
	flag.IntVar(&seed, "s", -1, "PRNG seed (default seeded with time in ns)")
	flag.IntVar(&nAddrs, "n", 100, "Number of addresses per IP-version per country")
	flag.BoolVar(&all, "all", false, "Use all country codes instead of hard coded list")

	// parse flags from command line
	flag.Parse()

	var rdr io.Reader
	if seed == -1 {
		rdr = rand.New(rand.NewSource(time.Now().UnixNano()))
	} else {
		rdr = rand.New(rand.NewSource(int64(seed)))
	}
	// generate dict of subnets.
	ccMap, err := gen.BuildCountryCodeMaps(dbDir + pathCC)
	if err != nil {
		log.Fatal(err)
	}

	file4, err := os.Create(outfile + "_4")
	if err != nil {
		log.Fatal(err)
	}
	defer file4.Close()

	file6, err := os.Create(outfile + "_6")
	if err != nil {
		log.Fatal(err)
	}
	defer file6.Close()

	selectedAddrs := make(map[string]struct{})
	respondingAddrs, err := gen.ParseRespongindAddrs(filterLiveFile)
	if err != nil {
		log.Fatalln(err)
	}

	if all {
		ccList = ccMap.GetCCList()
	}

	for _, cc := range ccList {
		blockSize := 10
		randAddrs4 := []*net.IP{}
		randAddrs6 := []*net.IP{}
		for countryCount := 0; countryCount < nAddrs; countryCount += blockSize {
			retries := 0
		GenAddrs:
			if retries > maxGenerationRetries {
				log.Println("too many retries generating for", cc, countryCount)
				continue
			}
			randAddrs4, err = ccMap.GetNRandomAddr4(rdr, cc, blockSize, maxGenerationRetries)
			if err != nil {
				if err != gen.ErrNoSubnets {
					log.Println(err)
					continue
				}
			}
			randAddrs6, err = ccMap.GetNRandomAddr6(rdr, cc, blockSize, maxGenerationRetries)
			if err != nil {
				if err != gen.ErrNoSubnets {
					log.Println(err)
					continue
				}
			}

			for _, addr := range randAddrs4 {
				if _, ok := selectedAddrs[addr.String()]; ok {
					log.Println("generated addr already selected", addr, cc)
					retries++
					goto GenAddrs
				}
				if _, ok := respondingAddrs[addr.String()]; ok {
					log.Println("generated addr responds on UDP 53", addr)
					retries++
					goto GenAddrs
				}
			}
			for _, addr := range randAddrs6 {
				if _, ok := selectedAddrs[addr.String()]; ok {
					log.Println("generated addr already selected", addr, cc)
					retries++
					goto GenAddrs
				}
			}

			for _, addr := range randAddrs4 {
				selectedAddrs[addr.String()] = struct{}{}
				file4.WriteString(addr.String() + " " + cc + "\n")
			}

			for _, addr := range randAddrs6 {
				selectedAddrs[addr.String()] = struct{}{}
				file6.WriteString(addr.String() + " " + cc + "\n")
			}
		}
	}
}
