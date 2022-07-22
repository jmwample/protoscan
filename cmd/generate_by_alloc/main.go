// Package implements a command to generate N random addresses per autonomous
// system number (ASN) OR per allocation for all ASNs / allocations in a set of
// countries.
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
var pathASN = "GeoLite2-ASN/"
var maxRetries = 100

func main() {
	var dbDir, outFilePath, filterLiveFile, idFile, csvFile string
	var seed, nAddrs int
	var all, six bool

	// var ccList = []string{"AE", "AF", "BR", "CA", "CN", "CU", "FR", "IN", "IR", "HK", "MM", "PK", "RU", "SA", "TH", "TM", "UA", "VN", "US"}
	var ccList = []string{"CN", "IR"}

	flag.StringVar(&dbDir, "d", "./GeoLite2/", "Database directory path")
	flag.BoolVar(&six, "6", false, "Generate IPv6 addresses (generates IPv4 by default) by building map from default v6 maxmind db file path")

	flag.StringVar(&idFile, "id-file", "", "MaxMind CSV Country locations file (e.g. \"<path_to>/GeoLite2-Country-Locations-en.csv\"). Overrides '-d' and '-6' options.")
	flag.StringVar(&csvFile, "csv-file", "", "Maxmind CSV Country database file  (e.g. \"<path_to>/GeoLite2-Country-Blocks-IPv4.csv\"). Overrides '-d' and '-6' options.")

	flag.StringVar(&filterLiveFile, "filter", "", "File containing list of addresses known to respond on UDP 53")

	flag.StringVar(&outFilePath, "o", "./generated_out", "Output file path")
	flag.IntVar(&seed, "s", -1, "PRNG seed (default seeded with time in ns)")
	flag.IntVar(&nAddrs, "n", 2, "Number of addresses per IP-version per allocation")
	flag.BoolVar(&all, "all", false, "Use all country codes instead of hard coded list")

	// parse flags from command line
	flag.Parse()

	var rdr io.Reader
	if seed == -1 {
		rdr = rand.New(rand.NewSource(time.Now().UnixNano()))
	} else {
		rdr = rand.New(rand.NewSource(int64(seed)))
	}

	idFilePath := dbDir + pathCC + "GeoLite2-Country-Locations-en.csv"
	if idFile != "" {
		idFilePath = idFile
	}

	csvDBFilePath := dbDir + pathCC + "GeoLite2-Country-Blocks-IPv4.csv"
	if csvFile != "" {
		csvDBFilePath = csvFile
	} else if six {
		csvDBFilePath = dbDir + pathCC + "GeoLite2-Country-Blocks-IPv6.csv"
	}

	// generate dict of subnets.
	ccMap, err := gen.ParseCCMap(csvDBFilePath, idFilePath)
	if err != nil {
		log.Fatal(err)
	}

	outFile, err := os.Create(outFilePath)
	if err != nil {
		log.Fatal(err)
	}
	defer outFile.Close()

	selectedAddrs := make(map[string]struct{})
	respondingAddrs, err := gen.ParseRespongindAddrs(filterLiveFile)
	if err != nil {
		log.Fatalln(err)
	}

	if all {
		ccList = ccMap.GetCCList()
	}

	acceptance := func(addr *net.IP) bool {
		if _, ok := selectedAddrs[addr.String()]; ok {
			log.Println("generated addr already selected", addr)
			return false
		}
		if _, ok := respondingAddrs[addr.String()]; ok {
			log.Println("generated addr responds on UDP 53", addr)
			return false
		}
		return true
	}

	for _, cc := range ccList {
		randAddrs := []*net.IP{}

		randAddrs, err = ccMap.GetNAddrPerAlloc(rdr, cc, nAddrs, maxRetries, acceptance)
		if err != nil {
			if err == gen.ErrNoSubnets {
				log.Println("No subnets allocations found for", cc)
				continue
			}
		}

		for _, addr := range randAddrs {
			selectedAddrs[addr.String()] = struct{}{}
			outFile.WriteString(addr.String() + " " + cc + "\n")
		}
	}
}
