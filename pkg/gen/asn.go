package gen

import (
	"bufio"
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
)

// ASNMap maps a string to a list of subnets. Here this maps ASN to to the list
// of subnets allocated within that country.
type ASNMap map[uint][]*net.IPNet

// GetRandomSubnet uses the provided random reader to select a random subnet out
// of the set of subnets associated with the provided country code. Returns nil
// if country code is not in map
func (asnm *ASNMap) GetRandomSubnet(r io.Reader, asn uint) *net.IPNet {
	if asnm.contains(asn) == ErrNoSubnets {
		return nil
	}
	tmpSlice := make([]byte, 4)
	_, err := r.Read(tmpSlice)
	if err != nil {
		return nil
	}
	i := binary.BigEndian.Uint32(tmpSlice) % uint32(len((*asnm)[asn]))
	return (*asnm)[asn][i]
}

// GetRandomAddr uses the provided random reader to select a random address
// from a random subnet out of the set of subnets associated with the provided
// country code. Return nil if country code is not in map
func (asnm *ASNMap) GetRandomAddr(r io.Reader, asn uint) *net.IP {
	if asnm.contains(asn) == ErrNoSubnets {
		return nil
	}
	subnet := asnm.GetRandomSubnet(r, asn)
	return RandomAddr(r, subnet)
}

func (asnm *ASNMap) contains(asn uint) error {
	if _, ok := (*asnm)[asn]; !ok {
		return ErrNoSubnets
	}
	return nil
}

// AutonomousSystemNumberMaps contains the ASNMaps mapping country code to subnet
// allocations for both IPv4 and IPv6 subnet allocations.
type AutonomousSystemNumberMaps struct {
	V4Map ASNMap
	V6Map ASNMap
}

// BuildASNMaps build the reverse map of country code to associated
// subnets
func BuildASNMaps(dbPath string) (*AutonomousSystemNumberMaps, error) {

	var err error
	var asnMap = &AutonomousSystemNumberMaps{}

	// Parse V4 Subnets.
	asnMap.V4Map, err = parseASNSubnets(dbPath + "GeoLite2-ASN-Blocks-IPv4.csv")
	if err != nil {
		return nil, err
	}

	// Parse V6 Subnets.
	asnMap.V6Map, err = parseASNSubnets(dbPath + "GeoLite2-ASN-Blocks-IPv6.csv")
	if err != nil {
		return nil, err
	}

	return asnMap, nil
}

func parseASNSubnets(csvPath string) (map[uint][]*net.IPNet, error) {
	csvFile, _ := os.Open(csvPath)
	reader := csv.NewReader(bufio.NewReader(csvFile))
	subnetMap := make(map[uint][]*net.IPNet, 0)

	// Parse label line
	_, err := reader.Read()
	if err != nil {
		if err == io.EOF {
			return nil, fmt.Errorf("Error parsing csv file '%s': Not enough content", csvPath)
		}
		return nil, fmt.Errorf("Error parsing csv file '%s: %s", csvPath, err)
	}

	for {
		line, err := reader.Read()
		if err == io.EOF {
			break
		} else if err != nil {
			log.Println(err)
			continue
		}

		if line[2] == "" {
			continue
		}

		// parse ASN to uint
		asn, err := strconv.ParseUint(line[1], 10, 32)
		if err != nil {
			log.Println(err)
			continue
		}

		// parse subnet from CIDR
		_, network, err := net.ParseCIDR(line[0])
		if err != nil {
			log.Println(err)
			continue
		}

		subnetMap[uint(asn)] = append(subnetMap[uint(asn)], network)
	}

	return subnetMap, nil
}

// GetRandomAddr4 selects an IPv4 addresses at random with from subnets
// associated with a specific country code.
func (asnm *AutonomousSystemNumberMaps) GetRandomAddr4(r io.Reader, asn uint) (*net.IP, error) {
	if err := asnm.V4Map.contains(asn); err != nil {
		return nil, err
	}
	return asnm.V4Map.GetRandomAddr(r, asn), nil
}

// GetRandomAddr6 selects an IPv6 addresses at random with from subnets
// associated with a specific country code.
func (asnm *AutonomousSystemNumberMaps) GetRandomAddr6(r io.Reader, asn uint) (*net.IP, error) {
	if err := asnm.V6Map.contains(asn); err != nil {
		return nil, err
	}
	return asnm.V6Map.GetRandomAddr(r, asn), nil
}

// GetNRandomAddr4 selects N IPv4 addresses at random with no repeats from
// subnets associated with a specific country code.
func (asnm *AutonomousSystemNumberMaps) GetNRandomAddr4(r io.Reader, asn uint, n int) ([]*net.IP, error) {
	if err := asnm.V4Map.contains(asn); err != nil {
		return nil, err
	}
	addrs := make([]*net.IP, 0)

	for i := 0; len(addrs) < n; i++ {
		addr := asnm.V4Map.GetRandomAddr(r, asn)
		if addr == nil {
			continue
		}
		for _, a := range addrs {
			if a.String() == addr.String() {
				continue
			}
		}

		addrs = append(addrs, addr)
	}

	return addrs, nil
}

// GetNRandomAddr6 selects N IPv6 addresses at random with no repeats from
// subnets associated with a specific country code.
func (asnm *AutonomousSystemNumberMaps) GetNRandomAddr6(r io.Reader, asn uint, n int) ([]*net.IP, error) {
	if err := asnm.V6Map.contains(asn); err != nil {
		return nil, err
	}
	addrs := make([]*net.IP, 0)

	for i := 0; len(addrs) < n; i++ {
		addr := asnm.V6Map.GetRandomAddr(r, asn)
		if addr == nil {
			continue
		}
		for _, a := range addrs {
			if a.String() == addr.String() {
				continue
			}
		}

		addrs = append(addrs, addr)
	}

	return addrs, nil
}

// GetASNList returns a list of all autonomous system numbers found.
func (asnm *AutonomousSystemNumberMaps) GetASNList() []uint {
	j := 0
	asns := make([]uint, len(asnm.V4Map))
	for asn := range asnm.V4Map {
		asns[j] = asn
		j++
	}
	for asn := range asnm.V6Map {
		seen := false
		for _, known := range asns {
			if known == asn {
				seen = true
			}
		}
		if !seen {
			asns = append(asns, asn)
		}
	}

	sort.Slice(asns, func(i, j int) bool { return asns[i] < asns[j] })
	return asns
}
