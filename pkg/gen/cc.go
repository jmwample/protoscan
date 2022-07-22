package gen

import (
	"bufio"
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"os"
	"sort"
	"strconv"
)

// CCMap maps a string to a list of subnets. Here this maps Country codes to
// to the list of subnets allocated within that country.
type CCMap map[string][]*net.IPNet

// ParseCCMap build the reverse map of country code to associated
// subnets for one type of address.
func ParseCCMap(csvFilePath, idFilePath string) (CCMap, error) {
	idMap, err := parseIDMap(idFilePath)
	if err != nil {
		return nil, err
	}

	return parseSubnetsCC(csvFilePath, idMap)
}

// GetRandomSubnet uses the provided random reader to select a random subnet out
// of the set of subnets associated with the provided country code. Returns nil
// if country code is not in map
func (ccm *CCMap) GetRandomSubnet(r io.Reader, cc string) *net.IPNet {
	if ccm.contains(cc) == ErrNoSubnets {
		return nil
	}
	tmpSlice := make([]byte, 4)
	_, err := r.Read(tmpSlice)
	if err != nil {
		return nil
	}
	i := binary.BigEndian.Uint32(tmpSlice) % uint32(len((*ccm)[cc]))
	return (*ccm)[cc][i]
}

// GetRandomAddr uses the provided random reader to select a random address
// from a random subnet out of the set of subnets associated with the provided
// country code. Return nil if country code is not in map
func (ccm *CCMap) GetRandomAddr(r io.Reader, cc string) *net.IP {
	if ccm.contains(cc) == ErrNoSubnets {
		return nil
	}
	subnet := ccm.GetRandomSubnet(r, cc)
	return RandomAddr(r, subnet)
}

func (ccm *CCMap) contains(cc string) error {
	if _, ok := map[string][]*net.IPNet(*ccm)[cc]; !ok {
		return ErrNoSubnets
	}
	return nil
}

// GetNRandomAddr selects N addresses at random with no repeats from
// subnets associated with a specific country code.
func (ccm *CCMap) GetNRandomAddr(r io.Reader, cc string, n int, maxRetries int) ([]*net.IP, error) {
	if err := ccm.contains(cc); err != nil {
		return nil, err
	}

	selectedAddrs := make(map[string]struct{})
	addrs := make([]*net.IP, 0)
	retries := 0

	for i := 0; len(addrs) < n; {
		if retries >= maxRetries {
			return nil, ErrTooManyRetries
		}

		addr := ccm.GetRandomAddr(r, cc)
		if addr == nil {
			continue
		}

		if _, ok := selectedAddrs[addr.String()]; ok {
			retries++
			continue
		}

		addrs = append(addrs, addr)
		selectedAddrs[addr.String()] = struct{}{}
		i++
	}

	return addrs, nil
}

// GetNAddrPerAlloc selects N addresses per allocation for a specific country
// code. This function allows the caller to specify an acceptance test function
// and a max number of retries should a subnet fail too often.
func (ccm *CCMap) GetNAddrPerAlloc(r io.Reader, cc string, n int, maxRetries int, acceptance func(*net.IP) bool) ([]*net.IP, error) {
	if err := ccm.contains(cc); err != nil {
		return nil, err
	}

	selectedAddrs := make(map[string]struct{})
	addrs := make([]*net.IP, 0)

	if n == 0 {
		return addrs, nil
	}

ByAllocLoop:
	for _, alloc := range (*ccm)[cc] {
		retries := 0

		ones, bits := alloc.Mask.Size()
		if bits-ones <= int(math.Floor(math.Log(float64(n)))) {
			// for allocs less than double the number of addresses we need add
			// the mask IP and continue so we don't just fail retrying to
			// select. This also handle /32 and /128 which have a single IP.
			addr := &alloc.IP
			if _, ok := selectedAddrs[addr.String()]; ok {
				continue
			}

			addrs = append(addrs, addr)
			selectedAddrs[addr.String()] = struct{}{}
			continue
		}

		for i := 0; i < n; {

			if retries >= maxRetries {
				log.Printf("too many retries generating for %s in %s\n", alloc, cc)
				continue ByAllocLoop
			}

			addr := RandomAddr(r, alloc)
			if addr == nil {
				retries++
				continue
			} else if acceptance != nil && !acceptance(addr) {
				retries++
				continue
			} else if _, ok := selectedAddrs[addr.String()]; ok {
				retries++
				continue
			}

			addrs = append(addrs, addr)
			selectedAddrs[addr.String()] = struct{}{}
			i++
		}
	}

	return addrs, nil
}

// GetCCList returns a list of all country codes.
func (ccm *CCMap) GetCCList() []string {
	j := 0
	countryCodes := make([]string, len((*ccm)))
	for cc := range *ccm {
		countryCodes[j] = cc
		j++
	}
	sort.Strings(countryCodes)

	return countryCodes
}

func parseSubnetsCC(csvPath string, idMap map[int]string) (map[string][]*net.IPNet, error) {
	csvFile, _ := os.Open(csvPath)
	reader := csv.NewReader(bufio.NewReader(csvFile))
	subnetMap := make(map[string][]*net.IPNet, 0)

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
		// registeredCCGeoID, err := strconv.Atoi(line[2])
		// if err != nil {
		// 	log.Println(err)
		// 	continue
		// }

		if line[2] == "" {
			continue
		}
		representedCCGeoID, err := strconv.Atoi(line[2])
		if err != nil {
			log.Println(err)
			continue
		}

		cc, ok := idMap[representedCCGeoID]
		if !ok {
			continue
		}

		_, network, err := net.ParseCIDR(line[0])
		if err != nil {
			log.Println(err)
			continue
		}

		// if _, ok := subnetMap[cc]; !ok {
		// 	subnetMap[cc] = []*net.IPNet{}
		// }

		subnetMap[cc] = append(subnetMap[cc], network)
	}

	return subnetMap, nil
}

func parseIDMap(idFilePath string) (map[int]string, error) {
	csvFile, _ := os.Open(idFilePath)
	reader := csv.NewReader(bufio.NewReader(csvFile))

	idMap := make(map[int]string, 0)

	// Parse label line
	_, err := reader.Read()
	if err != nil {
		if err == io.EOF {
			return nil, fmt.Errorf("Error parsing csv file '%s': Not enough content", idFilePath)
		}
		return nil, fmt.Errorf("Error parsing csv file'%s: %s", idFilePath, err)
	}

	for {
		line, err := reader.Read()
		if err == io.EOF {
			break
		} else if err != nil {
			log.Println(err)
			continue
		}
		geoID, err := strconv.Atoi(line[0])
		if err != nil {
			log.Println(err)
			continue
		}

		cc := line[4]
		if cc != "" {
			idMap[geoID] = cc
		}
	}

	return idMap, nil
}

// CountryCodeMaps contains the CCMaps mapping country code to subnet
// allocations for both IPv4 and IPv6 subnet allocations.
type CountryCodeMaps struct {
	idMap map[int]string
	V4Map CCMap
	V6Map CCMap
}

// BuildCountryCodeMaps build the reverse map of country code to associated
// subnets for BOTH IPv4 and IPv6
func BuildCountryCodeMaps(dbPath string) (*CountryCodeMaps, error) {

	idFile := dbPath + "GeoLite2-Country-Locations-en.csv"
	idMap, err := parseIDMap(idFile)
	if err != nil {
		return nil, err
	}

	ccMap := &CountryCodeMaps{
		idMap: idMap,
	}

	// Parse V4 Subnets.
	ccMap.V4Map, err = parseSubnetsCC(dbPath+"GeoLite2-Country-Blocks-IPv4.csv", ccMap.idMap)
	if err != nil {
		return nil, err
	}

	// Parse V6 Subnets.
	ccMap.V6Map, err = parseSubnetsCC(dbPath+"GeoLite2-Country-Blocks-IPv6.csv", ccMap.idMap)
	if err != nil {
		return nil, err
	}

	return ccMap, nil
}

// GetRandomAddr4 selects an IPv4 addresses at random with from subnets
// associated with a specific country code.
func (ccm *CountryCodeMaps) GetRandomAddr4(r io.Reader, cc string) (*net.IP, error) {
	if err := ccm.V4Map.contains(cc); err != nil {
		return nil, err
	}
	return ccm.V4Map.GetRandomAddr(r, cc), nil
}

// GetRandomAddr6 selects an IPv6 addresses at random with from subnets
// associated with a specific country code.
func (ccm *CountryCodeMaps) GetRandomAddr6(r io.Reader, cc string) (*net.IP, error) {
	if err := ccm.V6Map.contains(cc); err != nil {
		return nil, err
	}
	return ccm.V6Map.GetRandomAddr(r, cc), nil
}

// GetNRandomAddr4 selects N IPv4 addresses at random with no repeats from
// subnets associated with a specific country code.
func (ccm *CountryCodeMaps) GetNRandomAddr4(r io.Reader, cc string, n int, maxRetries int) ([]*net.IP, error) {
	return ccm.V4Map.GetNRandomAddr(r, cc, n, maxRetries)
}

// GetNRandomAddr6 selects N IPv6 addresses at random with no repeats from
// subnets associated with a specific country code.
func (ccm *CountryCodeMaps) GetNRandomAddr6(r io.Reader, cc string, n int, maxRetries int) ([]*net.IP, error) {
	return ccm.V6Map.GetNRandomAddr(r, cc, n, maxRetries)
}

// GetNAddrPerAlloc4 selects N IPv4 addresses per allocation for a specific
// country code. This function allows the caller to specify an acceptance test
// function and a max number of retries should a subnet fail too often.
func (ccm *CountryCodeMaps) GetNAddrPerAlloc4(r io.Reader, cc string, n int, maxRetries int, acceptance func(*net.IP) bool) ([]*net.IP, error) {
	return ccm.V4Map.GetNAddrPerAlloc(r, cc, n, maxRetries, acceptance)
}

// GetNAddrPerAlloc6 selects N IPv4 addresses per allocation for a specific
// country code. This function allows the caller to specify an acceptance test
// function and a max number of retries should a subnet fail too often.
func (ccm *CountryCodeMaps) GetNAddrPerAlloc6(r io.Reader, cc string, n int, maxRetries int, acceptance func(*net.IP) bool) ([]*net.IP, error) {
	return ccm.V6Map.GetNAddrPerAlloc(r, cc, n, maxRetries, acceptance)
}

// GetCCList returns a list of all country codes.
func (ccm *CountryCodeMaps) GetCCList() []string {
	j := 0
	countryCodes := make([]string, len(ccm.idMap))
	for _, cc := range ccm.idMap {
		countryCodes[j] = cc
		j++
	}
	sort.Strings(countryCodes)

	return countryCodes
}
