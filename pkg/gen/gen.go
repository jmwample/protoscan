package gen

import (
	"bufio"
	"errors"
	"io"
	"net"
	"os"
)

var (
	// ErrNoSubnets is returned when an operation attempts to access a CCMap
	// with no subnets associated wth the provided CC.
	ErrNoSubnets = errors.New("no subnets available")

	// ErrTooManyRetries is returned when a GenerateN addresses function is called
	// with an acceptance test that fails too many times.
	ErrTooManyRetries = errors.New("encountered too many retries with acceptance check")
)

// RandomAddr uses the provided random reader to select a random address
// from a provided subnet.
func RandomAddr(rdr io.Reader, subnet *net.IPNet) *net.IP {
	var addr net.IP

	bytes := []byte{}
	r := make([]byte, len(subnet.Mask))
	_, err := rdr.Read(r)
	if err != nil {
		return nil
	}
	for i, b := range subnet.Mask {
		addrByte := (subnet.IP[i] & b) | (^b & r[i])
		bytes = append(bytes, addrByte)
	}
	addr = net.IP(bytes)
	return &addr
}

// ParseRespongindAddrs parses a file with one address per line of addresses and
// returns a "hash set" so that packages can check for inclusion. If no file
// path is provided an empty hash set is returned. However, if a file path is
// provided, but errs on open or read, the error will be returned
func ParseRespongindAddrs(fPath string) (map[string]struct{}, error) {
	respondingAddrs := make(map[string]struct{})

	if fPath == "" {
		return respondingAddrs, nil
	}

	inFile, err := os.Open(fPath)
	if err != nil {
		return nil, err
	}
	defer inFile.Close()

	scanner := bufio.NewScanner(inFile)
	for scanner.Scan() {
		respondingAddrs[scanner.Text()] = struct{}{}
	}

	if err = scanner.Err(); err != nil {
		return nil, err
	}

	return respondingAddrs, nil
}
