package gen

import (
	"math/rand"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRandAddr(t *testing.T) {
	rdr := rand.New(rand.NewSource(int64(12345)))

	_, network, err := net.ParseCIDR("10.0.0.1/16")
	require.Nil(t, err)

	addr := RandomAddr(rdr, network)
	t.Log(addr)

	_, network, err = net.ParseCIDR("2001::1/64")
	require.Nil(t, err)

	addr = RandomAddr(rdr, network)
	t.Log(addr)
}
