package gen

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRandAddr(t *testing.T) {
	_, network, err := net.ParseCIDR("10.0.0.1/16")
	require.Nil(t, err)

	addr := randomAddr(network)
	t.Log(addr)

	_, network, err = net.ParseCIDR("2001::1/64")
	require.Nil(t, err)

	addr = randomAddr(network)
	t.Log(addr)
}
