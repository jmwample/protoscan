package main

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTLSLen(t *testing.T) {

	b, _ := hex.DecodeString("6578616d706c652e756c666865696d2e6e6574")
	require.Equal(t, 19, len(b))
	require.Equal(t, "0013", fmt.Sprintf("%04x", len(b)))
}

func TestTLSPayload(t *testing.T) {
	p := &tlsProber{
		seed: 01234,
		r:    rand.New(rand.NewSource(1234)),
	}

	expected := "16030100f8010000f40303c00e5d67c2755389aded7d8b151cbd5bcdf7ed275ad5e028b664880fc7581c7720547deaf77620043495b358675999c4b7338ff339566349ed0ef6384876655d1b000813021303130100ff010000a30000001800160000136578616d706c652e756c666865696d2e6e6574000b000403000102000a00160014001d0017001e0019001801000101010201030104002300000016000000170000000d001e001c040305030603080708080809080a080b080408050806040105010601002b0003020304002d00020101003300260024001d0020358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254"

	hostname := "example.ulfheim.net"
	payload, err := p.buildPayload(hostname)
	require.Nil(t, err)
	require.Equal(t, expected, hex.EncodeToString(payload))
}
