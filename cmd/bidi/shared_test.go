package main

import (
	"encoding/hex"
	"hash/crc32"
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/require"
)

// This test does weird things when the host machine has virtualbox interfaces
// (e.g. vboxnet0) on the host. It throws some error about the device being out
// of order. otherwise test should pass.
func TestRoutingBasic(t *testing.T) {
	localIface, err := net.InterfaceByName("lo")
	require.Nil(t, err)

	ip, err := getSrcIP(localIface, "127.0.0.1", net.ParseIP("127.0.0.1"))
	require.Nil(t, err)
	require.Equal(t, "127.0.0.1", ip.String())

	ip, err = getSrcIP(localIface, "::1", net.ParseIP("::1"))
	require.Nil(t, err)
	require.Equal(t, "::1", ip.String())
}

func TestRoutingMixedPreferred(t *testing.T) {
	localIface, err := net.InterfaceByName("lo")
	require.Nil(t, err)

	ip, err := getSrcIP(localIface, "127.0.0.1", net.ParseIP("::1"))
	require.Nil(t, err)
	require.Equal(t, "::1", ip.String())

	ip, err = getSrcIP(localIface, "::1", net.ParseIP("127.0.0.1"))
	require.Nil(t, err)
	require.Equal(t, "127.0.0.1", ip.String())
}

func TestRandSeed(t *testing.T) {
	buf0 := make([]byte, 8)
	n, err := rand.Read(buf0)
	require.Nil(t, err)
	require.Equal(t, 8, n)

	buf1 := make([]byte, 8)
	rand.Seed(int64(time.Now().Nanosecond()))
	n, err = rand.Read(buf1)
	require.Nil(t, err)
	require.Equal(t, 8, n)

	buf2 := make([]byte, 8)
	rand.Seed(int64(time.Now().Nanosecond()))
	n, err = rand.Read(buf2)
	require.Nil(t, err)
	require.Equal(t, 8, n)

	wg := new(sync.WaitGroup)
	wg.Add(1)

	buf3 := make([]byte, 8)
	go func() {
		n, err = rand.Read(buf3)
		require.Nil(t, err)
		require.Equal(t, 8, n)
		wg.Done()
	}()

	wg.Wait()

	require.NotEqual(t, hex.EncodeToString(buf0), hex.EncodeToString(buf1))
	require.NotEqual(t, hex.EncodeToString(buf0), hex.EncodeToString(buf2))
	require.NotEqual(t, hex.EncodeToString(buf0), hex.EncodeToString(buf3))
	require.NotEqual(t, hex.EncodeToString(buf1), hex.EncodeToString(buf2))
	require.NotEqual(t, hex.EncodeToString(buf1), hex.EncodeToString(buf3))
	require.NotEqual(t, hex.EncodeToString(buf2), hex.EncodeToString(buf3))
	// t.Logf("\n%s\n%s\n%s\n%s", hex.EncodeToString(buf0), hex.EncodeToString(buf1), hex.EncodeToString(buf2), hex.EncodeToString(buf3))
}

func TestTCPTagValidate(t *testing.T) {
	ip := net.ParseIP("127.0.0.1")
	sport := 1234
	// name := "a.example.com"

	ipByteSlice := (*[4]byte)(unsafe.Pointer(&sport))[:] // sport to []byte
	ipByteSlice = append(ipByteSlice, ip.To16()...)      // append ip bytes

	ack := crc32.ChecksumIEEE(ipByteSlice)

	require.Equal(t, "d204000000000000000000000000ffff7f000001", hex.EncodeToString(ipByteSlice))
	require.Equal(t, uint32(4165421024), ack)

	// log.Println(hex.EncodeToString(ipByteSlice))
	// log.Println(ip.String(), []byte(ip.To16()), sport, ack)

	/*
		$ python
		>>> import zlib
		>>> zlib.crc32(bytes.fromhex("d204000000000000000000000000ffff7f000001"))
		4165421024
	*/
}

func TestTCPTagValidateWithSeq(t *testing.T) {
	rand.Seed(1234)
	seq := rand.Uint32()
	ip := net.ParseIP("127.0.0.1")
	sport := 1234
	// name := "a.example.com"

	ipByteSlice := (*[4]byte)(unsafe.Pointer(&sport))[:]                      // sport to []byte
	ipByteSlice = append(ipByteSlice, ip.To16()...)                           // append ip bytes
	ipByteSlice = append(ipByteSlice, (*[4]byte)(unsafe.Pointer(&seq))[:]...) // append seq as []byte

	ack := crc32.ChecksumIEEE(ipByteSlice)

	require.Equal(t, "d204000000000000000000000000ffff7f00000184eba638", hex.EncodeToString(ipByteSlice))
	require.Equal(t, uint32(2573409105), ack)

	// log.Println(hex.EncodeToString(ipByteSlice))
	// log.Println(seq, ip.String(), []byte(ip.To16()), sport, ack)

	/*
		$ python
		>>> import zlib
		>>> zlib.crc32(bytes.fromhex("d204000000000000000000000000ffff7f00000184eba638"))
		2573409105
	*/
}

func TestQuicTagValidate(t *testing.T) {
	
}