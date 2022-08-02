package main

import (
	"math/rand"
	"net"
	"testing"
	"time"
)

func Benchmark_GeneratePayloads(b *testing.B) {
	pt := &tlsProber{}
	ph := &httpProber{}
	// pq := &quicProber{}
	pd := &dnsProber{}
	for n := 0; n < b.N; n++ {
		pt.buildPayload("test.com")
		ph.buildPayload("test.com")
		// pq.buildPayload("test.com")
		pd.buildPayload("test.com")
	}
}

/*
Takeaways:
- lots (~30%) of TLS payload build time is spent on hex.Decode which is
  avoidable
    - generating payload is really fast anyways and this is a really convenient
      way to interact with things. Might make sense to do this as some sort of
      init if we really care. Or move to using slice init with bytes. But for
      now it doesn't matter.
- Quic build is comparatively WAY SLOWER than the others because of the
  encryption
- DNS is a little slow (slower than TLS) because miekg/dns uses crypto/rand
  which blocks for randomness which we probably don't need
    - Fixed

The calls to TLS / HTTP buildPayload are not what is causing the low pps output.
*/

func Benchmark_SendProbes(b *testing.B) {
	rand.Seed(int64(time.Now().Nanosecond()))
	t, err := newTCPSender("wlo1", "", "", false, 0*time.Second, true)
	if err != nil {
		panic(err)
	}
	pt := &tlsProber{
		sender: t,
	}
	pd := &dnsProber{}
	for n := 0; n < b.N; n++ {
		err := pt.sendProbe(net.ParseIP("192.12.240.40"), "test.com", true)
		if err != nil {
			b.Log("tls", err)
		}
		err = pd.sendProbe(net.ParseIP("192.12.240.40"), "test.com", true)
		if err != nil {
			b.Log("dns", err)
		}
	}
}

/*
Takeaways:
- Using getSrc for every probe sent is a TERRIBLE idea. Move that to its own thing.
*/
