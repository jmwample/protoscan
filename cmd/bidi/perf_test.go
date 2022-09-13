package main

import (
	"math/rand"
	"net"
	"testing"
	"time"

	"github.com/jmwample/protoscan/pkg/send/probes/dns"
	"github.com/jmwample/protoscan/pkg/send/probes/http"
	"github.com/jmwample/protoscan/pkg/send/probes/tls"
	"github.com/jmwample/protoscan/pkg/send/senders/tcp"
	// "github.com/jmwample/protoscan/pkg/send/probes/quic"
)

func Benchmark_GeneratePayloads(b *testing.B) {
	pt := &tls.Prober{}
	ph := &http.Prober{}
	// pq := &quicProber{}
	pd := &dns.Prober{}
	for n := 0; n < b.N; n++ {
		pt.BuildPayload("test.com")
		ph.BuildPayload("test.com")
		// pq.BuildPayload("test.com")
		pd.BuildPayload("test.com")
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

The calls to TLS / HTTP BuildPayload are not what is causing the low pps output.
*/

func Benchmark_SendProbes(b *testing.B) {
	rand.Seed(int64(time.Now().Nanosecond()))
	t, err := tcp.NewSender("wlo1", "", "", false, 0*time.Second, true)
	if err != nil {
		panic(err)
	}
	pt := &tls.Prober{
		Sender: t,
	}
	pd := &dns.Prober{}
	for n := 0; n < b.N; n++ {
		err := pt.SendProbe(net.ParseIP("192.12.240.40"), "test.com", true)
		if err != nil {
			b.Log("tls", err)
		}
		err = pd.SendProbe(net.ParseIP("192.12.240.40"), "test.com", true)
		if err != nil {
			b.Log("dns", err)
		}
	}
}

/*
Takeaways:
- Using getSrc for every probe sent is a TERRIBLE idea. Move that to its own thing.
*/
