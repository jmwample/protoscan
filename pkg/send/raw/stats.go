package raw

import (
	"log"
	"math"
	"sync"
	"sync/atomic"
	"time"
)

type sendStats struct {
	start      time.Time
	epochStart time.Time

	// packets per epoch
	ppe int64
	// bytes per epoch
	bpe int64
	// errors per epoch
	epe int64
	// packets total
	pt int64
	// bytes total
	bt int64
	// errors total
	et int64

	mu sync.Mutex
}

func newStats() *sendStats {
	return &sendStats{
		start:      time.Now(),
		epochStart: time.Now(),
	}
}

func (s *sendStats) incPacketPerSec() {
	s.mu.Lock()
	defer s.mu.Unlock()
	atomic.AddInt64(&s.ppe, 1)
	atomic.AddInt64(&s.pt, 1)
}

func (s *sendStats) incErrPerSec() {
	s.mu.Lock()
	defer s.mu.Unlock()
	atomic.AddInt64(&s.epe, 1)
	atomic.AddInt64(&s.et, 1)
}

func (s *sendStats) incBytesPerSec(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	atomic.AddInt64(&s.bpe, int64(n))
	atomic.AddInt64(&s.bt, int64(n))
}

func (s *sendStats) epochReset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	atomic.StoreInt64(&s.bpe, 0)
	atomic.StoreInt64(&s.ppe, 0)
	atomic.StoreInt64(&s.epe, 0)

	s.epochStart = time.Now()
}

// PrintAndReset prints stats and starts a new epoch for tracking.
func (s *sendStats) PrintAndReset() {
	var epochDur float64 = math.Max(float64(time.Since(s.epochStart).Milliseconds()), 1)
	var totalDur float64 = math.Max(float64(time.Since(s.start).Milliseconds()), 1)

	log.Printf("stats %f %f %d %d %d %.3f %.3f %.3f",
		totalDur,
		epochDur,
		s.pt,
		s.bt,
		s.et,
		float64(s.ppe)*1000/epochDur,
		float64(s.bpe)*1000/epochDur,
		float64(s.epe)*1000/epochDur)

	s.epochReset()
}
