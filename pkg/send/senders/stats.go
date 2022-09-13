package senders

import (
	"fmt"
	"sync"
)

var Stats *sendStats = &sendStats{}

type sendStats struct {
	// packets per epoch
	ppe int64
	// bytes per epoch
	bpe int64
	// packets total
	pt int64
	// bytes total
	bt int64

	mu sync.Mutex
}

func (s *sendStats) incPacketPerSec() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ppe++
	s.pt++
}

func (s *sendStats) incBytesPerSec(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bpe += int64(n)
	s.bt += int64(n)
}

func (s *sendStats) EpochReset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bpe = 0
	s.ppe = 0
}

func (s *sendStats) GetEpochStats(epochDur int64) string {
	return fmt.Sprintf("%d %d %f %f",
		Stats.pt,
		Stats.bt,
		float64(Stats.ppe)*1000/float64(epochDur),
		float64(Stats.bpe)*1000/float64(epochDur))
}
