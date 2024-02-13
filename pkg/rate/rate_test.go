package rate

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRateParse(t *testing.T) {

	testCases := []struct {
		input string
		lim   int64
		dur   time.Duration
		err   error
	}{
		{input: "abcd", lim: 0, dur: 0, err: ErrUnparsableLimit},
		{input: "20", lim: 20, dur: 1 * time.Second, err: nil},
		{input: "200.0", lim: 200, dur: 1 * time.Second, err: nil},
		{input: "10.5", lim: 10, dur: 1 * time.Second, err: nil},
		{input: "2k", lim: 2048, dur: 1 * time.Second, err: nil},
		{input: "4M", lim: 1 << 22, dur: 1 * time.Second, err: nil},
		{input: "8G", lim: 1 << 33, dur: 1 * time.Second, err: nil},
		{input: "1.5G", lim: 1.5 * (1 << 30), dur: 1 * time.Second, err: nil},
		{input: "", lim: 0, dur: 0, err: nil},
	}

	for _, c := range testCases {
		lim, dur, err := ParseLimit(c.input)
		require.Equal(t, c.lim, lim)
		require.Equal(t, c.dur, dur)
		require.Equal(t, c.err, err)
	}
}

// Test that a limiter that starts with a surplus of messages will limit the number written. Note
// that the limiter is somewhat burst-y as both of the available slots are filled at the very start
// of the available time. Also the receiver channel blocks until a new message is available (i.e
// next time the ticker is available to write).
func TestRateLimiterCountRecv(t *testing.T) {

	in := make(chan int, 5)
	out := make(chan int)
	defer close(in)

	CountLimit[int]("2", in, out)

	go func() {
		for i := 0; i < 10; i++ {
			in <- i
		}
	}()

	start := time.Now()
	for j := 0; j < 3; j++ {
		<-out
	}

	require.GreaterOrEqual(t, time.Since(start), 990*time.Millisecond)
	require.Less(t, time.Since(start), 1100*time.Millisecond)

	<-out
	require.GreaterOrEqual(t, time.Since(start), 990*time.Millisecond)
	require.Less(t, time.Since(start), 1100*time.Millisecond)

	<-out
	require.GreaterOrEqual(t, time.Since(start), 1990*time.Millisecond)
	require.Less(t, time.Since(start), 2100*time.Millisecond)
}

// Test that a limiter that starts with a surplus of receive capacity does not exceed the specified
// transmission rate. The sender channel blocks until a new bucket is available (i.e next time the
// ticker is available to write) even though the out channel could buffer more elements.
func TestRateLimiterCountSend(t *testing.T) {

	in := make(chan int)
	out := make(chan int, 4)
	defer close(in)

	CountLimit[int]("2", in, out)

	go func() {
		// Wait to start emptying buffer
		time.Sleep(4 * time.Second)
		for i := 0; i < 10; i++ {
			<-out
		}
	}()

	start := time.Now()
	for j := 0; j < 3; j++ {
		in <- j
	}

	require.GreaterOrEqual(t, time.Since(start), 990*time.Millisecond)
	require.Less(t, time.Since(start), 1100*time.Millisecond)

	in <- 0
	require.GreaterOrEqual(t, time.Since(start), 990*time.Millisecond)
	require.Less(t, time.Since(start), 1100*time.Millisecond)

	in <- 0
	require.GreaterOrEqual(t, time.Since(start), 1990*time.Millisecond)
	require.Less(t, time.Since(start), 2100*time.Millisecond)

	// the channel buffer should be full by the time we reach this send, so we block until the recv
	// channel wakes up and empties its buffer. Otherwise it would write another element during the
	// previous two time periods (2 or 3 seconds in)
	in <- 0
	require.GreaterOrEqual(t, time.Since(start), 3990*time.Millisecond)
	require.Less(t, time.Since(start), 4100*time.Millisecond)
}

// TestRateLimiterBPS demonstrates using a bytes-per-second limiter. Since messages can be longer
// than the max bytes this makes for an inaccurate limiter. It accumulates until the number of bytes
// sent in the current epoch is above the max, but sends messages whole, so if only one message is
// sent each epoch, but the message is significantly larger than the max the BPS will can be higher
// than the limiter should allow.
//
// This demonstrates that you should use a max bytes larger (as much as possible) than your max
// message size. If all messages are going to be larger than you max bps increase the epoch duration
// and raise the max size.
func TestRateLimiterBPS(t *testing.T) {
	longString := "this is an example long string that we can pull ~arbitrary short strings from"

	in := make(chan []byte)
	out := make(chan []byte)

	err := BPSLimit("2", in, out)
	require.Nil(t, err)

	start := time.Now()
	go func() {
		for i := 1; i < 5; i++ {
			s := []byte(longString[:i])
			in <- s
			// t.Logf("%s sent: %s", time.Since(start), s)
		}

		in <- []byte(longString)
	}()

	for j := 0; j < 3; j++ {
		<-out //1, 2  - epoch 0     // 3 - epoch 1
	}

	require.GreaterOrEqual(t, time.Since(start), 990*time.Millisecond)
	require.Less(t, time.Since(start), 1110*time.Millisecond)

	<-out // 3 - epoch 2
	require.GreaterOrEqual(t, time.Since(start), 1900*time.Millisecond)
	require.Less(t, time.Since(start), 2100*time.Millisecond)

	<-out // 4 - epoch 3
	require.GreaterOrEqual(t, time.Since(start), 2990*time.Millisecond)
	require.Less(t, time.Since(start), 3100*time.Millisecond)
}

func TestRateLimiterUnlimited(t *testing.T) {
	in := make(chan int)
	out := make(chan int)
	N := 100

	CountLimit[int]("", in, out)

	go func() {
		for i := 0; i < N; i++ {
			in <- i
		}
	}()

	start := time.Now()
	for j := 0; j < N; j++ {
		<-out
	}

	require.Less(t, time.Since(start), 1*time.Millisecond)
}
