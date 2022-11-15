package rate

import (
	"errors"
	"strconv"
	"sync/atomic"
	"time"
)

type test interface{}

// -> In -> check{} -> Out ->
type limiter[T test] struct {
	in     <-chan T
	out    chan<- T
	ticker *time.Ticker
	count  int64
	max    int64
	countf func(T) int64
}

// CountLimit is a basic number of messages per second limiter
func CountLimit[T any](r string, in <-chan T, out chan<- T) error {
	Limit[T](r, in, out, nil)
	return nil
}

// BPSLimit is a basic number of messages per second limiter
func BPSLimit(r string, in <-chan []byte, out chan<- []byte) error {
	return Limit[[]byte](
		r,
		in,
		out,
		func(m []byte) int64 {
			return int64(len(m))
		},
	)
}

// Limit places a rate limit on transmission of generic elements between two channels. if `max <= 0`
// or `duration == 0` it will run with no limit copying directly between the input and output
// channels.
//
// Stops on input close. If out is closed first it will block.
func Limit[T any](r string, in <-chan T, out chan<- T, count func(T) int64) error {

	max, dur, err := ParseLimit(r)
	if err != nil {
		return err
	}

	LimitExplicit[T](max, dur, in, out, count)
	return nil
}

// LimitExplicit places a rate limit on transmission of generic elements between two channels. if `max <= 0`
// or `duration == 0` it will run with no limit copying directly between the input and output
// channels.
//
// Stops on input close. If out is closed first it will block.
func LimitExplicit[T any](max int64, d time.Duration, in <-chan T, out chan<- T, count func(T) int64) {

	c := &limiter[T]{
		in:     in,
		out:    out,
		count:  0,
		max:    max,
		countf: count,
	}

	if max <= 0 || d == 0 {
		// if no limit or duration was specified run with no limit
		go c.runUnlimited()
		return
	}

	c.ticker = time.NewTicker(d)
	c.max = max

	go c.run()
}

// runUnlimited copies elements straight from in to out with no delay. Used when no limit or
// duration was specified. Closes when in is closed. If out is closed first this will block.
func (c *limiter[T]) runUnlimited() {
	for elem := range c.in {
		c.out <- elem
	}
}

// run copies elements straight from in to out with structured delays.  Closes when in is closed. If
// out is closed first this will block.
func (c *limiter[T]) run() {
	var n int64 = 1

	for {
		select {
		case <-c.ticker.C:
			atomic.StoreInt64(&c.count, 0)

		default:
			// log.Println("default: ", c.count, c.max)
			if c.count >= c.max {
				// prevent busy wait if we go over max in a period.
				<-c.ticker.C
				atomic.StoreInt64(&c.count, 0)
			}

			elem, ok := <-c.in
			if !ok {
				// if the send channel was closed we exit
				return
			}

			n = 1
			if c.countf != nil {
				n = c.countf(elem)
			}

			c.out <- elem
			atomic.AddInt64(&c.count, n)

		}
	}
}

var humanReadableSuffixes = map[byte]int{
	'k': 1 << 10,
	'M': 1 << 20,
	'G': 1 << 30,
}

// ErrUnparsableLimit is returned when a bad string limit is provided
var ErrUnparsableLimit = errors.New("unable to parse provided limit string")

// ParseLimit takes a human readable limit with suffixes like k, M, G and returns
// a reasonable limit and duration for a Limiter
func ParseLimit(s string) (int64, time.Duration, error) {

	if s == "" {
		return 0, 0, nil
	}

	shift, ok := humanReadableSuffixes[s[len(s)-1]]
	if !ok {
		// No human readable suffix found
		value, err := strconv.ParseFloat(s, 64)
		if err == nil {
			return int64(value), 1 * time.Second, nil
		}
	} else {
		if val, err := strconv.ParseFloat(s[:len(s)-1], 64); err == nil {
			return int64(val * float64(shift)), 1 * time.Second, nil
		}

	}
	return 0, 0, ErrUnparsableLimit
}
