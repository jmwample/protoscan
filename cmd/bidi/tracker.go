package main

import (
	"encoding/hex"
	"math/rand"
	"sync"
)

// tracker provides a structure for tracking keys - random bytes used in packet
// fields - alongside the domains that they match. This way when we receive
// injected responses that contain traces of the random values we can determine
// which domain is the one receiving the injection.
//
// This structure must be thread safe for both insertion and access because
// there will be many goroutines accessing and inserting values in parallel.
type tracker struct {
	m sync.Mutex

	keyLen uint

	d map[string]string
	r map[string]string
}

func newTracker(size uint) *tracker {
	t := &tracker{
		keyLen: size,
		d:      make(map[string]string),
		r:      make(map[string]string),
	}

	return t
}

func (t *tracker) get(key []byte) (string, bool) {
	t.m.Lock()
	defer t.m.Unlock()

	s, ok := t.d[hex.EncodeToString(key)]
	return s, ok
}

func (t *tracker) getKey(s string) (string, bool) {
	t.m.Lock()
	defer t.m.Unlock()

	k, ok := t.r[s]
	return k, ok
}

func (t *tracker) insert(b []byte, s string) {
	t.m.Lock()
	defer t.m.Unlock()

	key := hex.EncodeToString(b)
	t.d[key] = s
	t.r[s] = key
}

// insertGenerate generates a key that is not yet in the tracker for the
// inserting string value if the randomness generator throws an error or fails
// the read it will return an empty array of bytes. otherwise it returns the
// bytes new key.
//
// The keyLen field of the tracker struct must be set for this fn to work.
func (t *tracker) insertGenerate(s string, r *rand.Rand) []byte {
	t.m.Lock()
	defer t.m.Unlock()

	// if the string value already has a key return that key
	if k, ok := t.r[s]; ok {
		b, _ := hex.DecodeString(k)
		return b
	}

	// Generate a new unused key for the string value
	ok := true
	buf := make([]byte, t.keyLen)
	for {
		n, err := r.Read(buf)
		if err != nil || n != int(t.keyLen) {
			return []byte{}
		}
		// check if generated key collides with existing key
		_, ok = t.d[hex.EncodeToString(buf)]
		if !ok {
			break
		}
	}

	key := hex.EncodeToString(buf)
	t.d[key] = s
	t.r[s] = key
	return buf
}
