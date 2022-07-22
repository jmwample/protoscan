package main

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTracker(t *testing.T) {
	var keyLen uint = 8
	tr := newTracker(keyLen)
	r := rand.New(rand.NewSource(1234))

	buf := make([]byte, keyLen)
	_, err := r.Read(buf)
	require.Nil(t, err)

	// values get inserted.
	tr.insert(buf, "abc")
	require.Equal(t, 1, len(tr.d))
	require.Equal(t, 1, len(tr.r))

	// inserted value is accessible by key
	v, ok := tr.get(buf)
	require.True(t, ok)
	require.Equal(t, "abc", v)

	// inserted key is accessible by value
	k, ok := tr.getKey("abc")
	require.True(t, ok)
	require.Equal(t, hex.EncodeToString(buf), k)

	// unknown key returns not ok
	bufExpected := make([]byte, keyLen)
	_, _ = r.Read(bufExpected)
	k, ok = tr.get(bufExpected)
	require.False(t, ok)
	require.Equal(t, "", k)

	// unknown value returns not ok
	k, ok = tr.getKey("xyz")
	require.False(t, ok)
	require.Equal(t, "", k)

	// test insertGenerate with guaranteed collision by re-seeding
	r.Seed(1234)
	newKey := tr.insertGenerate("def", r)
	require.NotEqual(t, "", hex.EncodeToString(newKey))
	require.NotEqual(t, hex.EncodeToString(buf), hex.EncodeToString(newKey))
	require.Equal(t, hex.EncodeToString(bufExpected), hex.EncodeToString(newKey))
	require.Equal(t, 2, len(tr.d))
	require.Equal(t, 2, len(tr.r))

	// test that calling insertGenerate on an existing value returns the
	// existing key and does not update the maps
	newKey = tr.insertGenerate("def", r)
	require.Equal(t, hex.EncodeToString(bufExpected), hex.EncodeToString(newKey))
	require.Equal(t, 2, len(tr.d))
	require.Equal(t, 2, len(tr.r))
}

// run with `-race` option to make sure that none of these operations
func TestTrackerRace(t *testing.T) {
	var keyLen uint = 8
	tr := newTracker(keyLen)
	threads := 10
	maxInsert := 10

	for i := 0; i < threads; i++ {
		var k = i
		go func() {
			r := rand.New(rand.NewSource(1234))
			for j := 0; j < maxInsert; j++ {
				val := fmt.Sprintf("%d", j*k)
				b := tr.insertGenerate(val, r)

				tr.get(b)
				tr.getKey(val)

				buf := make([]byte, keyLen)
				_, _ = r.Read(buf)
				tr.insert(buf, fmt.Sprintf("%d", j*k+1))
				tr.get(buf)
			}
		}()
	}
}
