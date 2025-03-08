package track

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

var keyLen = 8

func TestKeyTable(t *testing.T) {
	rand.Seed(1234)

	tr := newKeyTable()
	tr.generate = func(s string) (interface{}, error) {
		return rand.Int63(), nil
	}

	val := rand.Int63()

	// values get inserted.
	tr.Insert("abc", val)
	require.Equal(t, 1, len(tr.F))
	require.Equal(t, 1, len(tr.R))

	// inserted value is accessible by key
	v, ok := tr.Get("abc")
	require.True(t, ok)
	require.Equal(t, val, v.(int64))

	// inserted key is accessible by value
	k, ok := tr.GetKey(val)
	require.True(t, ok)
	require.Equal(t, "abc", k)

	// unknown key returns not ok
	v, ok = tr.Get("xyz")
	require.False(t, ok)
	require.Nil(t, v)

	// unknown value returns not ok
	expected := rand.Int63()
	k, ok = tr.GetKey(expected)
	require.False(t, ok)
	require.Equal(t, "", k)

	// test TryInsertGenerate with guaranteed collision by re-seeding
	rand.Seed(1234)
	v, err := tr.TryInsertGenerate("def")
	newVal := v.(int64)
	require.Nil(t, err)
	require.NotEqual(t, "", newVal)
	require.NotEqual(t, val, newVal)
	require.Equal(t, expected, newVal)
	require.Equal(t, 2, len(tr.F))
	require.Equal(t, 2, len(tr.R))

	// test that calling TryInsertGenerate on an existing value returns the
	// existing key and does not update the maps
	v, err = tr.TryInsertGenerate("def")
	newVal = v.(int64)
	require.Nil(t, err)
	require.Equal(t, expected, newVal)
	require.Equal(t, 2, len(tr.F))
	require.Equal(t, 2, len(tr.R))
}

// run with `-race` option to make sure that none of these operations
func TestKeyTableRace(t *testing.T) {
	tr := newKeyTable()
	tr.generate = func(s string) (interface{}, error) {
		return rand.Int63(), nil
	}

	threads := 10
	maxInsert := 10

	for i := 0; i < threads; i++ {
		var k = i
		go func() {
			rand.Seed(1234)
			for j := 0; j < maxInsert; j++ {
				key := fmt.Sprintf("%d", j*k)
				v, _ := tr.TryInsertGenerate(key)

				tr.Get(key)
				tr.GetKey(v)

				val := rand.Int63()
				key = fmt.Sprintf("%d", j*k+1)
				tr.Insert(key, val)

				tr.Get(key)
				tr.GetKey(val)
			}
		}()
	}
}

// TODO: problem for future jmwample
func TestKeyTableDump(t *testing.T) {
	tr := newKeyTable()
	tr.generate = func(s string) (interface{}, error) {
		return rand.Int63(), nil
	}
	tr.Insert("a", 1)
	tr.Insert("b", 2)

	var buf bytes.Buffer
	err := tr.Marshal(&buf)
	require.Nil(t, err)
	t.Logf("%s", buf.String())
}
