package main

import (
	"encoding/hex"
	"math/rand"

	"github.com/jmwample/protoscan/pkg/send/keys"
)

func createDomainKeyTable(domains []string) (*keys.KeyTable, error) {
	t := keys.NewKeyTable()
	t.Generate = func(s string) (interface{}, error) {
		return int((rand.Int31() % 64535) + 1000), nil
	}

	for _, d := range domains {
		_, err := t.TryInsertGenerate(d)
		if err != nil {
			return nil, err
		}
	}

	return t, nil
}

func decodeOrPanic(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
