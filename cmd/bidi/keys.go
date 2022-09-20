package main

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

// KeyTable is intended to be used as a way to map elements sent in outgoing
// probes to features that will be returned in response packets.
//
// For example. The TLS probe sends a domain in the SNI field, but responses
// send a TCP reset. We need to be able to tie the TCP reset packet to the
// domain name that was used. We do this by mapping each domain to a unique
// port.
//
// We want:
//   - to do forward and reverse lookups so that it is easy (no loops) to lookup
//     for example the domain given the port (i.e. when we receive a reset), or
//     the port given the domain (i.e. when we are crafting the packet).
//   - to make sure there are no collisions. No duplicate ports, no duplicate
//     domains.
//   - to access this structure using many goroutines in parallel without race
//     condition issues.
//   - to be able to dump this structure into logs if necessary
//
// Note - because we use maps the value types must be hashable - i.e. no []byte
type KeyTable struct {
	m sync.Mutex

	generate func(string) (interface{}, error)

	// forward
	F map[string]interface{} `json:"fwd"`
	// reverse
	R map[interface{}]string `json:"rev"`
}

func newKeyTable() *KeyTable {
	t := &KeyTable{
		F: make(map[string]interface{}),
		R: make(map[interface{}]string),
	}

	return t
}

func (t *KeyTable) get(key string) (interface{}, bool) {
	t.m.Lock()
	defer t.m.Unlock()

	s, ok := t.F[key]
	return s, ok
}

func (t *KeyTable) getKey(v interface{}) (string, bool) {
	t.m.Lock()
	defer t.m.Unlock()

	k, ok := t.R[v]
	return k, ok
}

func (t *KeyTable) insert(key string, v interface{}) {
	t.m.Lock()
	defer t.m.Unlock()

	t.F[key] = v
	t.R[v] = key
}

func (t *KeyTable) tryInsertGenerate(key string) (v interface{}, err error) {
	t.m.Lock()
	defer t.m.Unlock()

	// if the string value already has a value return that value
	if v, ok := t.F[key]; ok {
		return v, nil
	}

	if t.generate == nil {
		return nil, fmt.Errorf("no generate function provided")
	}

	// Generate a new unused value for the string value
	ok := true
	for {
		v, err = t.generate(key)
		if err != nil {
			return nil, err
		}
		// check if generated value collides with existing value
		_, ok = t.R[v]
		if !ok {
			// no collision = we found a gook value
			break
		}
	}
	t.F[key] = v
	t.R[v] = key

	return
}

// Marshal and json.Marshal(*KeyTable) only work for objects that can be
// converted to int because that is all I need for now.
func (t *KeyTable) marshal(w io.Writer) error {
	b, err := json.Marshal(t)
	if err != nil {
		return err
	}

	_, err = w.Write(b)
	return err
}

func (t *KeyTable) MarshalJSON() ([]byte, error) {
	m := struct {
		F map[string]int
		R map[int]string
	}{
		F: make(map[string]int),
		R: make(map[int]string),
	}

	for k, v := range t.F {
		m.F[k] = v.(int)
		m.R[v.(int)] = k
	}
	return json.Marshal(m)
}
