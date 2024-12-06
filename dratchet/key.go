package dratchet

import (
	"fmt"
)

type Key []byte

// in-memory or persistent keys storage.
type KeysStorage interface {
	// Returns a message key by the given key and message number.
	Get(k Key, msgNum uint) (mk Key, ok bool, err error)

	// Saves the given mk under the specified key and msgNum.
	Save(k Key, msgNum uint, mk Key) error

	// ensures there's no message key under the specified key and msgNum.
	Delete(k Key, msgNum uint) error
}

type KeysStorageInMemory struct {
	keys map[string]map[uint]Key
}

func (ks *KeysStorageInMemory) Get(pubKey Key, msgNum uint) (Key, bool, error) {
	index := fmt.Sprintf("%x", pubKey)
	if ks.keys == nil {
		return Key{}, false, nil
	}
	msgs, ok := ks.keys[index]
	if !ok {
		return Key{}, false, nil
	}
	mk, ok := msgs[msgNum]
	if !ok {
		return Key{}, false, nil
	}
	return mk, true, nil
}

// Save saves the given mk under the specified key and msgNum.
func (s *KeysStorageInMemory) Save(pubKey Key, msgNum uint, mk Key) error {
	index := fmt.Sprintf("%x", pubKey)

	if s.keys == nil {
		s.keys = make(map[string]map[uint]Key)
	}
	if _, ok := s.keys[index]; !ok {
		s.keys[index] = make(map[uint]Key)
	}
	s.keys[index][msgNum] = mk
	return nil
}

// DeleteMk ensures there's no message key under the specified key and msgNum.
func (s *KeysStorageInMemory) Delete(pubKey Key, msgNum uint) error {
	index := fmt.Sprintf("%x", pubKey)

	if s.keys == nil {
		return nil
	}
	if _, ok := s.keys[index]; !ok {
		return nil
	}
	if _, ok := s.keys[index][msgNum]; !ok {
		return nil
	}
	delete(s.keys[index], msgNum)
	if len(s.keys[index]) == 0 {
		delete(s.keys, index)
	}
	return nil
}
