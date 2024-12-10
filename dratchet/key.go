package dratchet

import (
	"fmt"
)

type Key []byte

type KeysStorage interface {
	Get(k Key, msgNum uint) (mk Key, ok bool, err error)

	Save(k Key, msgNum uint, mk Key) error

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

func (ks *KeysStorageInMemory) Save(pubKey Key, msgNum uint, mk Key) error {
	index := fmt.Sprintf("%x", pubKey)

	if ks.keys == nil {
		ks.keys = make(map[string]map[uint]Key)
	}
	if _, ok := ks.keys[index]; !ok {
		ks.keys[index] = make(map[uint]Key)
	}
	ks.keys[index][msgNum] = mk
	return nil
}

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
