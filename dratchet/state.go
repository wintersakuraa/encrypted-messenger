package dratchet

import (
	"fmt"
)

// The double ratchet state.
type State struct {
	// DH Ratchet key pair (the "sending" or "self" ratchet key)
	DHs DHPair

	// DH Ratchet public key (the "received" or "remote" key)
	DHr Key

	// 32-byte Root Key
	RK Key

	// 32-byte Chain Keys for sending and receiving
	CKs, CKr Key

	// Message numbers for sending and receiving
	Ns, Nr uint32

	// Number of messages in previous sending chain.
	PN uint32

	// Dictionary of skipped-over message keys, indexed by ratchet public key or header key
	// and message number.
	MkSkipped KeysStorage

	// The maximum number of message keys that can be skipped in a single chain.
	// WithMaxSkip should be set high enough to tolerate routine lost or delayed messages,
	// but low enough that a malicious sender can't trigger excessive recipient computation.
	MaxSkip uint

	// Receiving header key and next header key. Only used for header encryption.
	// HKr, NHKr Key

	// Sending header key and next header key. Only used for header encryption.
	// HKs, NHKs Key
}

func RatchetInitBob(sk Key, keyPair DHPair) (*State, error) {
	state, err := newState(sk)
	if err != nil {
		return nil, err
	}

	state.DHs = keyPair

	return state, nil
}

func RatchetInitAlice(sk, dhPubKey Key) (*State, error) {
	state, err := newState(sk)
	if err != nil {
		return nil, err
	}

	state.DHs, err = GenerateDH()
	if err != nil {
		return nil, fmt.Errorf("can't generate key pair: %s", err)
	}

	state.DHr = dhPubKey
	secret, err := DH(state.DHs, state.DHr)
	if err != nil {
		return nil, fmt.Errorf("can't generate dh secret: %s", err)
	}

	// state.RK, state.CKs, state.NHKs = KdfRK(sk, secret)
	state.RK, state.CKs, _ = KdfRK(sk, secret)

	return state, nil
}

func newState(sk Key) (*State, error) {
	if sk == nil {
		return nil, fmt.Errorf("empty shared key")
	}

	return &State{
		DHs:       dhPair{},
		RK:        sk,
		MkSkipped: &KeysStorageInMemory{},
		MaxSkip:   1000,
	}, nil
}

// single ratchet step.
func (s *State) dhRatchet(h Header) error {
	s.PN = s.Ns
	s.Ns = 0
	s.Nr = 0
	s.DHr = h.DH

	recvSecret, err := DH(s.DHs, s.DHr)
	if err != nil {
		return fmt.Errorf("failed to generate dh recieve ratchet secret: %s", err)
	}

	// s.RK, s.CKr, s.NHKr = KdfRK(s.RK, recvSecret)
	s.RK, s.CKr, _ = KdfRK(s.RK, recvSecret)

	s.DHs, err = GenerateDH()
	if err != nil {
		return fmt.Errorf("failed to generate dh pair: %s", err)
	}

	sendSecret, err := DH(s.DHs, s.DHr)
	if err != nil {
		return fmt.Errorf("failed to generate dh send ratchet secret: %s", err)
	}

	// s.RK, s.CKs, s.NHKs = KdfRK(s.RK, sendSecret)
	s.RK, s.CKs, _ = KdfRK(s.RK, sendSecret)

	return nil
}

type skippedKey struct {
	key Key
	nr  uint
	mk  Key
	seq uint
}

// Skip message keys in the current receiving chain.
func (s *State) skipMessageKeys(key Key, until uint) error {
	if until < uint(s.Nr) {
		return fmt.Errorf("out-of-order message (maybe it was deleted)")
	}

	if uint(s.Nr)+s.MaxSkip < until {
		return fmt.Errorf("too many messages")
	}

	for uint(s.Nr) < until {
		var mk Key
		s.CKs, mk = KdfCK(s.CKs)
		s.Ns += 1
		s.MkSkipped.Save(s.DHr, uint(s.Nr), mk)

	}
	return nil
}