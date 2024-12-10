package dratchet

import (
	"bytes"
	"fmt"
)

func RatchetEncrypt(s *State, plaintext, ad []byte) (Message, error) {
	var (
		h = Header{
			DH: s.DHs.PublicKey(),
			N:  s.Ns,
			PN: s.PN,
		}
		mk Key
	)

	s.CKs, mk = KdfCK(s.CKs)
	s.Ns += 1

	ct, err := Encrypt(mk, plaintext, append(ad, h.Encode()...))
	if err != nil {
		return Message{}, err
	}

	return Message{h, ct}, nil
}

func RatchetDecrypt(s *State, m Message, ad []byte) ([]byte, error) {
	// Check if message is skipped
	mk, ok, err := s.MkSkipped.Get(m.Header.DH, uint(m.Header.N))
	if err != nil {
		return nil, err
	}

	if ok {
		plaintext, err := Decrypt(mk, m.Ciphertext, append(ad, m.Header.Encode()...))
		if err != nil {
			return nil, fmt.Errorf("can't decrypt skipped message: %s", err)
		}
		s.MkSkipped.Delete(m.Header.DH, uint(m.Header.N))
		return plaintext, nil
	}

	// Check if new ratchet key
	if !bytes.Equal(m.Header.DH, s.DHr) {
		if err = s.skipMessageKeys(uint(m.Header.PN)); err != nil {
			return nil, fmt.Errorf("can't skip previous chain message keys: %s", err)
		}
		if err = s.dhRatchet(m.Header); err != nil {
			return nil, fmt.Errorf("can't perform ratchet step: %s", err)
		}
	}

	if err = s.skipMessageKeys(uint(m.Header.N)); err != nil {
		return nil, fmt.Errorf("can't skip current chain message keys: %s", err)
	}

	s.CKr, mk = KdfCK(s.CKr)
	s.Nr += 1

	plaintext, err := Decrypt(mk, m.Ciphertext, append(ad, m.Header.Encode()...))
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
