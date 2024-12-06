package dratchet

import (
	"encoding/binary"
	"fmt"
)

type Message struct {
	Header     Header
	Ciphertext []byte
}

type Header struct {
	// sender's current ratchet public key.
	DH Key

	// N is the number of the message in the sending chain.
	N uint32

	// PN is the length of the previous sending chain.
	PN uint32
}

type MessageEncHeader []byte

// Encode the header in the binary format.
func (h Header) Encode() MessageEncHeader {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint32(buf[0:4], h.N)
	binary.LittleEndian.PutUint32(buf[4:8], h.PN)
	return append(buf, h.DH[:]...)
}

// Decode message header out of the binary-encoded representation.
func (h MessageEncHeader) Decode() (Header, error) {
	// n (4 bytes) + pn (4 bytes) + dh (32 bytes)
	if len(h) != 40 {
		return Header{}, fmt.Errorf("invalid message header length: %d", len(h))
	}
	var dh Key = make(Key, 32)
	// take last 32 bytes
	copy(dh[:], h[8:40])
	return Header{
		DH: dh,
		N:  binary.LittleEndian.Uint32(h[0:4]),
		PN: binary.LittleEndian.Uint32(h[4:8]),
	}, nil
}
