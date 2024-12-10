package main

import (
	"bytes"
	"fmt"
	"log"

	"github.com/wintersakuraa/encrypted-messenger/dratchet"
)

func main() {
	bobKeyPair, _ := dratchet.GenerateDH()
	sharedKey := make([]byte, 32)
	for i := range sharedKey {
		sharedKey[i] = byte(i)
	}

	aliceState, _ := dratchet.RatchetInitAlice(sharedKey, bobKeyPair.PublicKey())
	bobState, _ := dratchet.RatchetInitBob(sharedKey, bobKeyPair)

	// Alice sends 3 messages
	m1, _ := dratchet.RatchetEncrypt(aliceState, []byte("Message 1"), nil)
	m2, _ := dratchet.RatchetEncrypt(aliceState, []byte("Message 2"), nil)
	m3, _ := dratchet.RatchetEncrypt(aliceState, []byte("Message 3"), nil)

	// Bob receives m1 and m3 (m2 is skipped)
	fmt.Println("Processing M1...")
	plaintext1, err := dratchet.RatchetDecrypt(bobState, m1, nil)
	if err != nil {
		log.Fatalf("Failed to decrypt M1: %v", err)
	}
	fmt.Printf("Decrypted M1: %s\n", plaintext1)

	fmt.Println("Processing M3 (skipping M2)...")
	plaintext3, err := dratchet.RatchetDecrypt(bobState, m3, nil)
	if err != nil {
		log.Fatalf("Failed to decrypt M3: %v", err)
	}
	fmt.Printf("Decrypted M3: %s\n", plaintext3)

	// Check if Bob has saved the skipped key for m2
	fmt.Println("Checking skipped keys for M2...")
	_, ok, err := bobState.MkSkipped.Get(m2.Header.DH, uint(m2.Header.N))
	if err != nil || !ok {
		log.Fatalf("Skipped key for M2 not found: %v", err)
	}
	fmt.Println("Skipped key for M2 found!")

	// Bob processes m2 later
	fmt.Println("Processing M2 (after being skipped)...")
	plaintext2, err := dratchet.RatchetDecrypt(bobState, m2, nil)
	if err != nil {
		log.Fatalf("Failed to decrypt skipped M2: %v", err)
	}
	fmt.Printf("Decrypted M2: %s\n", plaintext2)

	if !bytes.Equal(plaintext1, []byte("Message 1")) || !bytes.Equal(plaintext2, []byte("Message 2")) || !bytes.Equal(plaintext3, []byte("Message 3")) {
		log.Fatal("Message content mismatch!")
	}
	fmt.Println("All messages decrypted successfully, including skipped ones!")
}
