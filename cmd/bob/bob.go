package main

import (
	"fmt"
	"net"

	"github.com/wintersakuraa/encrypted-messenger/dratchet"
	"github.com/wintersakuraa/encrypted-messenger/utils"
)

func main() {
	fmt.Println("Bob is waiting for Alice to connect...")
	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		fmt.Println("error listening", err)
		return
	}
	defer listener.Close()

	keyPair, err := dratchet.GenerateDH()
	if err != nil {
		fmt.Println("error generating DH key pair", err)
		return
	}

	// Share public key with Alice
	utils.SharePub(keyPair.PublicKey())

	// Assume both parties have already agreed the shared key before
	sk, err := utils.GetSK()
	if err != nil {
		fmt.Println("error reading shared key", err)
		return
	}

	state, err := dratchet.RatchetInitBob(sk, keyPair)
	if err != nil {
		fmt.Println("error initializing session", err)
		return
	}

	conn, err := listener.Accept()
	if err != nil {
		fmt.Println("error accepting connection", err)
		return
	}
	defer conn.Close()

	fmt.Println("Connected to Alice. Start chatting!")
	go utils.HandleIncomingMessages(conn, "Alice", state)

	utils.SendMessages(conn, "Bob", state)
}
