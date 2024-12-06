package main

import (
	"fmt"
	"net"

	"github.com/wintersakuraa/encrypted-messenger/dratchet"
	"github.com/wintersakuraa/encrypted-messenger/utils"
)

func main() {

	fmt.Println("Connecting to Bob...")
	conn, err := net.Dial("tcp", "localhost:8080")
	if err != nil {
		fmt.Println("error connecting to Bob:", err)
		return
	}
	defer conn.Close()

	// Assume both parties have already agreed the shared key before
	sk, err := utils.GetSK()
	if err != nil {
		fmt.Println("error reading shared key", err)
		return
	}

	// Assume Alice already have Bob's ratchet public key
	dhPubKey, err := utils.GetSharedPub()
	if err != nil {
		fmt.Println("error reading dh pub key", err)
		return
	}

	state, err := dratchet.RatchetInitAlice(sk, dhPubKey)
	if err != nil {
		fmt.Println("error initializing session", err)
		return
	}

	fmt.Println("Connected to Bob. Start chatting!")
	go utils.HandleIncomingMessages(conn, "Bob", state)

	utils.SendMessages(conn, "Alice", state)
}
