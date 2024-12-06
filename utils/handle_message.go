package utils

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"

	"github.com/wintersakuraa/encrypted-messenger/dratchet"
)

func HandleIncomingMessages(conn net.Conn, sender string, state *dratchet.State) {
	reader := bufio.NewReader(conn)

	for {
		jsonMsg, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("Connection closed.")
			return
		}

		var message dratchet.Message
		err = json.Unmarshal([]byte(jsonMsg), &message)
		if err != nil {
			fmt.Println("error parsing message", err)
			return
		}

		pl, err := dratchet.RatchetDecrypt(state, message, nil)
		if err != nil {
			fmt.Println("error decrypting message", err)
			return
		}

		fmt.Printf("\n%s", pl)
		fmt.Printf("You: ")
	}
}

func SendMessages(conn net.Conn, sender string, state *dratchet.State) {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print("You: ")

	for scanner.Scan() {
		fmt.Print("You: ")
		text := scanner.Text()

		// encrypt plain text message and get cipher text
		plm := fmt.Sprintf("%s: %s\n", sender, text)
		message, err := dratchet.RatchetEncrypt(state, []byte(plm), nil)
		if err != nil {
			fmt.Println("error encrypting message", err)
			return
		}

		jsonMsg, err := json.Marshal(message)
		if err != nil {
			fmt.Println("error stringifying message", err)
			return
		}

		_, err = conn.Write(append(jsonMsg, '\n'))
		if err != nil {
			fmt.Println("error sending message", err)
			return
		}
	}
}
