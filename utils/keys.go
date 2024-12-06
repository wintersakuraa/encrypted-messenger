package utils

import (
	"fmt"
	"os"
)

func SharePub(key []byte) error {
	filename := "pub.bin"
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	_, err = file.Write(key[:])
	if err != nil {
		return fmt.Errorf("failed to write key to file: %w", err)
	}

	return nil
}

func GetSharedPub() ([]byte, error) {
	key := make([]byte, 32)

	filename := "pub.bin"
	file, err := os.Open(filename)
	if err != nil {
		return key, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	buf := make([]byte, 32)
	n, err := file.Read(buf)
	if err != nil {
		return key, fmt.Errorf("failed to read key from file: %w", err)
	}
	if n != 32 {
		return key, fmt.Errorf("unexpected key size: expected 32 bytes, got %d", n)
	}

	copy(key[:], buf)

	return key, nil
}

func GetSK() ([]byte, error) {
	key := make([]byte, 32)

	filename := "sk.bin"
	file, err := os.Open(filename)
	if err != nil {
		return key, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	buf := make([]byte, 32)
	n, err := file.Read(buf)
	if err != nil {
		return key, fmt.Errorf("failed to read key from file: %w", err)
	}
	if n != 32 {
		return key, fmt.Errorf("unexpected key size: expected 32 bytes, got %d", n)
	}

	copy(key, buf[:])

	return key, nil
}
