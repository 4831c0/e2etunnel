package main

import "golang.org/x/crypto/argon2"

func deriveArgon2id32FromPSK(psk, salt []byte) []byte {
	time := uint32(1)
	memory := uint32(4 * 1024)
	threads := uint8(2)
	keyLen := uint32(32)
	return argon2.IDKey(psk, salt, time, memory, threads, keyLen)
}
