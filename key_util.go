package main

import "crypto/sha256"

func deriveChildKey(base []byte, iterations int) []byte {
	v := base
	for i := 0; i < iterations; i++ {
		v = B32ToB(sha256.Sum256(v))
	}

	return v
}
