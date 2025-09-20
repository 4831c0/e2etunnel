package main

// B32ToB converts [32]byte into a []byte
func B32ToB(data [32]byte) []byte {
	ret := make([]byte, len(data))
	for i, datum := range data {
		ret[i] = datum
	}

	return ret
}

// BToB32 converts []byte to [32]byte
func BToB32(data []byte) [32]byte {
	var ret [32]byte
	for i, datum := range data {
		ret[i] = datum
	}

	return ret
}
