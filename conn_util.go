package main

import (
	"errors"
	"fmt"
	"io"
	"net"
)

var (
	ErrVarintOverflow = errors.New("varint: overflow (too many bytes)")
	ErrConnClosed     = errors.New("connection closed")
)

const maxVarintBytes = 10

// writeUvarint writes u as an unsigned varint to conn.
func writeUvarint(conn net.Conn, u uint64) error {
	var buf [maxVarintBytes]byte
	i := 0
	for u >= 0x80 {
		buf[i] = byte(u&0x7F) | 0x80
		u >>= 7
		i++
	}
	buf[i] = byte(u)
	i++
	n := i
	written := 0
	for written < n {
		m, err := conn.Write(buf[written:n])
		if err != nil {
			return err
		}
		if m == 0 {
			return ErrConnClosed
		}
		written += m
	}
	return nil
}

// writeVarint writes a signed integer using ZigZag encoding.
func writeVarint(conn net.Conn, v int64) error {
	uv := encodeZigZag(v)
	return writeUvarint(conn, uv)
}

// readUvarint reads an unsigned varint from conn and returns it.
// It will read up to maxVarintBytes and return ErrVarintOverflow if exceeded.
func readUvarint(conn net.Conn) (uint64, error) {
	var x uint64
	var s uint
	var buf [1]byte
	for i := 0; i < maxVarintBytes; i++ {
		n, err := conn.Read(buf[:])
		if err != nil {
			if err == io.EOF {
				return 0, io.ErrUnexpectedEOF
			}
			return 0, err
		}
		if n != 1 {
			return 0, io.ErrUnexpectedEOF
		}
		b := buf[0]
		if b < 0x80 {
			if i == maxVarintBytes-1 && b>>1 != 0 {
				// overflow guard for last byte
				return 0, ErrVarintOverflow
			}
			x |= uint64(b) << s
			return x, nil
		}
		x |= uint64(b&0x7F) << s
		s += 7
	}
	return 0, ErrVarintOverflow
}

// readVarint reads a signed varint (ZigZag) from conn.
func readVarint(conn net.Conn) (int64, error) {
	u, err := readUvarint(conn)
	if err != nil {
		return 0, err
	}
	return decodeZigZag(u), nil
}

// encodeZigZag converts signed int64 to unsigned uint64 using ZigZag.
func encodeZigZag(v int64) uint64 {
	return uint64(uint64((v << 1) ^ (v >> 63)))
}

// decodeZigZag converts ZigZag-encoded uint64 back to int64.
func decodeZigZag(u uint64) int64 {
	return int64((u >> 1) ^ uint64((int64(u&1)<<63)>>63))
}

// SendFrame checks the length of the data
// sends a uvariant of the length and the data to conn.
func SendFrame(conn net.Conn, data []byte) error {
	err := writeUvarint(conn, uint64(len(data)))
	if err != nil {
		return err
	}

	_, err = conn.Write(data)
	return err
}

// ReceiveFrame reads a uvarint from conn as the length
// if maxLen != -1 then the varint has to be smaller than maxLen
func ReceiveFrame(conn net.Conn, maxLen int64) ([]byte, error) {
	length, err := readUvarint(conn)
	if err != nil {
		return nil, err
	}

	if maxLen != -1 && length > uint64(maxLen) {
		return nil, ErrVarintOverflow
	}

	buf := make([]byte, length)

	_, err = io.ReadFull(conn, buf)
	return buf, err
}

// SendEncryptedFrame encrypts the payload using chacha
// then sends it as a frame
func SendEncryptedFrame(conn net.Conn, data []byte, key []byte, nonce []byte, aad []byte) error {
	enc, err := ChaChaSeal(key, nonce, data, aad)
	if err != nil {
		return err
	}

	fmt.Printf("Sending encrypted frame: %d\n", len(enc))
	return SendFrame(conn, enc)
}

// ReceiveEncryptedFrame reads a frame
// then decrypts it using chacha
func ReceiveEncryptedFrame(conn net.Conn, maxLen int64, key []byte, aad []byte) ([]byte, error) {
	ciphertext, err := ReceiveFrame(conn, maxLen)
	if err != nil {
		return nil, err
	}

	fmt.Printf("Decrypted frame: %d\n", len(ciphertext))

	return ChaChaOpen(key, ciphertext, aad)
}
