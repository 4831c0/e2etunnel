package main

import (
	"crypto/rand"
	"encoding/json"
	"flag"
	"log"
	"net"
	"os"
	"sync"
)

type Config struct {
	Src    string `json:"src"`
	Dst    string `json:"dst"`
	PSK    []byte `json:"psk"`
	AAD1   []byte `json:"AAD1"`
	AAD2   []byte `json:"AAD2"`
	Client bool   `json:"client"`
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

var config Config

func main() {
	configFile := flag.String("config", "config.json", "Path to config file")
	flag.Parse()

	configBytes, err := os.ReadFile(*configFile)
	check(err)

	check(json.Unmarshal(configBytes, &config))

	if config.Client {
		runClient(config.Src, config.Dst)
	} else {
		runServer(config.Src, config.Dst)
	}
}

func runClient(src string, dst string) {
	log.Printf("Running client, src = %s, dst = %s\n", src, dst)

	l, err := net.Listen("tcp", dst)
	check(err)

	for {
		c, err := l.Accept()
		check(err)

		go func(plainClientConn net.Conn) {
			log.Println("New connection")
			encRemoteConn, err := net.Dial("tcp", src)
			if err != nil {
				log.Println(err)

				plainClientConn.Close()
				encRemoteConn.Close()
				return
			}

			log.Println("Receiving public key")
			pk, err := ReceiveFrame(encRemoteConn, 2000)
			if err != nil {
				log.Println(err)

				plainClientConn.Close()
				encRemoteConn.Close()
				return
			}
			log.Printf("pk: %d\n", len(pk))

			xPair, err := GenerateX25519Keypair()
			if err != nil {
				log.Println(err)

				plainClientConn.Close()
				encRemoteConn.Close()
				return
			}

			ct, enc, err := EncryptWithMlKem(pk, B32ToB(xPair.Public))
			if err != nil {
				log.Println(err)

				plainClientConn.Close()
				encRemoteConn.Close()
				return
			}
			log.Printf("mlEnc(xPair.pub): (%d, %d)\n", len(ct), len(enc))

			err = SendFrame(encRemoteConn, ct)
			if err != nil {
				log.Println(err)

				plainClientConn.Close()
				encRemoteConn.Close()
				return
			}
			err = SendFrame(encRemoteConn, enc)
			if err != nil {
				log.Println(err)

				plainClientConn.Close()
				encRemoteConn.Close()
				return
			}

			encSalt, err := ReceiveFrame(encRemoteConn, 89)
			if err != nil {
				log.Println(err)

				plainClientConn.Close()
				encRemoteConn.Close()
				return
			}

			salt, err := X25519Decrypt(xPair.Private, encSalt, config.AAD1)
			if err != nil {
				log.Println(err)

				plainClientConn.Close()
				encRemoteConn.Close()
				return
			}

			chachaNonce, err := ReceiveFrame(encRemoteConn, 12)
			log.Printf("Receved chacha nonce: %d\n", len(chachaNonce))

			log.Printf("Deriving key, salt: %d\n", len(salt))
			rootKey := deriveArgon2id32FromPSK(config.PSK, salt)
			log.Printf("Derived root key: %d\n", len(rootKey))

			activeKey := deriveChildKey(rootKey, 1_000_000)
			log.Printf("Derived initial child key: %d\n", len(activeKey))

			var sendPacketCount int
			var recvPacketCount int
			var sendKeyMutex sync.Mutex
			var recvKeyMutex sync.Mutex
			sendActiveKey := make([]byte, len(activeKey))
			recvActiveKey := make([]byte, len(activeKey))
			copy(sendActiveKey, activeKey)
			copy(recvActiveKey, activeKey)

			// server -> client
			go func() {
				for {
					buf := make([]byte, 1024)
					n, err := plainClientConn.Read(buf)

					if err != nil {
						plainClientConn.Close()
						encRemoteConn.Close()
						break
					}

					b := make([]byte, n)
					for i, _ := range b {
						b[i] = buf[i]
					}

					buf = nil

					sendKeyMutex.Lock()
					err = SendEncryptedFrame(encRemoteConn, b, sendActiveKey, chachaNonce, config.AAD2)
					sendPacketCount++

					// Rotate key every 50 packets
					if sendPacketCount%50 == 0 {
						sendActiveKey = deriveChildKey(sendActiveKey, 50_000)
						log.Printf("Rotated send key after %d packets\n", sendPacketCount)
					}
					sendKeyMutex.Unlock()

					if err != nil {
						plainClientConn.Close()
						encRemoteConn.Close()
						break
					}
				}
			}()

			// client -> server
			go func() {
				for {
					recvKeyMutex.Lock()
					data, err := ReceiveEncryptedFrame(encRemoteConn, -1, recvActiveKey, config.AAD2)
					recvPacketCount++

					// Rotate key every 50 packets
					if recvPacketCount%50 == 0 {
						recvActiveKey = deriveChildKey(recvActiveKey, 50_000)
						log.Printf("Rotated recv key after %d packets\n", recvPacketCount)
					}
					recvKeyMutex.Unlock()

					if err != nil {
						plainClientConn.Close()
						encRemoteConn.Close()
						break
					}

					_, err = plainClientConn.Write(data)

					if err != nil {
						plainClientConn.Close()
						encRemoteConn.Close()
						break
					}
				}
			}()

		}(c)
	}
}

func runServer(src string, dst string) {
	log.Printf("Running server, src = %s, dst = %s\n", src, dst)

	l, err := net.Listen("tcp", dst)
	check(err)

	for {
		c, err := l.Accept()
		check(err)

		go func(encClientConn net.Conn) {
			log.Println("New connection")
			plainRemoteConn, err := net.Dial("tcp", src)
			if err != nil {
				log.Printf("Error connecting to server: %s\n", err)

				encClientConn.Close()

				return
			}

			pair, err := GenerateMlKemKeyPair1024()
			if err != nil {
				log.Printf("Error generating pair: %s\n", err)

				plainRemoteConn.Close()
				encClientConn.Close()
				return
			}

			log.Printf("Sending mlkem public key: %d\n", len(pair.Public))

			err = SendFrame(encClientConn, pair.Public)
			if err != nil {
				log.Printf("Error sending frame: %s\n", err)

				plainRemoteConn.Close()
				encClientConn.Close()
				return
			}

			ct, err := ReceiveFrame(encClientConn, 60)
			if err != nil {
				log.Printf("Failed to receive ciphertext: %s", err)

				plainRemoteConn.Close()
				encClientConn.Close()
				return
			}

			log.Printf("Received ciphertext: %d\n", len(ct))

			enc, err := ReceiveFrame(encClientConn, 1568)
			if err != nil {
				log.Printf("Failed to receive encapsulation: %s", err)

				plainRemoteConn.Close()
				encClientConn.Close()
				return
			}

			log.Printf("Received encapsulation: %d\n", len(enc))

			x25519PubB, err := DecryptWithMlKem(pair.Private, enc, ct)
			if err != nil {
				log.Printf("Failed to decrypt x25519 public key: %s", err)

				plainRemoteConn.Close()
				encClientConn.Close()
				return
			}
			x25519Pub := BToB32(x25519PubB)

			log.Println("Decrypted public x25519 key: 32")

			salt := make([]byte, 16)
			_, err = rand.Read(salt)

			if err != nil {
				log.Printf("Failed to generate salt: %s\n", err)

				plainRemoteConn.Close()
				encClientConn.Close()
				return
			}

			encSalt, err := X25519Encrypt(x25519Pub, salt, config.AAD1)
			if err != nil {
				log.Printf("Failed to encrypt salt: %s\n", err)

				plainRemoteConn.Close()
				encClientConn.Close()
				return
			}

			log.Printf("Sending x25519 encrypted salt: %d\n", len(encSalt))

			err = SendFrame(encClientConn, encSalt)
			if err != nil {
				log.Printf("Error sending frame: %s\n", err)

				plainRemoteConn.Close()
				encClientConn.Close()
				return
			}

			chachaNonce, err := ChaChaGenerateNonce()
			if err != nil {
				log.Printf("Failed to generate chacha nonce: %s\n", err)

				plainRemoteConn.Close()
				encClientConn.Close()
				return
			}

			log.Printf("Sending chacha nonce: %d\n", len(chachaNonce))

			err = SendFrame(encClientConn, chachaNonce)
			if err != nil {
				log.Printf("Error sending chacha nonce: %s\n", err)

				plainRemoteConn.Close()
				encClientConn.Close()
				return
			}

			log.Printf("Deriving key, salt: %d\n", len(salt))
			rootKey := deriveArgon2id32FromPSK(config.PSK, salt)
			log.Printf("Derived root key: %d\n", len(rootKey))

			activeKey := deriveChildKey(rootKey, 1_000_000)
			log.Printf("Derived initial child key: %d\n", len(activeKey))

			var sendPacketCount int
			var recvPacketCount int
			var sendKeyMutex sync.Mutex
			var recvKeyMutex sync.Mutex
			sendActiveKey := make([]byte, len(activeKey))
			recvActiveKey := make([]byte, len(activeKey))
			copy(sendActiveKey, activeKey)
			copy(recvActiveKey, activeKey)

			// server -> client
			go func() {
				for {
					buf := make([]byte, 1024)
					n, err := plainRemoteConn.Read(buf)

					if err != nil {
						plainRemoteConn.Close()
						encClientConn.Close()
						break
					}

					b := make([]byte, n)
					for i, _ := range b {
						b[i] = buf[i]
					}

					buf = nil

					sendKeyMutex.Lock()
					err = SendEncryptedFrame(encClientConn, b, sendActiveKey, chachaNonce, config.AAD2)
					sendPacketCount++

					// Rotate key every 50 packets
					if sendPacketCount%50 == 0 {
						sendActiveKey = deriveChildKey(sendActiveKey, 50_000)
						log.Printf("Rotated send key after %d packets\n", sendPacketCount)
					}
					sendKeyMutex.Unlock()

					if err != nil {
						plainRemoteConn.Close()
						encClientConn.Close()
						break
					}
				}
			}()

			// client -> server
			go func() {
				for {
					recvKeyMutex.Lock()
					data, err := ReceiveEncryptedFrame(encClientConn, -1, recvActiveKey, config.AAD2)
					recvPacketCount++

					// Rotate key every 50 packets
					if recvPacketCount%50 == 0 {
						recvActiveKey = deriveChildKey(recvActiveKey, 50_000)
						log.Printf("Rotated recv key after %d packets\n", recvPacketCount)
					}
					recvKeyMutex.Unlock()

					if err != nil {
						plainRemoteConn.Close()
						encClientConn.Close()
						break
					}

					_, err = plainRemoteConn.Write(data)

					if err != nil {
						plainRemoteConn.Close()
						encClientConn.Close()
						break
					}
				}
			}()

		}(c)
	}
}
