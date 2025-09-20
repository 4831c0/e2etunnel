package main

import (
	"crypto/rand"
	"encoding/json"
	"flag"
	"log"
	"net"
	"os"
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
			finalKey := deriveArgon2id32FromPSK(config.PSK, salt)
			log.Printf("Derived final key: %d\n", len(finalKey))

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

					err = SendEncryptedFrame(encRemoteConn, b, finalKey, chachaNonce, config.AAD2)
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
					data, err := ReceiveEncryptedFrame(encRemoteConn, -1, finalKey, config.AAD2)

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
			finalKey := deriveArgon2id32FromPSK(config.PSK, salt)
			log.Printf("Derived final key: %d\n", len(finalKey))

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

					err = SendEncryptedFrame(encClientConn, b, finalKey, chachaNonce, config.AAD2)
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
					data, err := ReceiveEncryptedFrame(encClientConn, -1, finalKey, config.AAD2)

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
