package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/ntnj/derpnet"
	"github.com/ntnj/derpnet/derpquic"
	"golang.org/x/crypto/curve25519"
)

var (
	derpServer = flag.String("derp", "", "derp server to use")
	keyName    = flag.String("key", "derpconnect", "key file to use")
	debug      = flag.Bool("debug", false, "enable debug logging")
)

func main() {
	flag.Parse()
	if *debug {
		derpnet.Debug = true
		derpquic.Debug = true
	}
	if *derpServer == "" {
		log.Fatalln(`Provide a DERP server to use with --derp=<xxx>.tailscale.com flag.
You can find Tailscale hosted DERP server from https://login.tailscale.com/derpmap/default or use a self hosted DERP server.`)
	}
	key, err := getKey(*keyName)
	if err != nil {
		log.Fatalf("unable to generate key: %v", err)
	}

	switch flag.Arg(0) {
	case "serve":
		pubKey, err := curve25519.X25519(key, curve25519.Basepoint)
		if err != nil {
			log.Fatalf("unable to get public key: %v", err)
		}
		port, err := strconv.Atoi(flag.Arg(1))
		if err != nil {
			log.Fatalf(`provide a valid port with "derpconnect serve <port>"`)
		}
		l, err := derpquic.Listen(*derpServer, key)
		if err != nil {
			log.Fatalf("unable to connect to DERP server: %v", err)
		}
		log.Printf(`Listening through DERP. Join with "derpconnect --derp=%s join %v"`, *derpServer, base64.RawURLEncoding.EncodeToString(pubKey))
		proxyConn(l, func() (net.Conn, error) {
			return net.Dial("tcp", fmt.Sprintf("localhost:%d", port))
		})
	case "join":
		pubkey, err := base64.RawURLEncoding.DecodeString(flag.Arg(1))
		if err != nil || len(pubkey) != 32 {
			log.Fatalf(`provide correct public key of server with "derpconnect join <pubkey>": %v`, err)
		}
		port, err := strconv.Atoi(flag.Arg(2))
		if err != nil {
			if flag.Arg(2) == "" {
				port = 0
			} else {
				log.Fatalf("unable to get port to listen to: %v", err)
			}
		}
		l, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			log.Fatalf("unable to listen locally on port %d: %v", port, err)
		}
		d, err := derpquic.NewDialer(*derpServer, key)
		if err != nil {
			log.Fatalf("unable to connect to DERP server: %v", err)
		}
		log.Printf("Listening on %v", l.Addr())
		proxyConn(l, func() (net.Conn, error) {
			return d.Dial(pubkey)
		})
	case "internaltest":
		internalTesting()
	default:
		log.Println(`Run "derpconnect --derp=... serve <port>" on server
Run "derpconnect --derp=... join <pubkey> <listen_port>" to connect client to server`)
	}
}

func proxyConn(l net.Listener, dial func() (net.Conn, error)) {
	for {
		inConn, err := l.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			continue
		}
		if *debug {
			log.Printf("Accepted connection from %v", inConn.RemoteAddr())
		}
		go func(conn net.Conn) {
			outConn, err := dial()
			if err != nil {
				log.Printf("Error connecting to target: %v", err)
				inConn.Close()
				return
			}
			go func() {
				defer closeRead(conn)
				defer closeWrite(outConn)
				n, err := io.Copy(outConn, conn)
				if *debug {
					log.Printf("Copied out %d bytes %v", n, err)
				}
			}()
			go func() {
				defer closeRead(outConn)
				defer closeWrite(conn)
				n, err := io.Copy(conn, outConn)
				if *debug {
					log.Printf("Copied in %d bytes %v", n, err)
				}
			}()
		}(inConn)
	}
}

type closerReadWrite interface {
	CloseRead() error
	CloseWrite() error
}

func closeRead(conn net.Conn) {
	if c, ok := conn.(closerReadWrite); ok {
		c.CloseRead()
	}
}

func closeWrite(conn net.Conn) {
	if c, ok := conn.(closerReadWrite); ok {
		c.CloseWrite()
	}
}

func getKey(name string) (derpnet.Key, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return nil, fmt.Errorf("unable to store key: %w", err)
	}
	keyPath := filepath.Join(configDir, "derpconnect", name)
	if bytes, err := os.ReadFile(keyPath); err == nil {
		if len(bytes) != 32 {
			return nil, fmt.Errorf("invalid key length found: %d", len(bytes))
		}
		return bytes, nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("unable to read existing key: %w", err)
	}

	key, err := derpnet.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return nil, fmt.Errorf("unable to create dir: %w", err)
	}
	if err := os.WriteFile(keyPath, key, 0o400); err != nil {
		return nil, fmt.Errorf("unable to save key: %w", err)
	}
	return key, nil
}

func internalTesting() {
	key1 := [32]byte{'h', 'e'}
	key2 := [32]byte{'e', 'f'}
	var pkey1, pkey2 [32]byte
	curve25519.ScalarBaseMult(&pkey1, &key1)
	curve25519.ScalarBaseMult(&pkey2, &key2)
	go func() {
		conn, err := derpnet.ListenPacket(*derpServer, key1[:])
		if err != nil {
			panic(err)
		}
		go func() {
			for range time.Tick(13 * time.Second) {
				msg := fmt.Sprintf("key1: %v", time.Now())
				n, err := conn.WriteTo([]byte(msg), derpnet.Addr(pkey2[:]))
				log.Printf("W1 %d: %s : %v", n, msg, err)
			}
		}()
		go func() {
			b := make([]byte, 4096)
			for {
				n, _, err := conn.ReadFrom(b)
				log.Printf("R1 %d: %s : %v", n, b, err)
			}
		}()
	}()
	go func() {
		conn, err := derpnet.ListenPacket(*derpServer, key2[:])
		if err != nil {
			panic(err)
		}
		go func() {
			for range time.Tick(5 * time.Second) {
				msg := fmt.Sprintf("key2: %v", time.Now())
				n, err := conn.WriteTo([]byte(msg), derpnet.Addr(pkey1[:]))
				log.Printf("W2 %d: %s : %v", n, msg, err)
			}
		}()
		go func() {
			b := make([]byte, 4096)
			for {
				n, _, err := conn.ReadFrom(b)
				log.Printf("R2 %d: %s : %v", n, b, err)
			}
		}()
	}()
	time.Sleep(2 * time.Minute)
}
