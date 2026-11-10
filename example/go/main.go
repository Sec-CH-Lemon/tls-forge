package main

import (
	"fmt"
	"log"
	"os"

	tlsforge "github.com/Sec-CH-Lemon/tls-forge"
)

const defaultURL = "https://tls.browserleaks.com/json"

func main() {
	target := defaultURL
	if len(os.Args) > 1 {
		target = os.Args[1]
	}

	client, err := tlsforge.New(tlsforge.WithProfile("chrome"))
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			log.Printf("closing client: %v", err)
		}
	}()

	response, err := client.Get(target)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("status: %d\n", response.Status)
	fmt.Printf("url: %s\n\n", response.URL)
	fmt.Println(response.Text())
}
