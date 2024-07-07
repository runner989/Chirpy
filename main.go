package main

import (
	"net/http"
	"log"
)

func main() {
	mux := http.NewServeMux()
	server := &http.Server {
		Addr: "localhost:8080",
		Handler: mux,
	}

	log.Println("Listening on 8080...")
	log.Fatal(server.ListenAndServe())
}
