package main

import (
	"log"
	"net/http"

	"github.com/joho/godotenv"
	"github.com/radiance822/tz_jwt/handlers"
)

func main() {
	godotenv.Load(".env")
	mux := http.NewServeMux()
	mux.HandleFunc("/generate/{id}", handlers.GenerateTokenPair)
	mux.HandleFunc("/refresh", handlers.RefreshTokenPair)

	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatal("error serving port :8080")
	}
}
