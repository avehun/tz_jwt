package main

import (
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
	"github.com/radiance822/tz_jwt/handlers"
)

func init() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/generate/", handlers.GenerateTokenPair)
	mux.HandleFunc("/refresh", handlers.RefreshTokenPair)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Starting server on port %s", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatal("Error starting server: ", err)
	}
}
