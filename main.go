package main

import (
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/radiance822/tz_jwt/handlers"
)

func main() {
	if err := godotenv.Load(".env"); err != nil {
		log.Fatal("Error loading dotenv file")
	}

	router := mux.NewRouter()
	router.HandleFunc("/generate/{id}", handlers.GenerateTokenPair).Methods("GET")
	router.HandleFunc("/refresh", handlers.RefreshTokenPair).Methods("POST")

	if err := http.ListenAndServe(":8080", router); err != nil {
		log.Fatal("error serving port :8080")
	}
}
