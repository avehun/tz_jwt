package handlers

import (
	"encoding/json"
	"net/http"

	"log"

	"github.com/radiance822/tz_jwt/manager"
	"github.com/radiance822/tz_jwt/models"
)

var TokenDb map[string]string

func GenerateTokenPair(w http.ResponseWriter, r *http.Request) {
	userid := r.URL.Query().Get("id")
	accesToken, err := manager.GenerateAccessToken(userid)
	if err != nil {
		log.Printf("error creating accessToken")
	}
	refreshToken, err := manager.GenerateRefhreshToken()
	if err != nil {
		log.Printf("error creating refreshToken")
	}

	TokenDb[userid] = refreshToken

	response := models.TokenPair{
		AccesToken:   accesToken,
		RefreshToken: refreshToken,
	}
	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		log.Printf("unable to encode TokenPair: %s", err)
	}
}
func RefreshTokenPair(w http.ResponseWriter, r *http.Request) {
	var tokens models.TokenPair
	json.NewDecoder(r.Body).Decode(&tokens)
	userid, err := manager.Parse(tokens.AccesToken)
	if err != nil {
		log.Fatal("error parsing jwt token")
	}
	if TokenDb[userid] != tokens.RefreshToken {
		log.Fatal("no refresh token in db for this access token")
	}
	newAccessToken, err := manager.GenerateAccessToken(userid)
	if err != nil {
		log.Fatal("error creating new access token")
	}
	tokens.AccesToken = newAccessToken
	err = json.NewEncoder(w).Encode(tokens)
	if err != nil {
		log.Printf("unable to refresh token: %s", err)
	}
}
