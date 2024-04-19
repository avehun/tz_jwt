package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/radiance822/tz_jwt/manager"
	"github.com/radiance822/tz_jwt/models"
)

var TokenDb = make(map[string]string) // In production, replace with a proper DB

func GenerateTokenPair(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userid := vars["id"]

	accessToken, err := manager.GenerateAccessToken(userid)
	if err != nil {
		http.Error(w, "Error creating access token", http.StatusInternalServerError)
		return
	}

	refreshToken, err := manager.GenerateRefreshToken()
	if err != nil {
		http.Error(w, "Error creating refresh token", http.StatusInternalServerError)
		return
	}

	TokenDb[userid] = refreshToken

	response := models.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func RefreshTokenPair(w http.ResponseWriter, r *http.Request) {
	var tokens models.TokenPair
	err := json.NewDecoder(r.Body).Decode(&tokens)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	userid, err := manager.Parse(tokens.AccessToken)
	if err != nil {
		http.Error(w, "Invalid access token", http.StatusUnauthorized)
		return
	}

	if TokenDb[userid] != tokens.RefreshToken {
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	newAccessToken, err := manager.GenerateAccessToken(userid)
	if err != nil {
		http.Error(w, "Error creating new access token", http.StatusInternalServerError)
		return
	}
	tokens.AccessToken = newAccessToken

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokens)
}
