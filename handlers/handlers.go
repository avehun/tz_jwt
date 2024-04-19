package handlers

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/radiance822/tz_jwt/manager"
	"github.com/radiance822/tz_jwt/models"
	"go.mongodb.org/mongo-driver/bson"
	"golang.org/x/crypto/bcrypt"
)

func GenerateTokenPair(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("id")
	accessToken, err := manager.GenerateAccessToken(userID)
	if err != nil {
		http.Error(w, "Failed to create access token", http.StatusInternalServerError)
		return
	}
	refreshToken, err := manager.GenerateRefreshToken()
	if err != nil {
		http.Error(w, "Failed to create refresh token", http.StatusInternalServerError)
		return
	}

	hashedToken, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash refresh token", http.StatusInternalServerError)
		return
	}

	collection := manager.GetDatabase().Collection("tokens")
	_, err = collection.InsertOne(context.Background(), bson.M{"userid": int(userID), "refresh_token": string(hashedToken)})
	if err != nil {
		http.Error(w, "Failed to save refresh token", http.StatusInternalServerError)
		return
	}

	response := models.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}
	json.NewEncoder(w).Encode(response)
}

func RefreshTokenPair(w http.ResponseWriter, r *http.Request) {
	var tokens models.TokenPair
	err := json.NewDecoder(r.Body).Decode(&tokens)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	userID, err := manager.Parse(tokens.AccessToken)
	if err != nil {
		http.Error(w, "Invalid access token", http.StatusBadRequest)
		return
	}

	collection := manager.GetDatabase().Collection("tokens")
	var tokenDoc bson.M
	err = collection.FindOne(context.Background(), bson.M{"userid": userID}).Decode(&tokenDoc)
	if err != nil {
		http.Error(w, "No matching refresh token found", http.StatusUnauthorized)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(tokenDoc["refresh_token"].(string)), []byte(tokens.RefreshToken))
	if err != nil {
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	newAccessToken, err := manager.GenerateAccessToken(userID)
	if err != nil {
		http.Error(w, "Failed to create new access token", http.StatusInternalServerError)
		return
	}
	tokens.AccessToken = newAccessToken

	json.NewEncoder(w).Encode(tokens)
}
