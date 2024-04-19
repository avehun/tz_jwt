package manager

import (
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
)

func GenerateAccessToken(userid string) (string, error) {
	secretKey := os.Getenv("SECRET_KEY")
	token := jwt.New(jwt.SigningMethodHS512)
	claims := token.Claims.(jwt.MapClaims)
	claims["user_id"] = userid
	claims["exp"] = time.Now().Add(time.Minute * 15).Unix()
	acces, err := token.SignedString(secretKey)
	if err != nil {
		return "", err
	}
	return acces, nil
}

func GenerateRefhreshToken() (string, error) {
	b := make([]byte, 32)
	s := rand.NewSource(time.Now().Unix())
	r := rand.New(s)
	_, err := r.Read(b)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}

func Parse(accessToken string) (string, error) {
	token, err := jwt.Parse(accessToken, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %s", t.Header["alg"])
		}
		return []byte(os.Getenv("SECRET_KEY")), nil
	})
	if err != nil {
		return "", err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("error get user claims from token: %s", err)
	}
	return claims["user_id"].(string), nil
}
