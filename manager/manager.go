package manager

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var secretKey string
var database *mongo.Database

func init() {
	err := godotenv.Load(".env")
	if err != nil {
		fmt.Printf("Error loading .env file: %v", err)
	}
	secretKey = os.Getenv("SECRET_KEY")
	clientOptions := options.Client().ApplyURI(os.Getenv("MONGO_URI"))
	client, err := mongo.Connect(context.Background(), clientOptions)
	if err != nil {
		fmt.Println("Failed to connect to MongoDB:", err)
		return
	}

	err = client.Ping(context.Background(), nil)
	if err != nil {
		fmt.Println("Failed to ping MongoDB:", err)
		return
	}

	database = client.Database("jwt_tokens")
}

func GenerateAccessToken(userID string) (string, error) {
	if secretKey == "" {
		return "", fmt.Errorf("secret key is not set")
	}

	token := jwt.New(jwt.SigningMethodHS512)
	claims := token.Claims.(jwt.MapClaims)
	claims["user_id"] = userID
	claims["exp"] = time.Now().Add(time.Minute * 15).Unix()

	accessToken, err := token.SignedString([]byte(secretKey))
	if err != nil {
		return "", err
	}
	return accessToken, nil
}

func GenerateRefreshToken() (string, error) {
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
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(secretKey), nil
	})
	if err != nil {
		return "", err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("error getting user claims from token")
	}

	userID, ok := claims["user_id"].(string)
	if !ok {
		return "", fmt.Errorf("error getting user ID from token")
	}

	return userID, nil
}

func GetDatabase() *mongo.Database {
	return database
}
