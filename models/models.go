package models

type TokenPair struct {
	AccessToken  string `json:"acces_token"`
	RefreshToken string `json:"refresh_token"`
}
