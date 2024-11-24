package goutils

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
)

type AuthClaims struct {
	ID        string `json:"id"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Email     string `json:"email"`
	Admin     bool   `json:"role"`
	jwt.RegisteredClaims
}

func VerifyToken(token string) (*jwt.Token, error) {
	err := godotenv.Load()
	if err != nil {
		fmt.Println("Error loading .env file")
	}

	var JwtKey = []byte(os.Getenv("JWT_SECRET_KEY")) // Replace with a strong secret key

	// Parse the JWT token
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {

		// Verify the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("invalid signing method: %v", token.Header["alg"])
		}
		// Return the secret key used for signing
		return []byte(JwtKey), nil
	})

	if err != nil {
		// Check if the error is due to token expiration
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, fmt.Errorf("access token expired")
		}
		return nil, fmt.Errorf("invalid access token")
	}

	// Extract claims and validate
	claims, ok := parsedToken.Claims.(*AuthClaims)
	if !ok || !parsedToken.Valid {
		return nil, errors.New("invalid token")
	}

	// Validate registered claims
	if claims.ExpiresAt != nil && claims.ExpiresAt.Time.Before(time.Now()) {
		return nil, errors.New("token expired")
	}
	if claims.Issuer != "go-server" {
		return nil, errors.New("invalid issuer")
	}

	// Return the parsed token
	return parsedToken, nil
}
