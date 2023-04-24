package auth

import (
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
)

func CheckAuth(w http.ResponseWriter, r *http.Request, secretKey []byte) ([]byte, error) {

	type UserData struct {
		UserId   string
		Username string
	}
	var u UserData

	type JWTClaim struct {
		Data UserData
		jwt.StandardClaims
	}
	prefix := "Bearer "
	authHeader := r.Header.Get("Authorization")
	reqToken := strings.TrimPrefix(authHeader, prefix)
	userIdHeader := r.Header.Get("Wawi-UserID")
	u.UserId = userIdHeader
	u.Username = u.UserId

	_, err := jwt.ParseWithClaims(
		reqToken,
		&JWTClaim{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(secretKey), nil
		},
	)
	if err != nil {
		log.Println(err)
		(w).WriteHeader(http.StatusUnauthorized)
		return []byte("error"), err
	}
	return []byte(""), nil
}

func GenerateJWT(username, userID string, secretKey []byte) (string, error) {
	exp := time.Now().Add(24 * 365 * time.Hour)
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["exp"] = exp.UnixMilli() / 1000
	claims["username"] = username
	claims["userId"] = userID
	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}
