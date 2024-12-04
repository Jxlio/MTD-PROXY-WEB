package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-redis/redis/v8" // Import the package that defines the rdb variable
	"github.com/google/uuid"
)

var rdb = redis.NewClient(&redis.Options{
	Addr:     "localhost:6379", // Replace with the actual Redis server address
	Password: "",               // Replace with the actual Redis server password if required
	DB:       0,                // Replace with the actual Redis database number
})

var jwtKey = []byte("morphProxySecretKey")

func GenerateJWT(sessionID, ip string) (string, error) {
	if !CanGenerateJWT(ip) {
		return "", fmt.Errorf("rate limit exceeded for IP %s", ip)
	}

	claims := &Claims{
		SessionID: sessionID,
		StandardClaims: jwt.StandardClaims{
			Id:        sessionID,
			ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}

func SetSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    token,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
		Secure:   true,
	})
}

func GetSessionID(r *http.Request) (string, error) {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		return "", err
	}

	tokenStr := cookie.Value
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil || !token.Valid {
		return "", err
	}

	return claims.SessionID, nil
}

func IsSessionBlacklisted(sessionID string) bool {
	result, err := rdb.Get(ctx, "blacklist:"+sessionID).Result()
	if err == redis.Nil {
		logInfo("Session %s is not blacklisted", sessionID)
		return false
	} else if err != nil {
		logError("Error checking blacklist for session %s: %v", sessionID, err)
		return false
	}
	logInfo("Session %s is blacklisted", sessionID)
	return result == "1"
}

func BlacklistSession(sessionID string) {
	err := rdb.Set(ctx, "blacklist:"+sessionID, "1", 10*time.Minute).Err()
	if err != nil {
		logError("Failed to blacklist session: %v", err)
	} else {
		logInfo("Session %s blacklisted successfully", sessionID)
	}
}

func generateSessionID() string {
	return uuid.New().String()
}

func CanGenerateJWT(ip string) bool {
	key := fmt.Sprintf("jwt_rate:%s", ip)
	count, err := rdb.Get(ctx, key).Int()
	if err != nil && err != redis.Nil {
		logError("Failed to check JWT rate limit: %v", err)
		return false
	}

	if count >= 50 {
		return false
	}
	err = rdb.Incr(ctx, key).Err()
	if err != nil {
		logError("Failed to increment JWT rate limit: %v", err)
		return false
	}

	if count == 0 {
		rdb.Expire(ctx, key, 1*time.Minute)
	}

	return true
}
