package main

import (
	"encoding/json"
	"net"
	"net/http"
	"time"

	"github.com/go-redis/redis/v8"
)

// NewSuspiciousRating initializes a SuspiciousRating instance
func NewSuspiciousRating(redisAddr string, maxSuspicion int) *SuspiciousRating {
	client := redis.NewClient(&redis.Options{
		Addr: redisAddr,
	})
	sr := &SuspiciousRating{client: client, maxSuspicion: maxSuspicion}
	go sr.startDecay()
	return sr
}

// UpdateRating updates the suspicion rating for a given IP
func (sr *SuspiciousRating) UpdateRating(ip string, delta int) {
	sr.client.IncrBy(ctx, ip, int64(delta))
}

// GetRating retrieves the suspicion rating for a given IP
func (sr *SuspiciousRating) GetRating(ip string) int {
	rating, err := sr.client.Get(ctx, ip).Int()
	if err == redis.Nil {
		return 0
	} else if err != nil {
		logError("Error getting rating for IP %s: %v", ip, err)
		return 0
	}
	return rating
}

// startDecay starts the periodic decay of suspicion ratings
func (sr *SuspiciousRating) startDecay() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		sr.decayRatings()
	}
}

// decayRatings decrements the suspicion ratings over time
func (sr *SuspiciousRating) decayRatings() {
	keys, err := sr.client.Keys(ctx, "*").Result()
	if err != nil {
		logError("Error getting keys for decay: %v", err)
		return
	}
	for _, key := range keys {
		sr.client.DecrBy(ctx, key, 1)
	}
}

// DetectAttack detects whether the incoming request is suspicious
func (sr *SuspiciousRating) DetectAttack(r *http.Request) bool {
	// Example detection logic
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		return true
	}
	// Add more detection logic here if needed
	return false
}

func sendToDetectionService(data map[string]interface{}) (map[string]string, error) {
	// Convertir les données en JSON
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	// Établir une connexion TCP
	conn, err := net.Dial("tcp", "localhost:3000")
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Envoyer les données encodées en UTF-8 sur la connexion TCP
	_, err = conn.Write([]byte(jsonData))
	if err != nil {
		return nil, err
	}

	// Lire la réponse du serveur
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, err
	}

	// Décoder la réponse reçue (supposons qu'elle soit en JSON)
	var response map[string]string
	err = json.Unmarshal(buffer[:n], &response)
	if err != nil {
		return nil, err
	}

	return response, nil
}
