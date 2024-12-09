package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
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
	// Convertir les données de la requête en une map
	data := map[string]interface{}{
		"method":  r.Method,
		"url":     r.URL.String(),
		"headers": r.Header,
		"body":    extractRequestBody(r),
	}

	// Envoyer les données au service Flask
	response, err := sendToDetectionService(data)
	if err != nil {
		logError("Error contacting detection service: %v", err)
		return true // Considérer la requête comme malveillante en cas d'erreur
	}

	// Nettoyer la réponse pour éviter des espaces ou des caractères inattendus
	response = strings.TrimSpace(response)

	// Vérifier le verdict (texte brut)
	switch response {
	case "MALICIOUS":
		return true
	case "SAFE":
		return false
	default:
		// Si la réponse est inattendue, consigner l'erreur
		logError("Unexpected response from detection service: %s", response)
		return true // Considérer la requête comme malveillante par précaution
	}
}

// extractRequestBody extrait le corps de la requête HTTP
func extractRequestBody(r *http.Request) string {
	if r.Body == nil {
		return ""
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		logError("Error reading request body: %v", err)
		return ""
	}
	return string(body)
}

func sendToDetectionService(data map[string]interface{}) (string, error) {
	// Convertir les données en JSON
	jsonData, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	// Créer une nouvelle requête HTTP
	url := "http://localhost:3000" // URL du service Flask
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}

	// Ajouter le header Content-Type
	req.Header.Set("Content-Type", "application/json")

	// Envoyer la requête
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Lire la réponse en tant que texte brut
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// Journaliser la réponse brute pour débogage
	logInfo("Detection service raw response: %s", string(body))

	// Vérifier le statut HTTP
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("detection service returned status: %d, response: %s", resp.StatusCode, string(body))
	}

	// Retourner la réponse brute
	return string(body), nil
}
