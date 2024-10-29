package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings" // Add this line to import the strings package
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"golang.org/x/exp/rand"
)

var ctx = context.Background()

// ProxyManager manages dynamic proxy switching
type ProxyManager struct {
	proxies      []*url.URL
	mu           sync.Mutex
	currentProxy *url.URL
	ticker       *time.Ticker
}

// NewProxyManager initializes a ProxyManager with a list of proxy URLs
func NewProxyManager(proxyURLs []string) *ProxyManager {
	proxies := make([]*url.URL, len(proxyURLs))
	for i, proxyURL := range proxyURLs {
		url, err := url.Parse(proxyURL)
		if err != nil {
			log.Fatalf("Invalid proxy URL: %s", proxyURL)
		}
		proxies[i] = url
	}

	pm := &ProxyManager{
		proxies:      proxies,
		currentProxy: proxies[0],                       // Commence avec le premier proxy
		ticker:       time.NewTicker(10 * time.Second), // Change toutes les 10 secondes
	}

	go pm.startAutoSwitch() // Démarre le changement automatique de proxy

	return pm
}

// startAutoSwitch switches proxies automatically every 10 seconds
func (pm *ProxyManager) startAutoSwitch() {
	for range pm.ticker.C {
		pm.switchProxy()
	}
}

// switchProxy switches to the next proxy in the list
func (pm *ProxyManager) switchProxy() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	// Effectue un mélange des proxies pour la rotation
	rand.Shuffle(len(pm.proxies), func(i, j int) {
		pm.proxies[i], pm.proxies[j] = pm.proxies[j], pm.proxies[i]
	})

	// Sélectionne le premier proxy après mélange
	pm.currentProxy = pm.proxies[0]
	log.Printf("Switched to new proxy: %s", pm.currentProxy)

	// Mettre à jour l'URL du proxy actif dans Redis
	pm.UpdateActiveProxy(pm.currentProxy)
}

// GetProxy returns the current proxy
func (pm *ProxyManager) GetProxy() *url.URL {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	return pm.currentProxy
}

// UpdateActiveProxy updates the active proxy in Redis
func (pm *ProxyManager) UpdateActiveProxy(currentProxy *url.URL) {
	redisClient := redis.NewClient(&redis.Options{
		Addr: "localhost:6379", // Adresse de Redis
	})
	// Met à jour l'URL du proxy actif dans Redis
	err := redisClient.Set(ctx, "active_proxy", currentProxy.String(), 0).Err()
	if err != nil {
		log.Printf("Failed to update active proxy in Redis: %v", err)
	} else {
		log.Printf("Successfully updated active proxy to %s in Redis", currentProxy.String())
	}
	err = redisClient.Publish(ctx, "proxy_updates", currentProxy).Err()
	if err != nil {
		log.Printf("Failed to publish proxy update: %v", err)
	}
}

// ServeHTTP dynamically proxies the request through one of the managed proxies
func (pm *ProxyManager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Obtenir l'URL du proxy actif depuis Redis
	activeProxy, err := pm.GetActiveProxy()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Vérifie si l'URL demandée correspond à l'URL du proxy actif
	requestedURL := r.URL
	activeProxyURL := pm.GetProxy()

	if requestedURL.Scheme != activeProxyURL.Scheme || strings.Split(requestedURL.Host, ":")[0] != strings.Split(activeProxyURL.Host, ":")[0] {
		log.Printf("Requested host %s does not match active proxy %s", requestedURL.Host, activeProxyURL.Host)
		http.Redirect(w, r, activeProxyURL.String()+r.RequestURI, http.StatusTemporaryRedirect)
		return
	}
	// Proxy la requête au proxy courant
	proxy := httputil.NewSingleHostReverseProxy(activeProxy)
	proxy.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Ignore les erreurs de certificat
		},
	}
	log.Printf("Received request: %s %s", r.Method, r.URL)
	log.Printf("Proxying request to: %s", pm.GetProxy())
	proxy.ServeHTTP(w, r)
}

// GetActiveProxy retrieves the currently active proxy from Redis
func (pm *ProxyManager) GetActiveProxy() (*url.URL, error) {
	redisClient := redis.NewClient(&redis.Options{
		Addr: "localhost:6379", // Adresse de Redis
	})
	activeProxyStr, err := redisClient.Get(ctx, "active_proxy").Result()
	if err != nil {
		return nil, err
	}

	activeProxy, err := url.Parse(activeProxyStr)
	if err != nil {
		return nil, err
	}

	return activeProxy, nil
}

// SuspiciousRating manages the suspicion level of clients
type SuspiciousRating struct {
	client       *redis.Client
	maxSuspicion int
}

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
		log.Printf("Error getting rating for IP %s: %v", ip, err)
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
		log.Printf("Error getting keys for decay: %v", err)
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

func main() {
	// Proxy configurations
	proxyConfigs := []struct {
		id         string
		address    string
		backendURL string
	}{
		{id: "proxy1", address: ":8081", backendURL: "http://127.0.0.1:5000"},
		{id: "proxy2", address: ":8082", backendURL: "http://127.0.0.1:5000"},
		{id: "proxy3", address: ":8083", backendURL: "http://127.0.0.1:5000"},
		{id: "proxy4", address: ":8084", backendURL: "http://127.0.0.1:5000"},
	}

	// Start individual proxies
	for _, config := range proxyConfigs {
		go StartProxyServer(config.id, config.address, config.backendURL)
	}

	// List of proxy URLs
	proxyURLs := []string{
		"https://localhost:8081",
		"https://localhost:8082",
		"https://localhost:8083",
		"https://localhost:8084",
	}

	// Initialize ProxyManager and SuspiciousRating
	proxyManager := NewProxyManager(proxyURLs)
	suspiciousRating := NewSuspiciousRating("localhost:6379", 20)

	// Handle incoming requests
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		//if r.TLS == nil { // Vérifie si la requête est en HTTP (non-HTTPS)
		//	http.Redirect(w, r, "https://"+r.Host+r.RequestURI, http.StatusMovedPermanently)
		//	return
		//}

		ip := r.RemoteAddr
		if suspiciousRating.DetectAttack(r) {
			suspiciousRating.UpdateRating(ip, 5)
		}
		rating := suspiciousRating.GetRating(ip)
		if rating > suspiciousRating.maxSuspicion {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		suspiciousRating.UpdateRating(ip, 1)
		proxyManager.ServeHTTP(w, r)
	})

	// Handle blocked users
	http.HandleFunc("/blocked_users", func(w http.ResponseWriter, r *http.Request) {
		blockedUsers, err := suspiciousRating.client.SMembers(ctx, "blocked_users").Result()
		if err != nil {
			http.Error(w, "Error retrieving blocked users", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(blockedUsers)
	})

	// Start the main server
	server := &http.Server{
		Addr:         ":443",           // Port d'écoute
		Handler:      nil,              // Gestionnaire de requêtes (nil utilise http.DefaultServeMux)
		ReadTimeout:  10 * time.Second, // Timeout pour lire la requête
		WriteTimeout: 10 * time.Second, // Timeout pour envoyer la réponse
		IdleTimeout:  60 * time.Second, // Timeout pour les connexions inactives
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	// Serveur HTTP pour rediriger vers HTTPS
	log.Println("Starting HTTP to HTTPS redirect server on :80")
	server.ListenAndServeTLS("server.crt", "server.key")
}
