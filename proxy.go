package main

import (
	"log"
	"net/url"

	"github.com/go-redis/redis/v8"
	"golang.org/x/exp/rand"
)

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

func getNewProxyURL() string {
	// Retourner le proxy actif actuel
	return currentProxyURL
}


