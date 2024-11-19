package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var ctx = context.Background()

// Metrics for Prometheus monitoring
var (
	proxyRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "proxy_requests_total",
			Help: "Total number of requests handled by each proxy",
		},
		[]string{"proxy_id", "status", "method"},
	)
	proxyRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "proxy_request_duration_seconds",
			Help:    "Histogram of request durations per proxy",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"proxy_id", "method"},
	)
)
var proxySwitchesTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "proxy_switches_total",
		Help: "Total number of proxy switches",
	},
	[]string{"proxy_id"},
)

func init() {
	prometheus.MustRegister(proxyRequestsTotal, proxyRequestDuration)
	prometheus.MustRegister(proxySwitchesTotal)
}

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

// ServeHTTP dynamically proxies the request through one of the managed proxies
func (pm *ProxyManager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	status := "200"

	defer func() {
		duration := time.Since(start).Seconds()
		proxyRequestsTotal.WithLabelValues(status, r.Method).Inc()
		proxyRequestDuration.WithLabelValues(pm.GetProxy().String(), r.Method).Observe(duration)

	}()

	// Obtenir l'URL du proxy actif depuis Redis
	activeProxy, err := pm.GetActiveProxy()
	if err != nil {
		status = "500"
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

func main() {
	serverIP := getServerIPAddress()
	headerRulesFile := flag.String("header-rules", "", "Path to the header rules YAML file")
	flag.Parse()

	// Charger les règles d'en-têtes si le fichier est spécifié
	if *headerRulesFile != "" {
		log.Printf("Loading header rules from %s", *headerRulesFile)
		headerRules = loadHeaderRules(*headerRulesFile)
	} else {
		log.Println("No header rules specified. Header modification is disabled.")
	}
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
		"https://" + serverIP + ":8081",
		"https://" + serverIP + ":8082",
		"https://" + serverIP + ":8083",
		"https://" + serverIP + ":8084",
	}
	// Initialize ProxyManager and SuspiciousRating
	proxyManager := NewProxyManager(proxyURLs)
	suspiciousRating := NewSuspiciousRating("localhost:6379", 20)

	// Setup Prometheus metrics endpoint
	http.Handle("/metrics", promhttp.Handler())

	// Handle incoming requests
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
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
	// Start the main server
	server := &http.Server{
		Addr:         "0.0.0.0:443",    // Port d'écoute
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
