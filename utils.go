package main

import (
	"bytes"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/go-redis/redis/v8"
)

var redisClient *redis.Client
var currentProxyURL string

func getServerIPAddress() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Fatalf("Failed to get network interfaces: %v", err)
	}

	for _, addr := range addrs {
		// Vérifie si l'adresse est une IP valide (non loopback)
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			if ipNet.IP.To4() != nil { // Filtre uniquement les adresses IPv4
				return ipNet.IP.String()
			}
		}
	}

	log.Fatalf("No valid IP address found")
	return ""
}

// StartProxyServer starts a proxy server on the given address and forwards requests to the backendURL.
func StartProxyServer(proxyID, address, backendURL string) {
	parsedURL, err := url.Parse(backendURL)
	if err != nil {
		log.Fatalf("Failed to parse backend URL: %v", err)
	}

	redisClient = redis.NewClient(&redis.Options{
		Addr: "localhost:6379", // Adresse de Redis
	})

	proxy := httputil.NewSingleHostReverseProxy(parsedURL)

	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Header.Add("X-Proxy-ID", proxyID)
	}

	proxy.ModifyResponse = func(resp *http.Response) error {
		if strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return err
			}
			resp.Body.Close()

			// Modify resource links
			modifiedBody := bytes.Replace(body, []byte("src=\""), []byte("src=\""+parsedURL.Scheme+"://"+parsedURL.Host+"/"), -1)

			// Inject script
			modifiedBody = bytes.Replace(modifiedBody, []byte("</body>"), []byte("<script>s\n"+
				"(function() {\n"+
				"console.log('Script exécuté après le chargement de la page.');\n"+
				"const newProxy = \""+getNewProxyURL()+"\";\n"+
				"window.location.replace(newProxy + window.location.pathname + '?_=' + new Date().getTime());\n"+
				"})();\n"+
				"</script></body>"), 1)

			resp.Body = io.NopCloser(bytes.NewReader(modifiedBody))
			resp.ContentLength = int64(len(modifiedBody))
			resp.Header.Set("Content-Length", strconv.Itoa(len(modifiedBody)))
		}
		return nil
	}

	var requestCounts = make(map[string]int)
	var mu sync.Mutex
	mux := http.NewServeMux()

	// Route pour vérifier la santé du proxy
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Proxy is healthy"))
	})

	activeProxy, err := redisClient.Get(ctx, "active_proxy").Result()
	if err != nil {
		log.Printf("Failed to get active proxy: %v", err)
		activeProxy = "https://localhost" // Valeur par défaut
	}
	currentProxyURL = activeProxy // Initialisez la variable globale

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		ip := r.RemoteAddr // ou r.Header.Get("X-Forwarded-For") si vous utilisez un proxy
		requestCounts[ip]++

		if requestCounts[ip] > 500 {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		log.Printf("%s received a request", proxyID)

		activeProxy, err := redisClient.Get(ctx, "active_proxy").Result()
		if err != nil {
			log.Printf("Failed to get active proxy: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Comparer le proxy actif avec l'ID actuel
		if "https://"+r.Host != activeProxy {
			log.Printf("Request to proxy %s is blocked. Active proxy is %s", r.Host, activeProxy)
			http.Redirect(w, r, activeProxy+r.RequestURI, http.StatusFound)
			return
		}

		// Récupérer le corps de la requête
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusInternalServerError)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

		// Préparer les données pour la détection
		detectionData := map[string]interface{}{
			"uri":  r.RequestURI,
			"body": string(bodyBytes),
		}
		detectionResponse, err := sendToDetectionService(detectionData)
		if err != nil {
			http.Error(w, "Failed to connect to detection service", http.StatusInternalServerError)
			return
		}

		if detectionResponse["authorized"] == "MALICIOUS" {
			htmlContent, err := os.ReadFile("403.html")
			if err != nil {
				http.Error(w, "Failed to load 403 page", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusForbidden)
			w.Write(htmlContent)
			return
		}
		proxy.ServeHTTP(w, r)
	})

	go func() {
		pubsub := redisClient.Subscribe(ctx, "proxy_updates")
		defer pubsub.Close()

		for msg := range pubsub.Channel() {
			log.Printf("Received new proxy update: %s", msg.Payload)
			currentProxyURL = msg.Payload
		}
	}()

	server := &http.Server{
		Addr:    "0.0.0.0" + address,
		Handler: mux,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	log.Printf("Starting HTTPS proxy server %s on %s", proxyID, address)
	server.ListenAndServeTLS("server.crt", "server.key")
}
