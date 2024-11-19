package main

import (
	"net/url"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
)

type ProxyManager struct {
	proxies      []*url.URL
	mu           sync.Mutex
	currentProxy *url.URL
	ticker       *time.Ticker
}

type SuspiciousRating struct {
	client       *redis.Client
	maxSuspicion int
}

type HeaderRule struct {
	Action      string // add-header, set-header, del-header, replace-header
	Header      string // Le nom de l'en-tête ciblé
	Value       string // La valeur pour add-header ou set-header
	Regex       string // Pour replace-header
	Replacement string // Pour replace-header
}
type HeaderRulesConfig struct {
	HeaderRules []HeaderRule `yaml:"header_rules"`
}
