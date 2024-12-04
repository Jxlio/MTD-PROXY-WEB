package main

import (
	"net/url"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-redis/redis/v8"
)

type ProxyManager struct {
	proxies      []*url.URL
	currentProxy *url.URL
	ticker       *time.Ticker
	mu           sync.Mutex
	domain       string
}

type SuspiciousRating struct {
	client       *redis.Client
	maxSuspicion int
}

type HeaderRule struct {
	Action      string
	Header      string
	Value       string
	Regex       string
	Replacement string
}
type HeaderRulesConfig struct {
	HeaderRules []HeaderRule `yaml:"header_rules"`
}

type ACLRule struct {
	Name      string      `yaml:"name"`
	Condition string      `yaml:"condition"`
	Value     interface{} `yaml:"value"`
	Action    string      `yaml:"action"`
	Options   []string    `yaml:"options,omitempty"`
}

type ACLConfig struct {
	mu    sync.RWMutex
	Rules []ACLRule `yaml:"rules"`
}

type Proxy struct {
	ID        string
	URL       *url.URL
	ACLConfig *ACLConfig
}

type Claims struct {
	SessionID string `json:"session_id"`
	jwt.StandardClaims
}
