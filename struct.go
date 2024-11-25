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
	Action      string
	Header      string
	Value       string
	Regex       string
	Replacement string
}
type HeaderRulesConfig struct {
	HeaderRules []HeaderRule `yaml:"header_rules"`
}
