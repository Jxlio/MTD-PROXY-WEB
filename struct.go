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
