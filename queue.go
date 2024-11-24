package main

import (
	"context"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
)

type Queue struct {
	client *redis.Client
	stream string
	group  string
}

func NewQueue(addr, stream, group string) *Queue {
	client := redis.NewClient(&redis.Options{
		Addr: addr,
	})

	return &Queue{
		client: client,
		stream: stream,
		group:  group,
	}
}

func (q *Queue) AddToQueue(data map[string]interface{}) error {
	ctx := context.Background()
	_, err := q.client.XAdd(ctx, &redis.XAddArgs{
		Stream: q.stream,
		Values: data,
	}).Result()
	return err
}

func (q *Queue) ConsumeFromQueue(consumer string, count int64, block time.Duration) ([]redis.XMessage, error) {
	ctx := context.Background()
	streams, err := q.client.XReadGroup(ctx, &redis.XReadGroupArgs{
		Group:    q.group,
		Consumer: consumer,
		Streams:  []string{q.stream, ">"},
		Count:    count,
		Block:    block,
	}).Result()
	if err != nil {
		return nil, err
	}
	if len(streams) > 0 {
		return streams[0].Messages, nil
	}
	return nil, nil
}

func (q *Queue) AckMessage(id string) error {
	ctx := context.Background()
	_, err := q.client.XAck(ctx, q.stream, q.group, id).Result()
	return err
}

func ensureQueueSetup(queue *Queue) error {
	ctx := context.Background()

	// Créer le groupe si nécessaire
	err := queue.client.XGroupCreateMkStream(ctx, "proxy_requests", "proxy_group", "$").Err()
	if err != nil && err.Error() != "BUSYGROUP Consumer Group name already exists" {
		return fmt.Errorf("failed to create group: %v", err)
	}

	// Vérifier si le stream contient des messages
	count, err := queue.client.XLen(ctx, "proxy_requests").Result()
	if err != nil {
		return fmt.Errorf("failed to check stream length: %v", err)
	}
	if count == 0 {
		_, err = queue.client.XAdd(ctx, &redis.XAddArgs{
			Stream: "proxy_requests",
			Values: map[string]interface{}{"init": "true"},
		}).Result()
		if err != nil {
			return fmt.Errorf("failed to add initial message to stream: %v", err)
		}
	}

	return nil
}

func addTestMessage(queue *Queue) {
	ctx := context.Background()
	_, err := queue.client.XAdd(ctx, &redis.XAddArgs{
		Stream: "proxy_requests",
		Values: map[string]interface{}{
			"init": "true",
		},
	}).Result()
	if err != nil {
		logWarning("Failed to add test message: %v", err)
	} else {
		logInfo("Test message added to queue")
	}
}
