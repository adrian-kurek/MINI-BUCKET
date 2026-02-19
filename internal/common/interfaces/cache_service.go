package interfaces

import (
	"context"
	"time"
)

type CacheService interface {
	GetData(ctx context.Context, key string) (string, error)
	ExistsData(ctx context.Context, key string) (int64, error)
	DeleteData(ctx context.Context, key string) error
	SetData(ctx context.Context, key string, data string, ttl time.Duration) error
}
