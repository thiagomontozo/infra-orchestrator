package cache

import (
	"context"
	"github.com/redis/go-redis/v9"
	"time"
)

type Limiter interface {
	Allow(context.Context, string, int, time.Duration) (bool, error)
}
type Redis struct{ Client *redis.Client }

func New(raw string) (*Redis, error) {
	o, e := redis.ParseURL(raw)
	if e != nil {
		return nil, e
	}
	o.DialTimeout = 3 * time.Second
	o.ReadTimeout = 3 * time.Second
	o.WriteTimeout = 3 * time.Second
	return &Redis{redis.NewClient(o)}, nil
}
func (r *Redis) Allow(ctx context.Context, key string, max int, window time.Duration) (bool, error) {
	n, e := r.Client.Eval(ctx, `local n=redis.call('INCR',KEYS[1]); if n==1 then redis.call('PEXPIRE',KEYS[1],ARGV[1]) end; return n`, []string{"infra:limit:" + key}, window.Milliseconds()).Int()
	return n <= max, e
}
