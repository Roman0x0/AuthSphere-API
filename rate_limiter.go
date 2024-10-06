package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type user struct {
	ts     int64
	tokens uint
}

func clearInBackground(data *sync.Map, rate int64) {
	for {
		data.Range(func(k, v interface{}) bool {
			if v.(user).ts+rate <= time.Now().Unix() {
				data.Delete(k)
			}
			return true
		})
		time.Sleep(time.Minute)
	}
}

type inMemoryStoreType struct {
	rate  int64
	limit uint
	data  *sync.Map
	skip  func(ctx *gin.Context) bool
}

func (s *inMemoryStoreType) Limit(key string, c *gin.Context) Info {
	var u user
	m, ok := s.data.Load(key)
	if !ok {
		u = user{time.Now().Unix(), s.limit}
	} else {
		u = m.(user)
	}
	if u.ts+s.rate <= time.Now().Unix() {
		u.tokens = s.limit
	}
	if s.skip != nil && s.skip(c) {
		return Info{
			RateLimited:   false,
			ResetTime:     time.Now().Add(time.Duration((s.rate - (time.Now().Unix() - u.ts)) * time.Second.Nanoseconds())),
			RemainingHits: u.tokens,
		}
	}
	if u.tokens <= 0 {
		return Info{
			RateLimited:   true,
			ResetTime:     time.Now().Add(time.Duration((s.rate - (time.Now().Unix() - u.ts)) * time.Second.Nanoseconds())),
			RemainingHits: 0,
		}
	}
	u.tokens--
	u.ts = time.Now().Unix()
	s.data.Store(key, u)
	return Info{
		RateLimited:   false,
		ResetTime:     time.Now().Add(time.Duration((s.rate - (time.Now().Unix() - u.ts)) * time.Second.Nanoseconds())),
		RemainingHits: u.tokens,
	}
}

type InMemoryOptions struct {
	// the user can make Limit amount of requests every Rate
	Rate time.Duration
	// the amount of requests that can be made every Rate
	Limit uint
	// a function that returns true if the request should not count toward the rate limit
	Skip func(*gin.Context) bool
}

func InMemoryStore(options *InMemoryOptions) Store {
	data := &sync.Map{}
	store := inMemoryStoreType{int64(options.Rate.Seconds()), options.Limit, data, options.Skip}
	go clearInBackground(data, store.rate)
	return &store
}

type Info struct {
	RateLimited   bool
	ResetTime     time.Time
	RemainingHits uint
}

type Store interface {
	// Limit takes in a key and *gin.Context and should return whether that key is allowed to make another request
	Limit(key string, c *gin.Context) Info
}

type Options struct {
	ErrorHandler func(*gin.Context, Info)
	KeyFunc      func(*gin.Context) string
	// a function that lets you check the rate limiting info and modify the response
	BeforeResponse func(c *gin.Context, info Info)
}

// RateLimiter is a function to get gin.HandlerFunc
func RateLimiter(s Store, options *Options) gin.HandlerFunc {
	if options == nil {
		options = &Options{}
	}
	if options.ErrorHandler == nil {
		options.ErrorHandler = func(c *gin.Context, info Info) {
			c.Header("X-Rate-Limit-Reset", fmt.Sprintf("%.2f", time.Until(info.ResetTime).Seconds()))
			c.String(429, "Too many requests")
		}
	}
	if options.BeforeResponse == nil {
		options.BeforeResponse = func(c *gin.Context, info Info) {
			c.Header("X-Rate-Limit-Remaining", fmt.Sprintf("%v", info.RemainingHits))
			c.Header("X-Rate-Limit-Reset", fmt.Sprintf("%.2f", time.Until(info.ResetTime).Seconds()))
		}
	}
	if options.KeyFunc == nil {
		options.KeyFunc = func(c *gin.Context) string {
			return c.ClientIP() + c.FullPath()
		}
	}
	return func(c *gin.Context) {
		key := options.KeyFunc(c)
		info := s.Limit(key, c)
		options.BeforeResponse(c, info)
		if c.IsAborted() {
			return
		}
		if info.RateLimited {
			options.ErrorHandler(c, info)
			c.Abort()
		} else {
			c.Next()
		}
	}
}
