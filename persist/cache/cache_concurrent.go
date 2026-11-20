// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package cache

import (
	"sync"
	"time"
)

// DefaultConcurrentCacheSize is the number of decisions a cached enforcer keeps by default.
const DefaultConcurrentCacheSize = 100000

// ConcurrentCache is a bounded Cache that is safe for concurrent use. Get does not
// take a lock, so concurrent lookups of cached decisions do not wait on each other.
//
// There is no access order to evict by: when the cache is full, adding a new key
// empties it first. An expired item stays until it is overwritten or the cache is
// emptied.
type ConcurrentCache struct {
	items      sync.Map // string -> cacheItem
	mu         sync.Mutex
	size       int
	maxEntries int
}

// NewConcurrentCache creates a ConcurrentCache that holds at most maxEntries keys.
// A maxEntries of zero or less means no limit.
func NewConcurrentCache(maxEntries int) (Cache, error) {
	return &ConcurrentCache{maxEntries: maxEntries}, nil
}

func (c *ConcurrentCache) Set(key string, value bool, extra ...interface{}) error {
	ttl := time.Duration(-1)
	if len(extra) > 0 {
		ttl = extra[0].(time.Duration)
	}
	item := cacheItem{
		value:     value,
		expiresAt: time.Now().Add(ttl),
		ttl:       ttl,
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.items.Load(key); !ok {
		if c.maxEntries > 0 && c.size >= c.maxEntries {
			c.clearLocked()
		}
		c.size++
	}
	c.items.Store(key, item)
	return nil
}

func (c *ConcurrentCache) Get(key string) (bool, error) {
	v, ok := c.items.Load(key)
	if !ok {
		return false, ErrNoSuchKey
	}
	item := v.(cacheItem)
	if item.ttl > 0 && time.Now().After(item.expiresAt) {
		return false, ErrNoSuchKey
	}
	return item.value, nil
}

func (c *ConcurrentCache) Delete(key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.items.Load(key); !ok {
		return ErrNoSuchKey
	}
	c.items.Delete(key)
	c.size--
	return nil
}

func (c *ConcurrentCache) Clear() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.clearLocked()
	return nil
}

func (c *ConcurrentCache) clearLocked() {
	c.items.Range(func(key, _ interface{}) bool {
		c.items.Delete(key)
		return true
	})
	c.size = 0
}

// Len returns the number of keys in the cache, including expired ones not yet removed.
func (c *ConcurrentCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.size
}
