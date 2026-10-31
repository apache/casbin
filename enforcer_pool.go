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

package casbin

import (
	"container/list"
	"errors"
	"sync"

	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist"
)

// EnforcerFactory creates an enforcer for a cache entry. It is called only on
// a cache miss. The enforcer is shared by every caller that uses the same key,
// so it must be safe for concurrent use.
type EnforcerFactory func(key string, filter interface{}) (*SyncedEnforcer, error)

// EnforcerPool caches enforcers by key and bounds the cache with an LRU.
// It is intended for applications that would otherwise create a filtered
// enforcer for every request, for example one enforcer per tenant.
//
// The key must uniquely identify the filter: a cache hit returns the cached
// enforcer without calling the factory, even if a different filter is passed.
// Call Invalidate after a policy change that was not made through the cached
// enforcer, and call InvalidateAll from a watcher callback to drop enforcers
// built from a stale policy.
type EnforcerPool struct {
	mu         sync.Mutex
	factory    EnforcerFactory
	maxSize    int
	generation uint64
	enforcers  map[string]*enforcerPoolEntry
	lru        *list.List
}

type enforcerPoolEntry struct {
	enforcer *SyncedEnforcer
	elem     *list.Element
}

var (
	errNilEnforcerFactory = errors.New("casbin: nil enforcer factory")
	errNilEnforcer        = errors.New("casbin: enforcer factory returned nil")
	errNilAdapterFactory  = errors.New("casbin: nil adapter factory")
)

// NewEnforcerPool creates a pool that keeps at most maxSize enforcers.
// A maxSize of zero or less means no limit.
func NewEnforcerPool(factory EnforcerFactory, maxSize int) *EnforcerPool {
	return &EnforcerPool{
		factory:   factory,
		maxSize:   maxSize,
		enforcers: make(map[string]*enforcerPoolEntry),
		lru:       list.New(),
	}
}

// NewFilteredEnforcerPool creates a pool that builds one filtered enforcer per
// key. newAdapter is called once per enforcer, so adapters that keep filter
// state are not shared. The filter passed to Get must be the type the adapter
// expects.
func NewFilteredEnforcerPool(modelPath string, newAdapter func() persist.FilteredAdapter, maxSize int) *EnforcerPool {
	return NewEnforcerPool(func(key string, filter interface{}) (*SyncedEnforcer, error) {
		if newAdapter == nil {
			return nil, errNilAdapterFactory
		}

		m, err := model.NewModelFromFile(modelPath)
		if err != nil {
			return nil, err
		}

		e, err := NewSyncedEnforcer(m)
		if err != nil {
			return nil, err
		}

		e.SetAdapter(newAdapter())
		if err := e.LoadFilteredPolicy(filter); err != nil {
			return nil, err
		}

		return e, nil
	}, maxSize)
}

// Get returns the cached enforcer for key, calling the factory on a cache
// miss. filter is passed to the factory unchanged.
func (p *EnforcerPool) Get(key string, filter interface{}) (*SyncedEnforcer, error) {
	if p.factory == nil {
		return nil, errNilEnforcerFactory
	}

	for {
		p.mu.Lock()
		p.initLocked()
		if entry, ok := p.enforcers[key]; ok {
			p.lru.MoveToFront(entry.elem)
			e := entry.enforcer
			p.mu.Unlock()
			return e, nil
		}
		generation := p.generation
		p.mu.Unlock()

		e, err := p.factory(key, filter)
		if err != nil {
			return nil, err
		}
		if e == nil {
			return nil, errNilEnforcer
		}

		p.mu.Lock()
		// The policy changed while the factory was loading, so the enforcer
		// may have been built from stale data. Build it again.
		if generation != p.generation {
			p.mu.Unlock()
			continue
		}
		if entry, ok := p.enforcers[key]; ok {
			p.lru.MoveToFront(entry.elem)
			e = entry.enforcer
			p.mu.Unlock()
			return e, nil
		}

		entry := &enforcerPoolEntry{enforcer: e}
		entry.elem = p.lru.PushFront(key)
		p.enforcers[key] = entry
		p.evictLocked()
		p.mu.Unlock()
		return e, nil
	}
}

// Invalidate drops the enforcer cached for key.
func (p *EnforcerPool) Invalidate(key string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.initLocked()
	p.generation++
	if entry, ok := p.enforcers[key]; ok {
		delete(p.enforcers, key)
		p.lru.Remove(entry.elem)
	}
}

// InvalidateAll drops every cached enforcer.
func (p *EnforcerPool) InvalidateAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.initLocked()
	p.generation++
	p.enforcers = make(map[string]*enforcerPoolEntry)
	p.lru.Init()
}

// OnUpdate invalidates every cached enforcer. Its signature matches the
// callback passed to persist.Watcher.SetUpdateCallback.
func (p *EnforcerPool) OnUpdate(string) {
	p.InvalidateAll()
}

// Len returns the number of cached enforcers.
func (p *EnforcerPool) Len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.enforcers)
}

func (p *EnforcerPool) initLocked() {
	if p.enforcers == nil {
		p.enforcers = make(map[string]*enforcerPoolEntry)
	}
	if p.lru == nil {
		p.lru = list.New()
	}
}

func (p *EnforcerPool) evictLocked() {
	if p.maxSize <= 0 {
		return
	}
	for len(p.enforcers) > p.maxSize {
		back := p.lru.Back()
		if back == nil {
			return
		}
		delete(p.enforcers, back.Value.(string))
		p.lru.Remove(back)
	}
}
