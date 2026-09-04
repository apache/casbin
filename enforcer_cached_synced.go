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
	"sync"
	"sync/atomic"
	"time"

	"github.com/casbin/casbin/v3/persist/cache"
)

// SyncedCachedEnforcer wraps Enforcer and provides decision sync cache.
type SyncedCachedEnforcer struct {
	*SyncedEnforcer
	expireTime  time.Duration
	cache       cache.Cache
	enableCache int32
	locker      *sync.RWMutex
}

// NewSyncedCachedEnforcer creates a sync cached enforcer via file or DB.
func NewSyncedCachedEnforcer(params ...interface{}) (*SyncedCachedEnforcer, error) {
	e := &SyncedCachedEnforcer{}
	var err error
	e.SyncedEnforcer, err = NewSyncedEnforcer(params...)
	if err != nil {
		return nil, err
	}

	e.enableCache = 1
	e.cache, _ = cache.NewSyncCache()
	e.locker = new(sync.RWMutex)
	return e, nil
}

// EnableCache determines whether to enable cache on Enforce(). When enableCache is enabled, cached result (true | false) will be returned for previous decisions.
func (e *SyncedCachedEnforcer) EnableCache(enableCache bool) {
	var enabled int32
	if enableCache {
		enabled = 1
	}
	atomic.StoreInt32(&e.enableCache, enabled)
}

// Enforce decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (sub, obj, act).
// if rvals is not string , ignore the cache.
func (e *SyncedCachedEnforcer) Enforce(rvals ...interface{}) (bool, error) {
	if atomic.LoadInt32(&e.enableCache) == 0 {
		return e.SyncedEnforcer.Enforce(rvals...)
	}

	key, ok := e.getKey(rvals...)
	if !ok {
		return e.SyncedEnforcer.Enforce(rvals...)
	}

	if res, err := e.getCachedResult(key); err == nil {
		return res, nil
	} else if err != cache.ErrNoSuchKey {
		return res, err
	}

	res, err := e.SyncedEnforcer.Enforce(rvals...)
	if err != nil {
		return false, err
	}

	err = e.setCachedResult(key, res, e.expireTime)
	return res, err
}

func (e *SyncedCachedEnforcer) LoadPolicy() error {
	if atomic.LoadInt32(&e.enableCache) != 0 {
		if err := e.cache.Clear(); err != nil {
			return err
		}
	}
	return e.SyncedEnforcer.LoadPolicy()
}

func (e *SyncedCachedEnforcer) AddPolicy(params ...interface{}) (bool, error) {
	if ok, err := e.checkOneAndRemoveCache(params...); !ok {
		return ok, err
	}
	return e.SyncedEnforcer.AddPolicy(params...)
}

func (e *SyncedCachedEnforcer) AddPolicies(rules [][]string) (bool, error) {
	if ok, err := e.checkManyAndRemoveCache(rules); !ok {
		return ok, err
	}
	return e.SyncedEnforcer.AddPolicies(rules)
}

func (e *SyncedCachedEnforcer) RemovePolicy(params ...interface{}) (bool, error) {
	if ok, err := e.checkOneAndRemoveCache(params...); !ok {
		return ok, err
	}
	return e.SyncedEnforcer.RemovePolicy(params...)
}

func (e *SyncedCachedEnforcer) RemovePolicies(rules [][]string) (bool, error) {
	if ok, err := e.checkManyAndRemoveCache(rules); !ok {
		return ok, err
	}
	return e.SyncedEnforcer.RemovePolicies(rules)
}

func (e *SyncedCachedEnforcer) getCachedResult(key string) (res bool, err error) {
	return e.cache.Get(key)
}

func (e *SyncedCachedEnforcer) SetExpireTime(expireTime time.Duration) {
	e.locker.Lock()
	defer e.locker.Unlock()
	e.expireTime = expireTime
}

// SetCache need to be sync cache.
func (e *SyncedCachedEnforcer) SetCache(c cache.Cache) {
	e.locker.Lock()
	defer e.locker.Unlock()
	e.cache = c
}

func (e *SyncedCachedEnforcer) setCachedResult(key string, res bool, extra ...interface{}) error {
	return e.cache.Set(key, res, extra...)
}

func (e *SyncedCachedEnforcer) getKey(params ...interface{}) (string, bool) {
	return GetCacheKey(params...)
}

// InvalidateCache deletes all the existing cached decisions.
func (e *SyncedCachedEnforcer) InvalidateCache() error {
	return e.cache.Clear()
}

func (e *SyncedCachedEnforcer) checkOneAndRemoveCache(params ...interface{}) (bool, error) {
	if atomic.LoadInt32(&e.enableCache) != 0 {
		key, ok := e.getKey(params...)
		if ok {
			if err := e.cache.Delete(key); err != nil && err != cache.ErrNoSuchKey {
				return false, err
			}
		}
	}
	return true, nil
}

func (e *SyncedCachedEnforcer) checkManyAndRemoveCache(rules [][]string) (bool, error) {
	if len(rules) != 0 {
		if atomic.LoadInt32(&e.enableCache) != 0 {
			for _, rule := range rules {
				irule := make([]interface{}, len(rule))
				for i, param := range rule {
					irule[i] = param
				}
				key, _ := e.getKey(irule...)
				if err := e.cache.Delete(key); err != nil && err != cache.ErrNoSuchKey {
					return false, err
				}
			}
		}
	}
	return true, nil
}
