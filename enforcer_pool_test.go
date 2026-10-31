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
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/casbin/casbin/v3/persist"
	fileadapter "github.com/casbin/casbin/v3/persist/file-adapter"
)

func newTestPoolEnforcer() (*SyncedEnforcer, error) {
	return NewSyncedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
}

func TestEnforcerPoolGetCaches(t *testing.T) {
	calls := 0
	pool := NewEnforcerPool(func(key string, filter interface{}) (*SyncedEnforcer, error) {
		calls++
		return newTestPoolEnforcer()
	}, 10)

	e1, err := pool.Get("tenant1", nil)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	e2, err := pool.Get("tenant1", nil)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	if calls != 1 {
		t.Fatalf("factory calls = %d, want 1", calls)
	}
	if e1 != e2 {
		t.Fatal("Get returned different enforcers for the same key")
	}
	if pool.Len() != 1 {
		t.Fatalf("Len = %d, want 1", pool.Len())
	}
}

func TestEnforcerPoolDifferentKeys(t *testing.T) {
	calls := 0
	pool := NewEnforcerPool(func(key string, filter interface{}) (*SyncedEnforcer, error) {
		calls++
		return newTestPoolEnforcer()
	}, 10)

	e1, err := pool.Get("tenant1", nil)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	e2, err := pool.Get("tenant2", nil)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	if calls != 2 {
		t.Fatalf("factory calls = %d, want 2", calls)
	}
	if e1 == e2 {
		t.Fatal("Get returned the same enforcer for different keys")
	}
	if pool.Len() != 2 {
		t.Fatalf("Len = %d, want 2", pool.Len())
	}
}

func TestEnforcerPoolInvalidate(t *testing.T) {
	calls := 0
	pool := NewEnforcerPool(func(key string, filter interface{}) (*SyncedEnforcer, error) {
		calls++
		return newTestPoolEnforcer()
	}, 10)

	e1, err := pool.Get("tenant1", nil)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	pool.Invalidate("tenant1")
	if pool.Len() != 0 {
		t.Fatalf("Len = %d, want 0", pool.Len())
	}

	e2, err := pool.Get("tenant1", nil)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if calls != 2 {
		t.Fatalf("factory calls = %d, want 2", calls)
	}
	if e1 == e2 {
		t.Fatal("Get returned the invalidated enforcer")
	}

	pool.Invalidate("missing")
}

func TestEnforcerPoolInvalidateAll(t *testing.T) {
	calls := 0
	pool := NewEnforcerPool(func(key string, filter interface{}) (*SyncedEnforcer, error) {
		calls++
		return newTestPoolEnforcer()
	}, 10)

	if _, err := pool.Get("tenant1", nil); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if _, err := pool.Get("tenant2", nil); err != nil {
		t.Fatalf("Get: %v", err)
	}

	pool.OnUpdate("policy changed")
	if pool.Len() != 0 {
		t.Fatalf("Len = %d, want 0", pool.Len())
	}

	if _, err := pool.Get("tenant1", nil); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if calls != 3 {
		t.Fatalf("factory calls = %d, want 3", calls)
	}
}

func TestEnforcerPoolLRU(t *testing.T) {
	calls := 0
	pool := NewEnforcerPool(func(key string, filter interface{}) (*SyncedEnforcer, error) {
		calls++
		return newTestPoolEnforcer()
	}, 2)

	get := func(key string) *SyncedEnforcer {
		e, err := pool.Get(key, nil)
		if err != nil {
			t.Fatalf("Get(%q): %v", key, err)
		}
		return e
	}

	get("a")
	get("b")
	get("a")
	get("c")
	get("b")
	get("c")

	if calls != 4 {
		t.Fatalf("factory calls = %d, want 4", calls)
	}
	if pool.Len() != 2 {
		t.Fatalf("Len = %d, want 2", pool.Len())
	}
}

func TestEnforcerPoolUnbounded(t *testing.T) {
	pool := NewEnforcerPool(func(key string, filter interface{}) (*SyncedEnforcer, error) {
		return newTestPoolEnforcer()
	}, 0)

	for i := 0; i < 50; i++ {
		if _, err := pool.Get(strconv.Itoa(i), nil); err != nil {
			t.Fatalf("Get: %v", err)
		}
	}
	if pool.Len() != 50 {
		t.Fatalf("Len = %d, want 50", pool.Len())
	}
}

func TestEnforcerPoolFactoryError(t *testing.T) {
	boom := errors.New("boom")
	calls := 0
	pool := NewEnforcerPool(func(key string, filter interface{}) (*SyncedEnforcer, error) {
		calls++
		return nil, boom
	}, 10)

	if _, err := pool.Get("tenant1", nil); !errors.Is(err, boom) {
		t.Fatalf("Get error = %v, want %v", err, boom)
	}
	if pool.Len() != 0 {
		t.Fatalf("Len = %d, want 0", pool.Len())
	}

	if _, err := pool.Get("tenant1", nil); !errors.Is(err, boom) {
		t.Fatalf("Get error = %v, want %v", err, boom)
	}
	if calls != 2 {
		t.Fatalf("factory calls = %d, want 2", calls)
	}
}

func TestEnforcerPoolNilFactory(t *testing.T) {
	pool := NewEnforcerPool(nil, 10)
	if _, err := pool.Get("tenant1", nil); err != errNilEnforcerFactory {
		t.Fatalf("Get error = %v, want %v", err, errNilEnforcerFactory)
	}
}

func TestEnforcerPoolNilEnforcer(t *testing.T) {
	pool := NewEnforcerPool(func(key string, filter interface{}) (*SyncedEnforcer, error) {
		return nil, nil
	}, 10)
	if _, err := pool.Get("tenant1", nil); err != errNilEnforcer {
		t.Fatalf("Get error = %v, want %v", err, errNilEnforcer)
	}
}

func TestEnforcerPoolConcurrentGet(t *testing.T) {
	pool := NewEnforcerPool(func(key string, filter interface{}) (*SyncedEnforcer, error) {
		return newTestPoolEnforcer()
	}, 10)

	const n = 100
	results := make([]*SyncedEnforcer, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			e, err := pool.Get("tenant1", nil)
			if err != nil {
				t.Errorf("Get: %v", err)
				return
			}
			results[i] = e
		}(i)
	}
	wg.Wait()

	if t.Failed() {
		return
	}
	for i := 1; i < n; i++ {
		if results[i] != results[0] {
			t.Fatalf("Get returned different enforcers for the same key")
		}
	}
	if pool.Len() != 1 {
		t.Fatalf("Len = %d, want 1", pool.Len())
	}
}

func TestEnforcerPoolInvalidateDuringLoad(t *testing.T) {
	var calls int32
	started := make(chan struct{})
	release := make(chan struct{})
	pool := NewEnforcerPool(func(key string, filter interface{}) (*SyncedEnforcer, error) {
		if atomic.AddInt32(&calls, 1) == 1 {
			close(started)
			<-release
		}
		return newTestPoolEnforcer()
	}, 10)

	go func() {
		<-started
		pool.InvalidateAll()
		close(release)
	}()

	if _, err := pool.Get("tenant1", nil); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("factory calls = %d, want 2", got)
	}
	if pool.Len() != 1 {
		t.Fatalf("Len = %d, want 1", pool.Len())
	}
}

func TestNewFilteredEnforcerPool(t *testing.T) {
	pool := NewFilteredEnforcerPool(
		"examples/rbac_with_domains_model.conf",
		func() persist.FilteredAdapter {
			return fileadapter.NewFilteredAdapter("examples/rbac_with_domains_policy.csv")
		},
		10,
	)

	e, err := pool.Get("domain1", &fileadapter.Filter{P: []string{"", "domain1"}})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	policy, err := e.GetPolicy()
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if len(policy) != 2 {
		t.Fatalf("policy length = %d, want 2", len(policy))
	}

	allowed, err := e.Enforce("admin", "domain1", "data1", "read")
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if !allowed {
		t.Fatal("domain1 policy was not loaded")
	}

	allowed, err = e.Enforce("admin", "domain2", "data2", "read")
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if allowed {
		t.Fatal("domain2 policy was loaded by the domain1 enforcer")
	}
}
