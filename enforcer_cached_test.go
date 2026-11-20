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
	"strings"
	"sync"
	"testing"

	"github.com/casbin/casbin/v3/persist/cache"
)

type countingCacheableParam struct {
	key   string
	calls int
}

func (p *countingCacheableParam) GetCacheKey() string {
	p.calls++
	return p.key
}

func TestGetCacheKey(t *testing.T) {
	long := strings.Repeat("x", 100)
	for _, tc := range []struct {
		name   string
		params []interface{}
		key    string
		ok     bool
	}{
		{"empty", nil, "", true},
		{"strings", []interface{}{"alice", "data1", "read"}, "s5:alices5:data1s4:read", true},
		{"utf8 and delimiters", []interface{}{"", "é", "a:b", "a\x00b"}, "s0:s2:és3:a:bs3:a\x00b", true},
		{"three digit length", []interface{}{long}, "s100:" + long, true},
		{"enforce context", []interface{}{EnforceContext{RType: "r2", PType: "p", EType: "e", MType: "m2"}, "alice"}, "c25:EnforceContext{r2-p-e-m2}s5:alice", true},
		{"many params", []interface{}{"a", "b", "c", "d", "e", "f", "g", "h", "i"}, "s1:as1:bs1:cs1:ds1:es1:fs1:gs1:hs1:i", true},
		{"unsupported", []interface{}{"alice", 42}, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, ok := GetCacheKey(tc.params...)
			if key != tc.key || ok != tc.ok {
				t.Errorf("GetCacheKey() = %q, %t, supposed to be %q, %t", key, ok, tc.key, tc.ok)
			}
		})
	}

	param := &countingCacheableParam{key: "data1"}
	key, ok := GetCacheKey("alice", param, "read")
	if !ok || key != "s5:alicec5:data1s4:read" || param.calls != 1 {
		t.Errorf("GetCacheKey() = %q, %t with %d GetCacheKey calls", key, ok, param.calls)
	}
	if stringKey, _ := GetCacheKey("alice", "data1", "read"); stringKey == key {
		t.Errorf("string and CacheableParam parts share the key %q", key)
	}
}

func testEnforceCache(t *testing.T, e *CachedEnforcer, sub string, obj interface{}, act string, res bool) {
	t.Helper()
	if myRes, _ := e.Enforce(sub, obj, act); myRes != res {
		t.Errorf("%s, %v, %s: %t, supposed to be %t", sub, obj, act, myRes, res)
	}
}

func TestCache(t *testing.T) {
	e, _ := NewCachedEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
	// The cache is enabled by default for NewCachedEnforcer.

	testEnforceCache(t, e, "alice", "data1", "read", true)
	testEnforceCache(t, e, "alice", "data1", "write", false)
	testEnforceCache(t, e, "alice", "data2", "read", false)
	testEnforceCache(t, e, "alice", "data2", "write", false)

	// The cache is enabled, calling RemovePolicy, LoadPolicy or RemovePolicies will
	// also operate cached items.
	_, _ = e.RemovePolicy("alice", "data1", "read")

	testEnforceCache(t, e, "alice", "data1", "read", false)
	testEnforceCache(t, e, "alice", "data1", "write", false)
	testEnforceCache(t, e, "alice", "data2", "read", false)
	testEnforceCache(t, e, "alice", "data2", "write", false)

	e, _ = NewCachedEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")

	testEnforceCache(t, e, "alice", "data1", "read", true)
	testEnforceCache(t, e, "bob", "data2", "write", true)
	testEnforceCache(t, e, "alice", "data2", "read", true)
	testEnforceCache(t, e, "alice", "data2", "write", true)

	_, _ = e.RemovePolicies([][]string{
		{"alice", "data1", "read"},
		{"bob", "data2", "write"},
	})

	testEnforceCache(t, e, "alice", "data1", "read", false)
	testEnforceCache(t, e, "bob", "data2", "write", false)
	testEnforceCache(t, e, "alice", "data2", "read", true)
	testEnforceCache(t, e, "alice", "data2", "write", true)

	e, _ = NewCachedEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")
	testEnforceCache(t, e, "alice", "data1", "read", true)
	testEnforceCache(t, e, "bob", "data2", "write", true)
	testEnforceCache(t, e, "alice", "data2", "read", true)
	testEnforceCache(t, e, "alice", "data2", "write", true)

	e.ClearPolicy()

	testEnforceCache(t, e, "alice", "data1", "read", false)
	testEnforceCache(t, e, "bob", "data2", "write", false)
	testEnforceCache(t, e, "alice", "data2", "read", false)
	testEnforceCache(t, e, "alice", "data2", "write", false)
}

func TestCacheConcurrentEnforce(t *testing.T) {
	defaultCache, _ := cache.NewDefaultCache()
	for _, tc := range []struct {
		name  string
		cache cache.Cache
	}{
		{"concurrent cache", nil},
		{"cache not safe for concurrent use", defaultCache},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, _ := NewCachedEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")
			if tc.cache != nil {
				e.SetCache(tc.cache)
			}

			enforceConcurrently := func(want bool) {
				t.Helper()
				var wg sync.WaitGroup
				for i := 0; i < 16; i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						for j := 0; j < 200; j++ {
							if res, _ := e.Enforce("alice", "data1", "read"); res != want {
								t.Errorf("alice, data1, read: %t, supposed to be %t", res, want)
								return
							}
							if res, _ := e.Enforce("alice", "data2", "write"); !res {
								t.Error("alice, data2, write: false, supposed to be true")
								return
							}
						}
					}()
				}
				wg.Wait()
			}

			enforceConcurrently(true)
			_, _ = e.RemovePolicy("alice", "data1", "read")
			enforceConcurrently(false)
		})
	}
}
