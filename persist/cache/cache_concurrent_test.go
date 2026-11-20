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
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestConcurrentCache(t *testing.T) {
	c, _ := NewConcurrentCache(10)

	if _, err := c.Get("a"); err != ErrNoSuchKey {
		t.Fatalf("Get on an empty cache: got %v, want ErrNoSuchKey", err)
	}

	_ = c.Set("a", true)
	_ = c.Set("b", false)
	if res, err := c.Get("a"); err != nil || !res {
		t.Errorf("Get(a) = %v, %v, want true, nil", res, err)
	}
	if res, err := c.Get("b"); err != nil || res {
		t.Errorf("Get(b) = %v, %v, want false, nil", res, err)
	}

	_ = c.Set("a", false)
	if res, _ := c.Get("a"); res {
		t.Error("Set on an existing key should overwrite its value")
	}
	if n := c.(*ConcurrentCache).Len(); n != 2 {
		t.Errorf("Len() = %d, want 2", n)
	}

	if err := c.Delete("a"); err != nil {
		t.Errorf("Delete(a) = %v", err)
	}
	if err := c.Delete("a"); err != ErrNoSuchKey {
		t.Errorf("Delete of a missing key = %v, want ErrNoSuchKey", err)
	}

	_ = c.Clear()
	if _, err := c.Get("b"); err != ErrNoSuchKey {
		t.Error("Clear should remove every key")
	}
	if n := c.(*ConcurrentCache).Len(); n != 0 {
		t.Errorf("Len() after Clear = %d, want 0", n)
	}
}

func TestConcurrentCacheExpire(t *testing.T) {
	c, _ := NewConcurrentCache(10)
	_ = c.Set("a", true, time.Millisecond)
	_ = c.Set("b", true, time.Duration(0))
	time.Sleep(2 * time.Millisecond)
	if _, err := c.Get("a"); err != ErrNoSuchKey {
		t.Error("an expired key should not be returned")
	}
	if res, err := c.Get("b"); err != nil || !res {
		t.Error("a key with zero survival time should never expire")
	}
}

func TestConcurrentCacheBounded(t *testing.T) {
	c, _ := NewConcurrentCache(5)
	for i := 0; i < 8; i++ {
		_ = c.Set(fmt.Sprintf("key%d", i), true)
		if n := c.(*ConcurrentCache).Len(); n > 5 {
			t.Fatalf("Len() = %d, exceeds the limit of 5", n)
		}
	}
	// The cache was emptied when key5 was added, so it holds key5..key7.
	if _, err := c.Get("key0"); err != ErrNoSuchKey {
		t.Error("key0 should have been dropped when the cache was full")
	}
	if res, err := c.Get("key7"); err != nil || !res {
		t.Error("the newest key should be cached")
	}

	unbounded, _ := NewConcurrentCache(0)
	for i := 0; i < 100; i++ {
		_ = unbounded.Set(fmt.Sprintf("key%d", i), true)
	}
	if n := unbounded.(*ConcurrentCache).Len(); n != 100 {
		t.Errorf("Len() of an unbounded cache = %d, want 100", n)
	}
}

func TestConcurrentCacheParallel(t *testing.T) {
	c, _ := NewConcurrentCache(16)
	var wg sync.WaitGroup
	for g := 0; g < 32; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				key := fmt.Sprintf("key%d", (g+i)%40)
				if _, err := c.Get(key); err == ErrNoSuchKey {
					_ = c.Set(key, true)
				}
				if i%100 == 0 {
					_ = c.Delete(key)
				}
			}
		}(g)
	}
	wg.Wait()
	if n := c.(*ConcurrentCache).Len(); n > 16 || n < 0 {
		t.Errorf("Len() = %d, want between 0 and 16", n)
	}
}
