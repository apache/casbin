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

package util

import (
	"fmt"
	"testing"
)

func TestPatternCacheBounded(t *testing.T) {
	SetPatternCacheSize(5)
	defer SetPatternCacheSize(DefaultPatternCacheSize)

	var c patternCache
	for i := 0; i < 8; i++ {
		key2 := fmt.Sprintf("/team%d/:id", i)
		p := c.get(key2, buildKeyMatch2)
		if matched, err := p.match(fmt.Sprintf("/team%d/42", i)); err != nil || !matched {
			t.Errorf("%s should match /team%d/42", key2, i)
		}
		if n := c.len(); n > 5 {
			t.Fatalf("pattern cache holds %d entries, exceeds the limit of 5", n)
		}
	}
	// The cache was emptied when the sixth pattern arrived.
	if n := c.len(); n != 3 {
		t.Errorf("pattern cache holds %d entries, want 3", n)
	}
	if _, ok := c.m.Load("/team0/:id"); ok {
		t.Error("the first pattern should have been dropped when the cache was full")
	}

	// A pattern looked up again is served from the cache without growing it.
	c.get("/team7/:id", buildKeyMatch2)
	if n := c.len(); n != 3 {
		t.Errorf("pattern cache holds %d entries after a repeated lookup, want 3", n)
	}

	SetPatternCacheSize(0)
	var unbounded patternCache
	for i := 0; i < 100; i++ {
		unbounded.get(fmt.Sprintf("team%d.*", i), buildRegexMatch)
	}
	if n := unbounded.len(); n != 100 {
		t.Errorf("unbounded pattern cache holds %d entries, want 100", n)
	}
}
