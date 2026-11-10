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
	"testing"
)

type reviewCacheable struct {
	calls int
}

func (value *reviewCacheable) GetCacheKey() string {
	value.calls++
	return "name"
}

func TestReviewCacheKeyPreservesEncoding(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []interface{}
		key  string
		ok   bool
	}{
		{"empty request", nil, "", true},
		{"three strings", []interface{}{"alice", "data", "read"}, "s5:alices4:datas4:read", true},
		{"UTF8 and delimiter", []interface{}{"", "é", "a:b"}, "s0:s2:és3:a:b", true},
		{"null byte", []interface{}{"a\x00b"}, "s3:a\x00b", true},
		{"three length digits", []interface{}{strings.Repeat("x", 100)}, "s100:" + strings.Repeat("x", 100), true},
		{"unsupported", []interface{}{"alice", 42}, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, ok := GetCacheKey(tc.args...)
			if key != tc.key || ok != tc.ok {
				t.Fatalf("GetCacheKey = %q, %v; want %q, %v", key, ok, tc.key, tc.ok)
			}
		})
	}
}

func TestReviewCacheKeyCallsCustomKeyOnce(t *testing.T) {
	value := &reviewCacheable{}
	key, ok := GetCacheKey("alice", value, "read")
	if !ok || key != "s5:alicec4:names4:read" || value.calls != 1 {
		t.Fatalf("key = %q, cacheable = %v, calls = %d", key, ok, value.calls)
	}
	stringKey, _ := GetCacheKey("alice", "name", "read")
	if key == stringKey {
		t.Fatal("custom and string arguments must have distinct key namespaces")
	}
}
