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

	"github.com/casbin/casbin/v3/model"
)

var reviewCacheKeySink string

func BenchmarkReviewCacheKey(b *testing.B) {
	for _, tc := range []struct {
		name string
		args []interface{}
	}{
		{"route", []interface{}{"alice", "/v1/users/42", "GET"}},
		{"domain", []interface{}{"alice", "tenant-123", "/v1/users/42", "GET"}},
		{"long", []interface{}{"alice", strings.Repeat("x", 160), "GET"}},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				reviewCacheKeySink, _ = GetCacheKey(tc.args...)
			}
		})
	}
}

const reviewCacheModel = `
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`

func BenchmarkReviewSyncedCacheHit(b *testing.B) {
	m, err := model.NewModelFromString(reviewCacheModel)
	if err != nil {
		b.Fatal(err)
	}
	e, err := NewSyncedCachedEnforcer(m)
	if err != nil {
		b.Fatal(err)
	}
	if _, err := e.AddPolicy("alice", "/v1/users/42", "GET"); err != nil {
		b.Fatal(err)
	}
	if ok, err := e.Enforce("alice", "/v1/users/42", "GET"); err != nil || !ok {
		b.Fatal(ok, err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if ok, err := e.Enforce("alice", "/v1/users/42", "GET"); err != nil || !ok {
			b.Fatal(ok, err)
		}
	}
}
