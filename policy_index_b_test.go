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
	"fmt"
	"testing"
)

func BenchmarkPolicyIndex(b *testing.B) {
	const (
		typeCount = 100
		perType   = 100
	)

	e, _ := newIndexTestEnforcer(b, "some(where (p.eft == allow)) && !some(where (p.eft == deny))", false)

	rules := make([][]string, 0, typeCount*perType)
	for typeIndex := 0; typeIndex < typeCount; typeIndex++ {
		objType := fmt.Sprintf("type%d", typeIndex)
		for objIndex := 0; objIndex < perType; objIndex++ {
			rules = append(rules, []string{"alice", objType, fmt.Sprintf("obj%d", objIndex), "read"})
		}
	}
	if _, err := e.AddPolicies(rules); err != nil {
		b.Fatal(err)
	}

	request := []interface{}{"alice", "type50", "obj50", "read"}

	b.Run("unindexed", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if ok, err := e.Enforce(request...); err != nil || !ok {
				b.Fatal(ok, err)
			}
		}
	})

	setObjectTypeIndex(b, e)

	b.Run("indexed", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if ok, err := e.Enforce(request...); err != nil || !ok {
				b.Fatal(ok, err)
			}
		}
	})
}
