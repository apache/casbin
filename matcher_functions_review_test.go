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
	"testing"

	"github.com/casbin/casbin/v3/model"
)

func TestReviewEvalUsesCurrentRequest(t *testing.T) {
	m, err := model.NewModelFromString(`
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub_rule, obj, act
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = eval(p.sub_rule) && r.obj == p.obj && r.act == p.act
`)
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewSyncedEnforcer(m)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.AddPolicy(`r.sub == "alice"`, "data", "read"); err != nil {
		t.Fatal(err)
	}
	for _, subject := range []string{"alice", "bob", "alice", "carol"} {
		ok, err := e.Enforce(subject, "data", "read")
		if err != nil || ok != (subject == "alice") {
			t.Fatalf("subject %s: %v, %v", subject, ok, err)
		}
	}
}

func TestReviewMatcherFunctionAfterInvalidation(t *testing.T) {
	m, err := model.NewModelFromString(`
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`)
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewSyncedEnforcer(m)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.AddPolicy("alice", "data", "read"); err != nil {
		t.Fatal(err)
	}
	if ok, err := e.Enforce("alice", "data", "read"); err != nil || !ok {
		t.Fatal(ok, err)
	}
	calls := 0
	e.AddFunction("reviewCheck", func(args ...interface{}) (interface{}, error) {
		calls++
		return args[0] == "alice", nil
	})
	matcher := "reviewCheck(r.sub) && r.obj == p.obj && r.act == p.act"
	for i := 0; i < 2; i++ {
		if ok, err := e.EnforceWithMatcher(matcher, "alice", "data", "read"); err != nil || !ok {
			t.Fatal(ok, err)
		}
	}
	if calls != 2 {
		t.Fatalf("cached matcher must still invoke the function on each decision: calls=%d", calls)
	}
}
