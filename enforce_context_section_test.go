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
	"os"
	"path/filepath"
	"testing"

	"github.com/casbin/casbin/v3/model"
)

func newSectionTestEnforcer(t *testing.T, modelText string, policies [][]string) *Enforcer {
	t.Helper()
	m, err := model.NewModelFromString(modelText)
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewEnforcer(m)
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range policies {
		params := make([]interface{}, len(rule)-1)
		for i, v := range rule[1:] {
			params[i] = v
		}
		if rule[0][0] == 'g' {
			_, err = e.AddNamedGroupingPolicy(rule[0], params...)
		} else {
			_, err = e.AddNamedPolicy(rule[0], params...)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	return e
}

func TestEnforceContextUsesSectionEffect(t *testing.T) {
	e := newSectionTestEnforcer(t, `
[request_definition]
r = sub, obj, act
r2 = sub, obj, act

[policy_definition]
p = sub, obj, act, eft
p2 = sub, obj, act, eft

[policy_effect]
e = some(where (p.eft == allow))
e2 = some(where (p.eft == allow)) && !some(where (p.eft == deny))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
m2 = r2.sub == p2.sub && r2.obj == p2.obj && r2.act == p2.act
`, [][]string{
		{"p", "alice", "data1", "read", "allow"},
		{"p2", "alice", "data2", "read", "allow"},
		{"p2", "alice", "data2", "read", "deny"},
		{"p2", "alice", "data3", "read", "deny"},
	})

	ctx := NewEnforceContext("2")
	tests := []struct {
		obj  string
		want bool
	}{
		{"data2", false},
		{"data3", false},
		{"data4", false},
	}
	for _, tt := range tests {
		got, err := e.Enforce(ctx, "alice", tt.obj, "read")
		if err != nil {
			t.Fatal(err)
		}
		if got != tt.want {
			t.Errorf("Enforce(ctx2, alice, %s, read) = %v, want %v", tt.obj, got, tt.want)
		}
	}
	if ok, _ := e.Enforce("alice", "data1", "read"); !ok {
		t.Error("Enforce(alice, data1, read) = false, want true")
	}
}

func TestCachedEnforcerSeparatesEnforcementViews(t *testing.T) {
	m, err := model.NewModelFromString(`
[request_definition]
r = sub, obj, act
r2 = sub, obj, act

[policy_definition]
p = sub, obj, act
p2 = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))
e2 = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
m2 = r2.sub == p2.sub && r2.obj == p2.obj && r2.act == p2.act
`)
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewCachedEnforcer(m)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.AddPolicy("alice", "data1", "read"); err != nil {
		t.Fatal(err)
	}

	if ok, _ := e.Enforce("alice", "data1", "read"); !ok {
		t.Fatal("Enforce(alice, data1, read) = false, want true")
	}
	if ok, _ := e.Enforce(NewEnforceContext("2"), "alice", "data1", "read"); ok {
		t.Error("Enforce(ctx2, alice, data1, read) = true, want false")
	}
	if ok, _ := e.EnforceWithMatcher("r.sub == p.sub && false", "alice", "data1", "read"); ok {
		t.Error("EnforceWithMatcher(stricter matcher) = true, want false")
	}
	ok, _, _ := e.EnforceExWithMatcher("r.sub == p.sub && false", "alice", "data1", "read")
	if ok {
		t.Error("EnforceExWithMatcher(stricter matcher) = true, want false")
	}
}

func TestSubjectPriorityInNonDefaultSection(t *testing.T) {
	dir := t.TempDir()
	modelPath := filepath.Join(dir, "model.conf")
	policyPath := filepath.Join(dir, "policy.csv")
	modelText := `[request_definition]
r = sub, obj, act
r2 = sub, obj, act

[policy_definition]
p = sub, obj, act, eft
p2 = sub, obj, act, eft

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))
e2 = subjectPriority(p.eft) || deny

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
m2 = g(r2.sub, p2.sub) && r2.obj == p2.obj && r2.act == p2.act
`
	policyText := `p2, admin, data1, read, allow
p2, alice, data1, read, deny
g, alice, admin
`
	if err := os.WriteFile(modelPath, []byte(modelText), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyPath, []byte(policyText), 0o600); err != nil {
		t.Fatal(err)
	}
	e, err := NewEnforcer(modelPath, policyPath)
	if err != nil {
		t.Fatal(err)
	}

	ctx := NewEnforceContext("2")
	if ok, _ := e.Enforce(ctx, "alice", "data1", "read"); ok {
		t.Error("Enforce(ctx2, alice, data1, read) = true, want false: the deny on alice is more specific than the allow on admin")
	}
	if ok, _ := e.Enforce(ctx, "admin", "data1", "read"); !ok {
		t.Error("Enforce(ctx2, admin, data1, read) = false, want true")
	}
}

func TestPolicyIndexByTokenIgnoresOtherRequestTypes(t *testing.T) {
	e := newSectionTestEnforcer(t, `
[request_definition]
r = sub, obj, act
r2 = obj, sub

[policy_definition]
p = sub, obj, act, eft

[policy_effect]
e = some(where (p.eft == allow)) && !some(where (p.eft == deny))

[matchers]
m = (p.sub == "*" || r.sub == p.sub) && r.obj == p.obj && r.act == p.act
m2 = (p.sub == "*" || r2.sub == p.sub) && r2.obj == p.obj
`, [][]string{
		{"p", "*", "data1", "read", "allow"},
		{"p", "alice", "data1", "read", "deny"},
	})

	ctx := EnforceContext{RType: "r2", PType: "p", EType: "e", MType: "m2"}
	before, err := e.Enforce(ctx, "data1", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if before {
		t.Fatal("Enforce(r2, data1, alice) = true without index, want false")
	}

	if err = e.SetPolicyIndexByToken("p", "r_sub", "p_sub"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := e.Enforce("alice", "data1", "read"); ok {
		t.Error("Enforce(alice, data1, read) = true, want false")
	}
	if ok, _ := e.Enforce(ctx, "data1", "alice"); ok {
		t.Error("Enforce(r2, data1, alice) = true with index on r_sub, want false")
	}
}
