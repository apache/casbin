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

package stringadapter

import (
	"strings"
	"testing"

	"github.com/casbin/casbin/v3"
	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist"
)

func Test_KeyMatchRbac(t *testing.T) {
	conf := `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _ , _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub)  && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)
`
	line := `
p, alice, /alice_data/*, (GET)|(POST)
p, alice, /alice_data/resource1, POST
p, data_group_admin, /admin/*, POST
p, data_group_admin, /bob_data/*, POST
g, alice, data_group_admin
`
	a := NewAdapter(line)
	m := model.NewModel()
	err := m.LoadModelFromText(conf)
	if err != nil {
		t.Errorf("load model from text failed: %v", err.Error())
		return
	}
	e, _ := casbin.NewEnforcer(m, a)
	sub := "alice"
	obj := "/alice_data/login"
	act := "POST"
	if res, _ := e.Enforce(sub, obj, act); !res {
		t.Error("unexpected enforce result")
	}
}

// Test_SavePolicyRoundTripWithCommas verifies that a policy rule whose fields contain
// commas (e.g. ABAC condition expressions) survives a SavePolicy → LoadPolicy round trip
// without corruption. See https://github.com/apache/casbin/issues/1733.
func Test_SavePolicyRoundTripWithCommas(t *testing.T) {
	conf := `
[request_definition]
r = sub, obj, act, cond

[policy_definition]
p = sub, obj, act, cond

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`
	// cond field intentionally contains commas (as in ABAC expressions).
	condWithComma := `r.attrs in ('val1','val2')`
	line := "p, alice, data1, read, " + `"` + condWithComma + `"`

	a := NewAdapter(line)
	m := model.NewModel()
	if err := m.LoadModelFromText(conf); err != nil {
		t.Fatalf("load model: %v", err)
	}
	e, err := casbin.NewEnforcer(m, a)
	if err != nil {
		t.Fatalf("new enforcer: %v", err)
	}

	// SavePolicy serialises in-memory rules back to the adapter string.
	err = e.SavePolicy()
	if err != nil {
		t.Fatalf("SavePolicy: %v", err)
	}

	// The saved line must be a properly quoted CSV so that re-loading produces
	// exactly one rule with the comma-containing cond field intact.
	saved := a.Line
	reloaded := model.NewModel()
	err = reloaded.LoadModelFromText(conf)
	if err != nil {
		t.Fatalf("reload model: %v", err)
	}
	for _, l := range strings.Split(saved, "\n") {
		if l == "" {
			continue
		}
		err = persist.LoadPolicyLine(l, reloaded)
		if err != nil {
			t.Fatalf("LoadPolicyLine on saved line %q: %v", l, err)
		}
	}

	rules, err := reloaded.GetPolicy("p", "p")
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule after round-trip, got %d (saved: %q)", len(rules), saved)
	}
	if rules[0][3] != condWithComma {
		t.Errorf("cond field corrupted after round-trip: got %q, want %q", rules[0][3], condWithComma)
	}
}

func Test_StringRbac(t *testing.T) {
	conf := `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _ , _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
`
	line := `
p, alice, data1, read
p, data_group_admin, data3, read
p, data_group_admin, data3, write
g, alice, data_group_admin
`
	a := NewAdapter(line)
	m := model.NewModel()
	err := m.LoadModelFromText(conf)
	if err != nil {
		t.Errorf("load model from text failed: %v", err.Error())
		return
	}
	e, _ := casbin.NewEnforcer(m, a)
	sub := "alice" // the user that wants to access a resource.
	obj := "data1" // the resource that is going to be accessed.
	act := "read"  // the operation that the user performs on the resource.
	if res, _ := e.Enforce(sub, obj, act); !res {
		t.Error("unexpected enforce result")
	}
}

// Test_LoadPolicyMalformedLine verifies that a malformed policy line (here an
// unterminated quoted field) makes LoadPolicy return an error instead of
// silently producing a model that lacks the rule.
func Test_LoadPolicyMalformedLine(t *testing.T) {
	a := NewAdapter(`p, alice, data1, "read`)
	m := model.NewModel()

	err := a.LoadPolicy(m)
	if err == nil {
		t.Fatal("LoadPolicy() error = nil, want a parse error for the unterminated quoted field")
	}
}
