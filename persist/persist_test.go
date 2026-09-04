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

package persist_test

import (
	"reflect"
	"testing"

	"github.com/casbin/casbin/v3"
	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist"
)

func TestPersist(t *testing.T) {
	// No tests yet
}

func testRuleCount(t *testing.T, model model.Model, expected int, sec string, ptype string, tag string) {
	t.Helper()

	ruleCount := len(model[sec][ptype].Policy)
	if ruleCount != expected {
		t.Errorf("[%s] rule count: %d, expected %d", tag, ruleCount, expected)
	}
}

func TestDuplicateRuleInAdapter(t *testing.T) {
	e, _ := casbin.NewEnforcer("../examples/basic_model.conf")

	_, _ = e.AddPolicy("alice", "data1", "read")
	_, _ = e.AddPolicy("alice", "data1", "read")

	testRuleCount(t, e.GetModel(), 1, "p", "p", "AddPolicy")

	e.ClearPolicy()

	// simulate adapter.LoadPolicy with duplicate rules
	_ = persist.LoadPolicyArray([]string{"p", "alice", "data1", "read"}, e.GetModel())
	_ = persist.LoadPolicyArray([]string{"p", "alice", "data1", "read"}, e.GetModel())

	testRuleCount(t, e.GetModel(), 1, "p", "p", "LoadPolicyArray")
}

func TestPolicyLineToCsv(t *testing.T) {
	tests := []struct {
		name     string
		ptype    string
		rule     []string
		expected string
	}{
		{
			// Fields are separated by ", ", the layout used by the policy files
			// under examples/, so that SavePolicy does not reformat them.
			name:     "plain fields keep the space after the comma",
			ptype:    "p",
			rule:     []string{"alice", "data1", "read"},
			expected: "p, alice, data1, read",
		},
		{
			name:     "field containing a comma is quoted",
			ptype:    "p",
			rule:     []string{"alice", "data1", "read", "r.attrs in ('val1','val2')"},
			expected: `p, alice, data1, read, "r.attrs in ('val1','val2')"`,
		},
		{
			name:     "field containing a quote is escaped",
			ptype:    "p",
			rule:     []string{"alice", `say "hi"`, "read"},
			expected: `p, alice, "say ""hi""", read`,
		},
		{
			// A leading space must stay quoted: LoadPolicyLine trims leading
			// spaces on unquoted fields.
			name:     "field with a leading space is quoted",
			ptype:    "g",
			rule:     []string{" alice", "admin"},
			expected: `g, " alice", admin`,
		},
		{
			name:     "empty field",
			ptype:    "p",
			rule:     []string{"alice", "", "read"},
			expected: "p, alice, , read",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			line, err := persist.PolicyLineToCsv(tt.ptype, tt.rule)
			if err != nil {
				t.Fatalf("PolicyLineToCsv: %v", err)
			}
			if line != tt.expected {
				t.Errorf("line: %q, expected %q", line, tt.expected)
			}
		})
	}
}

func TestPolicyLineToCsvRoundTrip(t *testing.T) {
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
	rule := []string{" alice", `say "hi"`, "read", "r.attrs in ('val1','val2')"}

	line, err := persist.PolicyLineToCsv("p", rule)
	if err != nil {
		t.Fatalf("PolicyLineToCsv: %v", err)
	}

	m := model.NewModel()
	if err = m.LoadModelFromText(conf); err != nil {
		t.Fatalf("load model: %v", err)
	}
	if err = persist.LoadPolicyLine(line, m); err != nil {
		t.Fatalf("LoadPolicyLine on %q: %v", line, err)
	}

	rules, err := m.GetPolicy("p", "p")
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("rule count: %d, expected 1 (line: %q)", len(rules), line)
	}
	if !reflect.DeepEqual(rules[0], rule) {
		t.Errorf("rule after round-trip: %q, expected %q (line: %q)", rules[0], rule, line)
	}
}

// TestLoadPolicyArrayEmptyPtype verifies that a rule without a policy type
// returns an error instead of panicking with a slice-bounds error.
func TestLoadPolicyArrayEmptyPtype(t *testing.T) {
	e, _ := casbin.NewEnforcer("../examples/basic_model.conf")

	err := persist.LoadPolicyArray([]string{"", "alice", "data1"}, e.GetModel())
	if err == nil {
		t.Fatal(`LoadPolicyArray(["", "alice", "data1"]) error = nil, want an error for the empty policy type`)
	}

	err = persist.LoadPolicyArray([]string{}, e.GetModel())
	if err == nil {
		t.Fatal("LoadPolicyArray([]) error = nil, want an error for the empty rule")
	}
}

// TestLoadPolicyLineLeadingComma verifies that a policy line with a stray
// leading comma (which yields an empty policy type token) returns an error
// instead of panicking.
func TestLoadPolicyLineLeadingComma(t *testing.T) {
	e, _ := casbin.NewEnforcer("../examples/basic_model.conf")

	err := persist.LoadPolicyLine(", alice, data1", e.GetModel())
	if err == nil {
		t.Fatal(`LoadPolicyLine(", alice, data1") error = nil, want an error for the missing policy type`)
	}
}
