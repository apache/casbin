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

package authztest

import (
	"fmt"
	"strings"
	"testing"

	"github.com/casbin/casbin/v3"
	"github.com/casbin/casbin/v3/model"
)

// captureT records Errorf calls instead of failing the Go test binary.
type captureT struct {
	errs []string
}

func (c *captureT) Helper() {}

func (c *captureT) Errorf(format string, args ...interface{}) {
	c.errs = append(c.errs, fmt.Sprintf(format, args...))
}

const basicModel = `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`

const rbacModel = `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
`

const domainsModel = `
[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = sub, dom, obj, act

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && r.obj == p.obj && r.act == p.act
`

func newEnforcer(t *testing.T, modelText, policyText string) casbin.IEnforcer {
	t.Helper()
	m, err := model.NewModelFromString(modelText)
	if err != nil {
		t.Fatalf("load model: %v", err)
	}
	e, err := casbin.NewEnforcer(m)
	if err != nil {
		t.Fatalf("new enforcer: %v", err)
	}
	for _, line := range strings.Split(strings.TrimSpace(policyText), "\n") {
		f := strings.Split(strings.TrimSpace(line), ",")
		if len(f) < 2 {
			continue
		}
		for i := range f {
			f[i] = strings.TrimSpace(f[i])
		}
		if f[0] == "g" {
			if _, err := e.AddGroupingPolicy(f[1:]); err != nil {
				t.Fatalf("add grouping policy %v: %v", f, err)
			}
			continue
		}
		if _, err := e.AddPolicy(f[1:]); err != nil {
			t.Fatalf("add policy %v: %v", f, err)
		}
	}
	return e
}

func TestAssertAllowPasses(t *testing.T) {
	e := newEnforcer(t, basicModel, "p, alice, data1, read\n")
	ct := &captureT{}
	AssertAllow(ct, e, "alice", "data1", "read")
	if len(ct.errs) != 0 {
		t.Fatalf("unexpected errors: %v", ct.errs)
	}
}

func TestAssertDenyPasses(t *testing.T) {
	e := newEnforcer(t, basicModel, "p, alice, data1, read\n")
	ct := &captureT{}
	AssertDeny(ct, e, "bob", "data1", "read")
	if len(ct.errs) != 0 {
		t.Fatalf("unexpected errors: %v", ct.errs)
	}
}

func TestAssertAllowFailureNamesTheFailingPosition(t *testing.T) {
	e := newEnforcer(t, basicModel, "p, alice, data1, read\n")
	ct := &captureT{}
	AssertAllow(ct, e, "bob", "data1", "read")
	if len(ct.errs) != 1 {
		t.Fatalf("expected exactly one error, got %d: %v", len(ct.errs), ct.errs)
	}
	msg := ct.errs[0]
	if !strings.Contains(msg, "expected ALLOW, got DENY") {
		t.Errorf("message should state the expectation: %s", msg)
	}
	if !strings.Contains(msg, "(bob, data1, read)") {
		t.Errorf("message should restate the request: %s", msg)
	}
	if !strings.Contains(msg, "\n    sub: 'bob' does not match 'alice'") {
		t.Errorf("message should name the failing position: %s", msg)
	}
	if !strings.Contains(msg, "\n    act: ok ('read')") {
		t.Errorf("message should credit the positions that matched: %s", msg)
	}
}

const wildcardModel = `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = (r.sub == p.sub || p.sub == "*") && (r.obj == p.obj || p.obj == "*") && (r.act == p.act || p.act == "*")
`

func TestAssertDenyFailureShowsTheMatchingPolicy(t *testing.T) {
	e := newEnforcer(t, basicModel, "p, alice, data1, read\n")
	ct := &captureT{}
	AssertDeny(ct, e, "alice", "data1", "read")
	if len(ct.errs) != 1 {
		t.Fatalf("expected exactly one error, got %d: %v", len(ct.errs), ct.errs)
	}
	msg := ct.errs[0]
	if !strings.Contains(msg, "expected DENY, got ALLOW") {
		t.Errorf("message should state the expectation: %s", msg)
	}
	if !strings.Contains(msg, "p, alice, data1, read") {
		t.Errorf("message should show the policy line that allowed it: %s", msg)
	}
}

func TestRBACRoleInheritanceIsNotReportedAsMismatch(t *testing.T) {
	// alice inherits admin; the sub position genuinely matched, so the
	// diagnosis must credit it via g and blame act instead.
	e := newEnforcer(t, rbacModel, "p, admin, data2, write\ng, alice, admin\n")
	ct := &captureT{}
	AssertAllow(ct, e, "alice", "data2", "read")
	if len(ct.errs) != 1 {
		t.Fatalf("expected exactly one error, got %d: %v", len(ct.errs), ct.errs)
	}
	msg := ct.errs[0]
	if !strings.Contains(msg, "expected ALLOW, got DENY") {
		t.Fatalf("unexpected failure mode: %s", msg)
	}
	if !strings.Contains(msg, "inherits 'admin' via g") {
		t.Errorf("role-matched subject should be credited, not blamed: %s", msg)
	}
	if strings.Contains(msg, "does not match 'admin'") {
		t.Errorf("subject matched via role; must not be reported as mismatch: %s", msg)
	}
	if !strings.Contains(msg, "act: 'read' does not match 'write'") {
		t.Errorf("the actually failing position should be named: %s", msg)
	}
}

func TestWildcardPolicyIsCredited(t *testing.T) {
	e := newEnforcer(t, wildcardModel, "p, alice, data1, *\n")
	ct := &captureT{}
	AssertDeny(ct, e, "alice", "data1", "delete")
	if len(ct.errs) != 1 {
		t.Fatalf("expected exactly one error, got %d: %v", len(ct.errs), ct.errs)
	}
	msg := ct.errs[0]
	if !strings.Contains(msg, "act: ok (delete matches wildcard)") {
		t.Errorf("wildcard match should be explained: %s", msg)
	}
}

func TestDomainsModelAttribution(t *testing.T) {
	policy := "p, admin, domain1, data1, read\ng, alice, admin, domain1\n"
	e := newEnforcer(t, domainsModel, policy)

	// Right tenant: allowed via role inheritance.
	ct := &captureT{}
	AssertAllow(ct, e, "alice", "domain1", "data1", "read")
	if len(ct.errs) != 0 {
		t.Fatalf("alice should read domain1/data1 via admin: %v", ct.errs)
	}

	// Wrong tenant: dom position is the failure, sub still credited.
	ct = &captureT{}
	AssertAllow(ct, e, "alice", "domain2", "data1", "read")
	if len(ct.errs) != 1 {
		t.Fatalf("expected exactly one error, got %d: %v", len(ct.errs), ct.errs)
	}
	msg := ct.errs[0]
	if !strings.Contains(msg, "dom: 'domain2' does not match 'domain1'") {
		t.Errorf("diagnosis should blame the tenant mismatch: %s", msg)
	}
	if !strings.Contains(msg, "inherits 'admin' via g") {
		t.Errorf("subject matched via domain-scoped g: %s", msg)
	}
}

func TestExplainRanksClosestFirst(t *testing.T) {
	policy := "p, alice, data1, read\np, bob, data2, write\n"
	e := newEnforcer(t, basicModel, policy)
	misses, err := Explain(e, "bob", "data1", "read")
	if err != nil {
		t.Fatalf("Explain: %v", err)
	}
	if len(misses) != 2 {
		t.Fatalf("expected 2 near misses, got %d", len(misses))
	}
	// p, bob, data2, write matches 1 position (sub); the alice line matches 2.
	if got := strings.Join(misses[0].Policy, ", "); got != "alice, data1, read" {
		t.Errorf("closest policy should be ranked first, got %q", got)
	}
}

func TestArityMismatchIsReported(t *testing.T) {
	e := newEnforcer(t, basicModel, "p, alice, data1\n") // 3 fields declared, 2 given
	misses, err := Explain(e, "alice", "data1", "read")
	if err != nil {
		t.Fatalf("Explain: %v", err)
	}
	if len(misses) == 0 {
		t.Fatal("expected at least one near miss")
	}
	msg := strings.Join(misses[0].Failed, " ")
	if !strings.Contains(msg, "arity") {
		t.Errorf("arity mismatch should be surfaced: %v", misses[0])
	}
}

func TestEnforceErrorIsReported(t *testing.T) {
	e := newEnforcer(t, basicModel, "p, alice, data1, read\n")
	ct := &captureT{}
	// Wrong arity: casbin returns an error instead of a boolean.
	AssertAllow(ct, e, "only-one-value")
	if len(ct.errs) != 1 {
		t.Fatalf("expected exactly one error, got %d: %v", len(ct.errs), ct.errs)
	}
	if !strings.Contains(ct.errs[0], "returned error") {
		t.Errorf("enforce errors should be reported as errors, not misattributed: %s", ct.errs[0])
	}
}
