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

// Package authztest provides lightweight test helpers for Casbin
// authorization tests with meaningful failure context.
//
// The standard way to test Casbin policies is a stream of bare Enforce
// calls:
//
//	if ok, _ := e.Enforce("alice", "data1", "read"); !ok {
//		t.Error("expected alice to read data1")
//	}
//
// When such a test fails you learn *that* it failed, not *why*. These
// helpers keep the ergonomics (one line per assertion) and add the missing
// context: on failure they report the policies that came closest to
// matching, position by position, including role inheritance via g rules.
//
//	authztest.AssertAllow(t, e, "alice", "data1", "read")
//	authztest.AssertDeny(t, e, "bob", "data1", "write")
//
// Failure output looks like:
//
//	authztest: expected ALLOW, got DENY for (bob, data1, read)
//	no policy matched; closest candidates:
//	  p, alice, data1, read
//	    sub: 'bob' does not match 'alice' (no role link to alice)
//	    obj: ok ('data1')
//	    act: ok ('read')
package authztest

import (
	"fmt"
	"strings"

	"github.com/casbin/casbin/v3"
	"github.com/casbin/casbin/v3/rbac"
)

// T is the subset of testing.TB (and therefore *testing.T, *testing.B and
// *testing.F) used by the helpers.
type T interface {
	Helper()
	Errorf(format string, args ...interface{})
}

// AssertAllow asserts that the enforcer allows the request. On failure it
// reports the request and a near-miss diagnosis of the closest policies.
func AssertAllow(t T, e casbin.IEnforcer, rvals ...interface{}) {
	t.Helper()
	ok, err := e.Enforce(rvals...)
	if err != nil {
		t.Errorf("authztest: enforce(%s) returned error: %v", formatRequest(rvals), err)
		return
	}
	if ok {
		return
	}
	d := Diagnose(e, rvals...)
	t.Errorf("authztest: expected ALLOW, got DENY for %s\n%s", formatRequest(rvals), d)
}

// AssertDeny asserts that the enforcer denies the request. On unexpected
// allow it reports which policy line(s) matched.
func AssertDeny(t T, e casbin.IEnforcer, rvals ...interface{}) {
	t.Helper()
	ok, err := e.Enforce(rvals...)
	if err != nil {
		t.Errorf("authztest: enforce(%s) returned error: %v", formatRequest(rvals), err)
		return
	}
	if !ok {
		return
	}
	d := Diagnose(e, rvals...)
	t.Errorf("authztest: expected DENY, got ALLOW for %s\n%s", formatRequest(rvals), d)
}

// NearMiss describes how close one policy line came to matching a request.
type NearMiss struct {
	Policy  []string // the raw policy line
	Matched []string // human-readable per-position notes for matched positions
	Failed  []string // human-readable per-position notes for failed positions
}

// Score is the number of positions that matched; used to rank near misses.
func (n NearMiss) Score() int { return len(n.Matched) }

// FullyMatched reports whether every position matched. When a request was
// unexpectedly allowed, the fully matched policies are the reason.
func (n NearMiss) FullyMatched() bool { return len(n.Failed) == 0 }

// Diagnose returns a human-readable explanation of why a request was
// allowed or denied, ranking the closest policy lines first.
//
// The attribution is a structural analysis of the policy and g (role)
// rules, not a re-evaluation of the matcher expression. Matchers that use
// built-in functions (keyMatch, regexMatch, ...) may legitimately match in
// ways the structural analysis cannot see; the output is labelled
// accordingly and is meant to point you at the right line, not to replace
// reading the model.
func Diagnose(e casbin.IEnforcer, rvals ...interface{}) string {
	misses, err := Explain(e, rvals...)
	if err != nil || len(misses) == 0 {
		return fmt.Sprintf("(no diagnosis available: %v)", err)
	}

	var b strings.Builder
	allowed := misses[0].FullyMatched()
	if allowed {
		b.WriteString("matched policy line(s):")
	} else {
		b.WriteString("no policy matched; closest candidates:")
	}
	b.WriteString("\n")

	shown := 0
	for _, m := range misses {
		if allowed && !m.FullyMatched() {
			continue
		}
		if shown == 3 {
			b.WriteString(fmt.Sprintf("  (+%d more)\n", len(misses)-shown))
			break
		}
		b.WriteString(fmt.Sprintf("  p, %s\n", strings.Join(m.Policy, ", ")))
		for _, note := range m.Matched {
			b.WriteString("    " + note + "\n")
		}
		for _, note := range m.Failed {
			b.WriteString("    " + note + "\n")
		}
		shown++
	}
	if !allowed && shown == 0 {
		b.WriteString("  (none)\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

// Explain returns the structured near-miss analysis behind Diagnose, sorted
// from closest match to furthest. The first element is fully matched
// exactly when the request was allowed.
func Explain(e casbin.IEnforcer, rvals ...interface{}) ([]NearMiss, error) {
	m := e.GetModel()
	rTok := tokens(m, "r", "r")
	pTok := tokens(m, "p", "p")
	if rTok == nil || pTok == nil {
		return nil, fmt.Errorf("model lacks request_definition (r) or policy_definition (p)")
	}

	rvals = pad(rvals, len(rTok))
	rstr := toStrings(rvals)
	subIdx := indexOf(rTok, "sub")
	domIdx := indexOf(rTok, "dom")

	roleMgr := e.GetRoleManager()
	policies, err := e.GetPolicy()
	if err != nil {
		return nil, err
	}

	var misses []NearMiss
	for _, pol := range policies {
		n := NearMiss{Policy: pol}
		for i, pv := range pol {
			if i >= len(rTok) {
				break
			}
			name := pTok[i]
			rv := rstr[i]
			switch {
			case pv == "*":
				n.Matched = append(n.Matched, fmt.Sprintf("%s: ok (%s matches wildcard)", name, rv))
			case pv == rv:
				n.Matched = append(n.Matched, fmt.Sprintf("%s: ok ('%s')", name, rv))
			case i == subIdx && roleLinked(roleMgr, rv, pv, pol, rstr, domIdx):
				n.Matched = append(n.Matched, fmt.Sprintf("%s: ok ('%s' inherits '%s' via g)", name, rv, pv))
			default:
				n.Failed = append(n.Failed, fmt.Sprintf("%s: '%s' does not match '%s' (%s)", name, rv, pv, failureHint(i, subIdx, roleMgr, rv, pv, pol, rstr, domIdx)))
			}
		}
		if len(pol) != len(rTok) {
			n.Failed = append(n.Failed, fmt.Sprintf("arity: policy has %d fields, request_definition declares %d", len(pol), len(rTok)))
		}
		misses = append(misses, n)
	}

	sortMisses(misses)
	return misses, nil
}

// roleLinked reports whether the request subject reaches the policy subject
// through a g rule. For domain-aware models the link is checked in the
// policy line's own domain: "does the request subject hold this role where
// this policy applies?", which makes the remaining failure positions
// unambiguous.
func roleLinked(roleMgr rbac.RoleManager, sub, role string, pol, rstr []string, domIdx int) bool {
	if roleMgr == nil || sub == role {
		return false
	}
	if domIdx < 0 || domIdx >= len(rstr) {
		ok, _ := roleMgr.HasLink(sub, role)
		return ok
	}
	dom := rstr[domIdx] // fall back to the request's domain
	if domIdx < len(pol) {
		dom = pol[domIdx]
	}
	ok, _ := roleMgr.HasLink(sub, role, dom)
	return ok
}

func failureHint(i, subIdx int, roleMgr rbac.RoleManager, rv, pv string, pol, rstr []string, domIdx int) string {
	if i == subIdx {
		return "no role link from '" + rv + "' to '" + pv + "'"
	}
	return "not a wildcard"
}
