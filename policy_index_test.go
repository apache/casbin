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
	"reflect"
	"testing"

	"github.com/casbin/casbin/v3/model"
)

func newIndexTestEnforcer(t testing.TB, effect string, withEft bool) (*Enforcer, *int) {
	t.Helper()

	m := model.NewModel()
	m.AddDef("r", "r", "sub, obj_type, obj, act")
	if withEft {
		m.AddDef("p", "p", "sub, obj_type, obj, act, eft")
	} else {
		m.AddDef("p", "p", "sub, obj_type, obj, act")
	}
	m.AddDef("g", "g", "_, _")
	m.AddDef("e", "e", effect)
	m.AddDef("m", "m", "g(r.sub, p.sub) && matchObj(p.obj_type, p.obj, r.obj_type, r.obj) && r.act == p.act")

	e, err := NewEnforcer(m)
	if err != nil {
		t.Fatal(err)
	}

	calls := 0
	addMatchObjFunction(e, &calls)

	return e, &calls
}

func addMatchObjFunction(e *Enforcer, calls *int) {
	e.AddFunction("matchObj", func(args ...interface{}) (interface{}, error) {
		*calls++
		pType := args[0].(string)
		pObj := args[1].(string)
		rType := args[2].(string)
		rObj := args[3].(string)
		return (pType == "*" || pType == rType) && pObj == rObj, nil
	})
}

func addIndexTestPolicies(t testing.TB, e *Enforcer, withEft bool, withDeny bool) {
	t.Helper()

	rules := [][]string{
		{"alice", "doc", "doc1", "read"},
		{"alice", "doc", "doc2", "read"},
		{"alice", "img", "img1", "read"},
		{"alice", "*", "video1", "read"},
	}
	if withEft {
		for i := range rules {
			rules[i] = append(rules[i], "allow")
		}
	}

	if _, err := e.AddPolicies(rules); err != nil {
		t.Fatal(err)
	}
	if !withDeny {
		return
	}

	if !withEft {
		t.Fatal("a deny policy requires the eft token")
	}
	if _, err := e.AddPolicy("alice", "doc", "doc3", "read", "deny"); err != nil {
		t.Fatal(err)
	}
}

func setObjectTypeIndex(t testing.TB, e *Enforcer) {
	t.Helper()

	err := e.SetPolicyIndex("p", PolicyIndex{
		RequestKey: func(rvals []interface{}) (string, bool) {
			return rvals[1].(string), true
		},
		PolicyKey: func(rule []string) string {
			return rule[1]
		},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestPolicyIndexMatchesUnindexedDecisions(t *testing.T) {
	const effect = "some(where (p.eft == allow)) && !some(where (p.eft == deny))"

	indexed, _ := newIndexTestEnforcer(t, effect, true)
	addIndexTestPolicies(t, indexed, true, true)
	setObjectTypeIndex(t, indexed)

	unindexed, _ := newIndexTestEnforcer(t, effect, true)
	addIndexTestPolicies(t, unindexed, true, true)

	if _, err := indexed.AddGroupingPolicy("bob", "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := unindexed.AddGroupingPolicy("bob", "alice"); err != nil {
		t.Fatal(err)
	}

	requests := [][]interface{}{
		{"alice", "doc", "doc1", "read"},
		{"alice", "doc", "doc2", "read"},
		{"alice", "doc", "doc3", "read"},
		{"alice", "img", "img1", "read"},
		{"alice", "audio", "video1", "read"},
		{"alice", "audio", "missing", "read"},
		{"alice", "doc", "doc1", "write"},
		{"bob", "doc", "doc1", "read"},
		{"bob", "img", "img1", "read"},
		{"bob", "audio", "video1", "read"},
	}

	for _, request := range requests {
		indexedOK, indexedExplain, err := indexed.EnforceEx(request...)
		if err != nil {
			t.Fatal(err)
		}
		unindexedOK, unindexedExplain, err := unindexed.EnforceEx(request...)
		if err != nil {
			t.Fatal(err)
		}

		if indexedOK != unindexedOK {
			t.Fatalf("%v: indexed decision %v, unindexed %v", request, indexedOK, unindexedOK)
		}
		if !reflect.DeepEqual(indexedExplain, unindexedExplain) {
			t.Fatalf("%v: indexed explain %v, unindexed %v", request, indexedExplain, unindexedExplain)
		}
	}
}

func TestPolicyIndexSkipsUnrelatedRules(t *testing.T) {
	e, calls := newIndexTestEnforcer(t, "some(where (p.eft == allow)) && !some(where (p.eft == deny))", true)
	addIndexTestPolicies(t, e, true, true)
	setObjectTypeIndex(t, e)

	tests := []struct {
		request []interface{}
		calls   int
	}{
		{[]interface{}{"alice", "doc", "doc1", "read"}, 4},
		{[]interface{}{"alice", "img", "img1", "read"}, 2},
		{[]interface{}{"alice", "audio", "video1", "read"}, 1},
	}

	for _, test := range tests {
		*calls = 0
		if _, err := e.Enforce(test.request...); err != nil {
			t.Fatal(err)
		}
		if *calls != test.calls {
			t.Fatalf("%v: evaluated %d rules, want %d", test.request, *calls, test.calls)
		}
	}

	e.RemovePolicyIndex("p")
	*calls = 0
	if _, err := e.Enforce("alice", "doc", "doc1", "read"); err != nil {
		t.Fatal(err)
	}
	if *calls != 5 {
		t.Fatalf("without index: evaluated %d rules, want 5", *calls)
	}
}

func TestPolicyIndexRebuildsAfterPolicyChanges(t *testing.T) {
	e, calls := newIndexTestEnforcer(t, "some(where (p.eft == allow)) && !some(where (p.eft == deny))", true)
	addIndexTestPolicies(t, e, true, true)
	setObjectTypeIndex(t, e)

	if ok, err := e.Enforce("alice", "doc", "doc4", "read"); err != nil || ok {
		t.Fatalf("doc4 before add: ok=%v err=%v", ok, err)
	}

	if _, err := e.AddPolicy("alice", "doc", "doc4", "read", "allow"); err != nil {
		t.Fatal(err)
	}
	*calls = 0
	if ok, err := e.Enforce("alice", "doc", "doc4", "read"); err != nil || !ok {
		t.Fatalf("doc4 after add: ok=%v err=%v", ok, err)
	}
	if *calls != 5 {
		t.Fatalf("after add: evaluated %d rules, want 5", *calls)
	}

	if _, err := e.RemovePolicy("alice", "doc", "doc4", "read", "allow"); err != nil {
		t.Fatal(err)
	}
	if ok, err := e.Enforce("alice", "doc", "doc4", "read"); err != nil || ok {
		t.Fatalf("doc4 after remove: ok=%v err=%v", ok, err)
	}

	oldRule := []string{"alice", "img", "img1", "read", "allow"}
	newRule := []string{"alice", "doc", "doc4", "read", "allow"}
	if ok, err := e.UpdatePolicy(oldRule, newRule); err != nil || !ok {
		t.Fatalf("update policy: ok=%v err=%v", ok, err)
	}
	if ok, err := e.Enforce("alice", "img", "img1", "read"); err != nil || ok {
		t.Fatalf("img1 after update: ok=%v err=%v", ok, err)
	}
	if ok, err := e.Enforce("alice", "doc", "doc4", "read"); err != nil || !ok {
		t.Fatalf("doc4 after update: ok=%v err=%v", ok, err)
	}

	e.ClearPolicy()
	if ok, err := e.Enforce("alice", "doc", "doc1", "read"); err != nil || ok {
		t.Fatalf("doc1 after clear: ok=%v err=%v", ok, err)
	}
	if _, err := e.AddPolicy("alice", "doc", "doc1", "read", "allow"); err != nil {
		t.Fatal(err)
	}
	if ok, err := e.Enforce("alice", "doc", "doc1", "read"); err != nil || !ok {
		t.Fatalf("doc1 after clear and add: ok=%v err=%v", ok, err)
	}
}

func TestPolicyIndexDisabledForUnpartitionedRequest(t *testing.T) {
	e, calls := newIndexTestEnforcer(t, "some(where (p.eft == allow)) && !some(where (p.eft == deny))", true)
	addIndexTestPolicies(t, e, true, true)

	err := e.SetPolicyIndex("p", PolicyIndex{
		RequestKey: func(rvals []interface{}) (string, bool) {
			return "", false
		},
		PolicyKey: func(rule []string) string {
			return rule[1]
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	*calls = 0
	if _, err := e.Enforce("alice", "doc", "doc1", "read"); err != nil {
		t.Fatal(err)
	}
	if *calls != 5 {
		t.Fatalf("evaluated %d rules, want 5", *calls)
	}
}

func TestPolicyIndexValidation(t *testing.T) {
	e, _ := newIndexTestEnforcer(t, "some(where (p.eft == allow))", false)

	if err := e.SetPolicyIndex("missing", PolicyIndex{
		RequestKey: func([]interface{}) (string, bool) { return "", true },
		PolicyKey:  func([]string) string { return "" },
	}); err == nil {
		t.Fatal("expected an error for a missing policy type")
	}

	if err := e.SetPolicyIndex("p", PolicyIndex{}); err == nil {
		t.Fatal("expected an error for nil index functions")
	}

	setObjectTypeIndex(t, e)
	e.RemovePolicyIndex("p")
}

func TestAllowAndDenyShortCircuitsWithoutDenyRules(t *testing.T) {
	for _, withEft := range []bool{false, true} {
		e, calls := newIndexTestEnforcer(t, "some(where (p.eft == allow)) && !some(where (p.eft == deny))", withEft)
		addIndexTestPolicies(t, e, withEft, false)

		*calls = 0
		if ok, err := e.Enforce("alice", "doc", "doc1", "read"); err != nil || !ok {
			t.Fatalf("withEft=%v: ok=%v err=%v", withEft, ok, err)
		}
		if *calls != 1 {
			t.Fatalf("withEft=%v: evaluated %d rules, want 1", withEft, *calls)
		}
	}
}

func TestAllowAndDenyStillEvaluatesWhenDenyExists(t *testing.T) {
	e, calls := newIndexTestEnforcer(t, "some(where (p.eft == allow)) && !some(where (p.eft == deny))", true)
	addIndexTestPolicies(t, e, true, true)

	*calls = 0
	if ok, err := e.Enforce("alice", "doc", "doc1", "read"); err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if *calls != 5 {
		t.Fatalf("evaluated %d rules, want 5", *calls)
	}
}

func TestPolicyIndexByToken(t *testing.T) {
	e, calls := newIndexTestEnforcer(t, "some(where (p.eft == allow)) && !some(where (p.eft == deny))", true)
	addIndexTestPolicies(t, e, true, true)

	if err := e.SetPolicyIndexByToken("p", "r_obj_type", "p_obj_type"); err != nil {
		t.Fatal(err)
	}

	*calls = 0
	if ok, err := e.Enforce("alice", "doc", "doc1", "read"); err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if *calls != 4 {
		t.Fatalf("evaluated %d rules, want 4", *calls)
	}

	if err := e.SetPolicyIndexByToken("p", "r_missing", "p_obj_type"); err == nil {
		t.Fatal("expected an error for a missing request token")
	}
	if err := e.SetPolicyIndexByToken("p", "r_obj_type", "p_missing"); err == nil {
		t.Fatal("expected an error for a missing policy token")
	}
}

func TestPolicyIndexResetsWhenModelChanges(t *testing.T) {
	const effect = "some(where (p.eft == allow)) && !some(where (p.eft == deny))"

	e, calls := newIndexTestEnforcer(t, effect, false)
	if _, err := e.AddPolicy("alice", "doc", "doc1", "read"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.AddPolicy("alice", "img", "img1", "read"); err != nil {
		t.Fatal(err)
	}
	setObjectTypeIndex(t, e)

	if ok, err := e.Enforce("alice", "img", "img1", "read"); err != nil || !ok {
		t.Fatalf("before SetModel: ok=%v err=%v", ok, err)
	}

	replacement := model.NewModel()
	replacement.AddDef("r", "r", "sub, obj_type, obj, act")
	replacement.AddDef("p", "p", "sub, obj_type, obj, act")
	replacement.AddDef("g", "g", "_, _")
	replacement.AddDef("e", "e", effect)
	replacement.AddDef("m", "m", "g(r.sub, p.sub) && matchObj(p.obj_type, p.obj, r.obj_type, r.obj) && r.act == p.act")
	if err := replacement.AddPolicy("p", "p", []string{"alice", "img", "img1", "read"}); err != nil {
		t.Fatal(err)
	}
	if err := replacement.AddPolicy("p", "p", []string{"alice", "doc", "doc1", "read"}); err != nil {
		t.Fatal(err)
	}

	e.SetModel(replacement)
	addMatchObjFunction(e, calls)

	if ok, err := e.Enforce("alice", "img", "img1", "read"); err != nil || !ok {
		t.Fatalf("after SetModel: ok=%v err=%v", ok, err)
	}
}
