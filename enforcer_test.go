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
	"sync"
	"testing"

	"github.com/casbin/casbin/v3/detector"
	"github.com/casbin/casbin/v3/model"
	fileadapter "github.com/casbin/casbin/v3/persist/file-adapter"
	"github.com/casbin/casbin/v3/util"
)

func TestKeyMatchModelInMemory(t *testing.T) {
	m := model.NewModel()
	m.AddDef("r", "r", "sub, obj, act")
	m.AddDef("p", "p", "sub, obj, act")
	m.AddDef("e", "e", "some(where (p.eft == allow))")
	m.AddDef("m", "m", "r.sub == p.sub && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)")

	a := fileadapter.NewAdapter("examples/keymatch_policy.csv")

	e, _ := NewEnforcer(m, a)

	testEnforce(t, e, "alice", "/alice_data/resource1", "GET", true)
	testEnforce(t, e, "alice", "/alice_data/resource1", "POST", true)
	testEnforce(t, e, "alice", "/alice_data/resource2", "GET", true)
	testEnforce(t, e, "alice", "/alice_data/resource2", "POST", false)
	testEnforce(t, e, "alice", "/bob_data/resource1", "GET", false)
	testEnforce(t, e, "alice", "/bob_data/resource1", "POST", false)
	testEnforce(t, e, "alice", "/bob_data/resource2", "GET", false)
	testEnforce(t, e, "alice", "/bob_data/resource2", "POST", false)

	testEnforce(t, e, "bob", "/alice_data/resource1", "GET", false)
	testEnforce(t, e, "bob", "/alice_data/resource1", "POST", false)
	testEnforce(t, e, "bob", "/alice_data/resource2", "GET", true)
	testEnforce(t, e, "bob", "/alice_data/resource2", "POST", false)
	testEnforce(t, e, "bob", "/bob_data/resource1", "GET", false)
	testEnforce(t, e, "bob", "/bob_data/resource1", "POST", true)
	testEnforce(t, e, "bob", "/bob_data/resource2", "GET", false)
	testEnforce(t, e, "bob", "/bob_data/resource2", "POST", true)

	testEnforce(t, e, "cathy", "/cathy_data", "GET", true)
	testEnforce(t, e, "cathy", "/cathy_data", "POST", true)
	testEnforce(t, e, "cathy", "/cathy_data", "DELETE", false)

	e, _ = NewEnforcer(m)
	_ = a.LoadPolicy(e.GetModel())

	testEnforce(t, e, "alice", "/alice_data/resource1", "GET", true)
	testEnforce(t, e, "alice", "/alice_data/resource1", "POST", true)
	testEnforce(t, e, "alice", "/alice_data/resource2", "GET", true)
	testEnforce(t, e, "alice", "/alice_data/resource2", "POST", false)
	testEnforce(t, e, "alice", "/bob_data/resource1", "GET", false)
	testEnforce(t, e, "alice", "/bob_data/resource1", "POST", false)
	testEnforce(t, e, "alice", "/bob_data/resource2", "GET", false)
	testEnforce(t, e, "alice", "/bob_data/resource2", "POST", false)

	testEnforce(t, e, "bob", "/alice_data/resource1", "GET", false)
	testEnforce(t, e, "bob", "/alice_data/resource1", "POST", false)
	testEnforce(t, e, "bob", "/alice_data/resource2", "GET", true)
	testEnforce(t, e, "bob", "/alice_data/resource2", "POST", false)
	testEnforce(t, e, "bob", "/bob_data/resource1", "GET", false)
	testEnforce(t, e, "bob", "/bob_data/resource1", "POST", true)
	testEnforce(t, e, "bob", "/bob_data/resource2", "GET", false)
	testEnforce(t, e, "bob", "/bob_data/resource2", "POST", true)

	testEnforce(t, e, "cathy", "/cathy_data", "GET", true)
	testEnforce(t, e, "cathy", "/cathy_data", "POST", true)
	testEnforce(t, e, "cathy", "/cathy_data", "DELETE", false)
}

func TestKeyMatchWithRBACInDomain(t *testing.T) {
	e, _ := NewEnforcer("examples/keymatch_with_rbac_in_domain.conf", "examples/keymatch_with_rbac_in_domain.csv")
	testDomainEnforce(t, e, "Username==test2", "engines/engine1", "*", "attach", true)
}

func TestKeyMatchModelInMemoryDeny(t *testing.T) {
	m := model.NewModel()
	m.AddDef("r", "r", "sub, obj, act")
	m.AddDef("p", "p", "sub, obj, act")
	m.AddDef("e", "e", "!some(where (p.eft == deny))")
	m.AddDef("m", "m", "r.sub == p.sub && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)")

	a := fileadapter.NewAdapter("examples/keymatch_policy.csv")

	e, _ := NewEnforcer(m, a)

	testEnforce(t, e, "alice", "/alice_data/resource2", "POST", true)
}

func TestRBACModelInMemoryIndeterminate(t *testing.T) {
	m := model.NewModel()
	m.AddDef("r", "r", "sub, obj, act")
	m.AddDef("p", "p", "sub, obj, act")
	m.AddDef("g", "g", "_, _")
	m.AddDef("e", "e", "some(where (p.eft == allow))")
	m.AddDef("m", "m", "g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act")

	e, _ := NewEnforcer(m)

	_, _ = e.AddPermissionForUser("alice", "data1", "invalid")

	testEnforce(t, e, "alice", "data1", "read", false)
}

func TestRBACModelInMemory(t *testing.T) {
	m := model.NewModel()
	m.AddDef("r", "r", "sub, obj, act")
	m.AddDef("p", "p", "sub, obj, act")
	m.AddDef("g", "g", "_, _")
	m.AddDef("e", "e", "some(where (p.eft == allow))")
	m.AddDef("m", "m", "g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act")

	e, _ := NewEnforcer(m)

	_, _ = e.AddPermissionForUser("alice", "data1", "read")
	_, _ = e.AddPermissionForUser("bob", "data2", "write")
	_, _ = e.AddPermissionForUser("data2_admin", "data2", "read")
	_, _ = e.AddPermissionForUser("data2_admin", "data2", "write")
	_, _ = e.AddRoleForUser("alice", "data2_admin")

	testEnforce(t, e, "alice", "data1", "read", true)
	testEnforce(t, e, "alice", "data1", "write", false)
	testEnforce(t, e, "alice", "data2", "read", true)
	testEnforce(t, e, "alice", "data2", "write", true)
	testEnforce(t, e, "bob", "data1", "read", false)
	testEnforce(t, e, "bob", "data1", "write", false)
	testEnforce(t, e, "bob", "data2", "read", false)
	testEnforce(t, e, "bob", "data2", "write", true)
}

func TestRBACModelInMemory2(t *testing.T) {
	text := `
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
	m, _ := model.NewModelFromString(text)
	// The above is the same as:
	// m := NewModel()
	// m.LoadModelFromText(text)

	e, _ := NewEnforcer(m)

	_, _ = e.AddPermissionForUser("alice", "data1", "read")
	_, _ = e.AddPermissionForUser("bob", "data2", "write")
	_, _ = e.AddPermissionForUser("data2_admin", "data2", "read")
	_, _ = e.AddPermissionForUser("data2_admin", "data2", "write")
	_, _ = e.AddRoleForUser("alice", "data2_admin")

	testEnforce(t, e, "alice", "data1", "read", true)
	testEnforce(t, e, "alice", "data1", "write", false)
	testEnforce(t, e, "alice", "data2", "read", true)
	testEnforce(t, e, "alice", "data2", "write", true)
	testEnforce(t, e, "bob", "data1", "read", false)
	testEnforce(t, e, "bob", "data1", "write", false)
	testEnforce(t, e, "bob", "data2", "read", false)
	testEnforce(t, e, "bob", "data2", "write", true)
}

func TestCommentMarkerInMatcherString(t *testing.T) {
	text := `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && (r.act == "#write" || r.obj == 'a;b') # comment
`
	m, err := model.NewModelFromString(text)
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewEnforcer(m)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = e.AddPolicy("alice", "data1", "read")

	testEnforce(t, e, "alice", "data1", "#write", true)
	testEnforce(t, e, "alice", "a;b", "read", true)
	testEnforce(t, e, "alice", "data1", "read", false)
}

func TestNotUsedRBACModelInMemory(t *testing.T) {
	m := model.NewModel()
	m.AddDef("r", "r", "sub, obj, act")
	m.AddDef("p", "p", "sub, obj, act")
	m.AddDef("g", "g", "_, _")
	m.AddDef("e", "e", "some(where (p.eft == allow))")
	m.AddDef("m", "m", "g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act")

	e, _ := NewEnforcer(m)

	_, _ = e.AddPermissionForUser("alice", "data1", "read")
	_, _ = e.AddPermissionForUser("bob", "data2", "write")

	testEnforce(t, e, "alice", "data1", "read", true)
	testEnforce(t, e, "alice", "data1", "write", false)
	testEnforce(t, e, "alice", "data2", "read", false)
	testEnforce(t, e, "alice", "data2", "write", false)
	testEnforce(t, e, "bob", "data1", "read", false)
	testEnforce(t, e, "bob", "data1", "write", false)
	testEnforce(t, e, "bob", "data2", "read", false)
	testEnforce(t, e, "bob", "data2", "write", true)
}

func TestMatcherUsingInOperator(t *testing.T) {
	// From file config
	e, _ := NewEnforcer("examples/rbac_model_matcher_using_in_op.conf")
	_, _ = e.AddPermissionForUser("alice", "data1", "read")

	testEnforce(t, e, "alice", "data1", "read", true)
	testEnforce(t, e, "alice", "data2", "read", true)
	testEnforce(t, e, "alice", "data3", "read", true)
	testEnforce(t, e, "anyone", "data1", "read", false)
	testEnforce(t, e, "anyone", "data2", "read", true)
	testEnforce(t, e, "anyone", "data3", "read", true)
}

func TestMatcherUsingInOperatorBracket(t *testing.T) {
	e, _ := NewEnforcer("examples/rbac_model_matcher_using_in_op_bracket.conf")
	_, _ = e.AddPermissionForUser("alice", "data1", "read")

	testEnforce(t, e, "alice", "data1", "read", true)
	testEnforce(t, e, "alice", "data2", "read", true)
	testEnforce(t, e, "alice", "data3", "read", true)
	testEnforce(t, e, "anyone", "data1", "read", false)
	testEnforce(t, e, "anyone", "data2", "read", true)
	testEnforce(t, e, "anyone", "data3", "read", true)
}

func TestReloadPolicy(t *testing.T) {
	e, _ := NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")

	_ = e.LoadPolicy()
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})
}

func TestSavePolicy(t *testing.T) {
	e, _ := NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")

	_ = e.SavePolicy()
}

func TestClearPolicy(t *testing.T) {
	e, _ := NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")

	e.ClearPolicy()
}

func TestEnableEnforce(t *testing.T) {
	e, _ := NewEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")

	e.EnableEnforce(false)
	testEnforce(t, e, "alice", "data1", "read", true)
	testEnforce(t, e, "alice", "data1", "write", true)
	testEnforce(t, e, "alice", "data2", "read", true)
	testEnforce(t, e, "alice", "data2", "write", true)
	testEnforce(t, e, "bob", "data1", "read", true)
	testEnforce(t, e, "bob", "data1", "write", true)
	testEnforce(t, e, "bob", "data2", "read", true)
	testEnforce(t, e, "bob", "data2", "write", true)

	e.EnableEnforce(true)
	testEnforce(t, e, "alice", "data1", "read", true)
	testEnforce(t, e, "alice", "data1", "write", false)
	testEnforce(t, e, "alice", "data2", "read", false)
	testEnforce(t, e, "alice", "data2", "write", false)
	testEnforce(t, e, "bob", "data1", "read", false)
	testEnforce(t, e, "bob", "data1", "write", false)
	testEnforce(t, e, "bob", "data2", "read", false)
	testEnforce(t, e, "bob", "data2", "write", true)
}

func TestEnableLog(t *testing.T) {
	// This test is now a no-op since the logger has been removed
	// Keeping it for backward compatibility, but it just tests enforcement
	e, _ := NewEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")

	testEnforce(t, e, "alice", "data1", "read", true)
	testEnforce(t, e, "alice", "data1", "write", false)
	testEnforce(t, e, "alice", "data2", "read", false)
	testEnforce(t, e, "alice", "data2", "write", false)
	testEnforce(t, e, "bob", "data1", "read", false)
	testEnforce(t, e, "bob", "data1", "write", false)
	testEnforce(t, e, "bob", "data2", "read", false)
	testEnforce(t, e, "bob", "data2", "write", true)
}

func TestEnableAutoSave(t *testing.T) {
	e, _ := NewEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")

	e.EnableAutoSave(false)
	// Because AutoSave is disabled, the policy change only affects the policy in Casbin enforcer,
	// it doesn't affect the policy in the storage.
	_, _ = e.RemovePolicy("alice", "data1", "read")
	// Reload the policy from the storage to see the effect.
	_ = e.LoadPolicy()
	testEnforce(t, e, "alice", "data1", "read", true)
	testEnforce(t, e, "alice", "data1", "write", false)
	testEnforce(t, e, "alice", "data2", "read", false)
	testEnforce(t, e, "alice", "data2", "write", false)
	testEnforce(t, e, "bob", "data1", "read", false)
	testEnforce(t, e, "bob", "data1", "write", false)
	testEnforce(t, e, "bob", "data2", "read", false)
	testEnforce(t, e, "bob", "data2", "write", true)

	e.EnableAutoSave(true)
	// Because AutoSave is enabled, the policy change not only affects the policy in Casbin enforcer,
	// but also affects the policy in the storage.
	_, _ = e.RemovePolicy("alice", "data1", "read")

	// However, the file adapter doesn't implement the AutoSave feature, so enabling it has no effect at all here.

	// Reload the policy from the storage to see the effect.
	_ = e.LoadPolicy()
	testEnforce(t, e, "alice", "data1", "read", true) // Will not be false here.
	testEnforce(t, e, "alice", "data1", "write", false)
	testEnforce(t, e, "alice", "data2", "read", false)
	testEnforce(t, e, "alice", "data2", "write", false)
	testEnforce(t, e, "bob", "data1", "read", false)
	testEnforce(t, e, "bob", "data1", "write", false)
	testEnforce(t, e, "bob", "data2", "read", false)
	testEnforce(t, e, "bob", "data2", "write", true)
}

func TestInitWithAdapter(t *testing.T) {
	adapter := fileadapter.NewAdapter("examples/basic_policy.csv")
	e, _ := NewEnforcer("examples/basic_model.conf", adapter)

	testEnforce(t, e, "alice", "data1", "read", true)
	testEnforce(t, e, "alice", "data1", "write", false)
	testEnforce(t, e, "alice", "data2", "read", false)
	testEnforce(t, e, "alice", "data2", "write", false)
	testEnforce(t, e, "bob", "data1", "read", false)
	testEnforce(t, e, "bob", "data1", "write", false)
	testEnforce(t, e, "bob", "data2", "read", false)
	testEnforce(t, e, "bob", "data2", "write", true)
}

func TestRoleLinks(t *testing.T) {
	e, _ := NewEnforcer("examples/rbac_model.conf")
	e.EnableAutoBuildRoleLinks(false)
	_ = e.BuildRoleLinks()
	_, _ = e.Enforce("user501", "data9", "read")
}

func TestEnforceConcurrency(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Enforce is not concurrent")
		}
	}()

	e, _ := NewEnforcer("examples/rbac_model.conf")
	_ = e.LoadModel()

	var wg sync.WaitGroup

	// Simulate concurrency (maybe use a timer?)
	for i := 1; i <= 10000; i++ {
		wg.Add(1)
		go func() {
			_, _ = e.Enforce("user501", "data9", "read")
			wg.Done()
		}()
	}

	wg.Wait()
}

func TestGetAndSetModel(t *testing.T) {
	e, _ := NewEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
	e2, _ := NewEnforcer("examples/basic_with_root_model.conf", "examples/basic_policy.csv")

	testEnforce(t, e, "root", "data1", "read", false)

	e.SetModel(e2.GetModel())

	testEnforce(t, e, "root", "data1", "read", true)
}

func TestGetAndSetAdapterInMem(t *testing.T) {
	e, _ := NewEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
	e2, _ := NewEnforcer("examples/basic_model.conf", "examples/basic_inverse_policy.csv")

	testEnforce(t, e, "alice", "data1", "read", true)
	testEnforce(t, e, "alice", "data1", "write", false)

	a2 := e2.GetAdapter()
	e.SetAdapter(a2)
	_ = e.LoadPolicy()

	testEnforce(t, e, "alice", "data1", "read", false)
	testEnforce(t, e, "alice", "data1", "write", true)
}

func TestSetAdapterFromFile(t *testing.T) {
	e, _ := NewEnforcer("examples/basic_model.conf")

	testEnforce(t, e, "alice", "data1", "read", false)

	a := fileadapter.NewAdapter("examples/basic_policy.csv")
	e.SetAdapter(a)
	_ = e.LoadPolicy()

	testEnforce(t, e, "alice", "data1", "read", true)
}

func TestInitEmpty(t *testing.T) {
	e, _ := NewEnforcer()

	m := model.NewModel()
	m.AddDef("r", "r", "sub, obj, act")
	m.AddDef("p", "p", "sub, obj, act")
	m.AddDef("e", "e", "some(where (p.eft == allow))")
	m.AddDef("m", "m", "r.sub == p.sub && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)")

	a := fileadapter.NewAdapter("examples/keymatch_policy.csv")

	e.SetModel(m)
	e.SetAdapter(a)
	_ = e.LoadPolicy()

	testEnforce(t, e, "alice", "/alice_data/resource1", "GET", true)
}

func testEnforceEx(t *testing.T, e *Enforcer, sub, obj, act interface{}, res []string) {
	t.Helper()
	_, myRes, _ := e.EnforceEx(sub, obj, act)

	if ok := util.ArrayEquals(res, myRes); !ok {
		t.Error("Key: ", myRes, ", supposed to be ", res)
	}
}

func TestEnforceEx(t *testing.T) {
	e, _ := NewEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")

	testEnforceEx(t, e, "alice", "data1", "read", []string{"alice", "data1", "read"})
	testEnforceEx(t, e, "alice", "data1", "write", []string{})
	testEnforceEx(t, e, "alice", "data2", "read", []string{})
	testEnforceEx(t, e, "alice", "data2", "write", []string{})
	testEnforceEx(t, e, "bob", "data1", "read", []string{})
	testEnforceEx(t, e, "bob", "data1", "write", []string{})
	testEnforceEx(t, e, "bob", "data2", "read", []string{})
	testEnforceEx(t, e, "bob", "data2", "write", []string{"bob", "data2", "write"})

	e, _ = NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")

	testEnforceEx(t, e, "alice", "data1", "read", []string{"alice", "data1", "read"})
	testEnforceEx(t, e, "alice", "data1", "write", []string{})
	testEnforceEx(t, e, "alice", "data2", "read", []string{"data2_admin", "data2", "read"})
	testEnforceEx(t, e, "alice", "data2", "write", []string{"data2_admin", "data2", "write"})
	testEnforceEx(t, e, "bob", "data1", "read", []string{})
	testEnforceEx(t, e, "bob", "data1", "write", []string{})
	testEnforceEx(t, e, "bob", "data2", "read", []string{})
	testEnforceEx(t, e, "bob", "data2", "write", []string{"bob", "data2", "write"})

	e, _ = NewEnforcer("examples/priority_model.conf", "examples/priority_policy.csv")

	testEnforceEx(t, e, "alice", "data1", "read", []string{"alice", "data1", "read", "allow"})
	testEnforceEx(t, e, "alice", "data1", "write", []string{"data1_deny_group", "data1", "write", "deny"})
	testEnforceEx(t, e, "alice", "data2", "read", []string{})
	testEnforceEx(t, e, "alice", "data2", "write", []string{})
	testEnforceEx(t, e, "bob", "data1", "write", []string{})
	testEnforceEx(t, e, "bob", "data2", "read", []string{"data2_allow_group", "data2", "read", "allow"})
	testEnforceEx(t, e, "bob", "data2", "write", []string{"bob", "data2", "write", "deny"})

	e, _ = NewEnforcer("examples/abac_model.conf")
	obj := struct{ Owner string }{Owner: "alice"}
	testEnforceEx(t, e, "alice", obj, "write", []string{})
}

func TestEnforceExLog(t *testing.T) {
	// This test was previously named for logging, but actually tests EnforceEx explain functionality
	// Logger parameter has been removed, but the test still validates explain behavior
	e, _ := NewEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")

	testEnforceEx(t, e, "alice", "data1", "read", []string{"alice", "data1", "read"})
	testEnforceEx(t, e, "alice", "data1", "write", []string{})
	testEnforceEx(t, e, "alice", "data2", "read", []string{})
	testEnforceEx(t, e, "alice", "data2", "write", []string{})
	testEnforceEx(t, e, "bob", "data1", "read", []string{})
	testEnforceEx(t, e, "bob", "data1", "write", []string{})
	testEnforceEx(t, e, "bob", "data2", "read", []string{})
	testEnforceEx(t, e, "bob", "data2", "write", []string{"bob", "data2", "write"})
}

func testBatchEnforce(t *testing.T, e *Enforcer, requests [][]interface{}, results []bool) {
	t.Helper()
	myRes, _ := e.BatchEnforce(requests)
	if len(myRes) != len(results) {
		t.Errorf("%v supposed to be %v", myRes, results)
	}
	for i, v := range myRes {
		if v != results[i] {
			t.Errorf("%v supposed to be %v", myRes, results)
		}
	}
}

func TestBatchEnforce(t *testing.T) {
	e, _ := NewEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
	results := []bool{true, true, false}
	testBatchEnforce(t, e, [][]interface{}{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"jack", "data3", "read"}}, results)
}

func TestSubjectPriority(t *testing.T) {
	e, _ := NewEnforcer("examples/subject_priority_model.conf", "examples/subject_priority_policy.csv")
	testBatchEnforce(t, e, [][]interface{}{
		{"jane", "data1", "read"},
		{"alice", "data1", "read"},
	}, []bool{
		true, true,
	})
}

func TestSubjectPriorityWithDomain(t *testing.T) {
	e, _ := NewEnforcer("examples/subject_priority_model_with_domain.conf", "examples/subject_priority_policy_with_domain.csv")
	testBatchEnforce(t, e, [][]interface{}{
		{"alice", "data1", "domain1", "write"},
		{"bob", "data2", "domain2", "write"},
	}, []bool{
		true, true,
	})
}

func TestSubjectPriorityInFilter(t *testing.T) {
	e, _ := NewEnforcer()

	adapter := fileadapter.NewFilteredAdapter("examples/subject_priority_policy_with_domain.csv")
	_ = e.InitWithAdapter("examples/subject_priority_model_with_domain.conf", adapter)
	if err := e.loadFilteredPolicy(&fileadapter.Filter{
		P: []string{"", "", "domain1"},
	}); err != nil {
		t.Errorf("unexpected error in LoadFilteredPolicy: %v", err)
	}

	testBatchEnforce(t, e, [][]interface{}{
		{"alice", "data1", "domain1", "write"},
		{"admin", "data1", "domain1", "write"},
	}, []bool{
		true, false,
	})
}

func TestMultiplePolicyDefinitions(t *testing.T) {
	e, _ := NewEnforcer("examples/multiple_policy_definitions_model.conf", "examples/multiple_policy_definitions_policy.csv")
	enforceContext := NewEnforceContext("2")
	enforceContext.EType = "e"
	testBatchEnforce(t, e, [][]interface{}{
		{"alice", "data2", "read"},
		{enforceContext, struct{ Age int }{Age: 70}, "/data1", "read"},
		{enforceContext, struct{ Age int }{Age: 30}, "/data1", "read"},
	}, []bool{
		true, false, true,
	})
}

func TestPriorityExplicit(t *testing.T) {
	e, _ := NewEnforcer("examples/priority_model_explicit.conf", "examples/priority_policy_explicit.csv")
	testBatchEnforce(t, e, [][]interface{}{
		{"alice", "data1", "write"},
		{"alice", "data1", "read"},
		{"bob", "data2", "read"},
		{"bob", "data2", "write"},
		{"data1_deny_group", "data1", "read"},
		{"data1_deny_group", "data1", "write"},
		{"data2_allow_group", "data2", "read"},
		{"data2_allow_group", "data2", "write"},
	}, []bool{
		true, true, false, true, false, false, true, true,
	})

	_, err := e.AddPolicy("1", "bob", "data2", "write", "deny")
	if err != nil {
		t.Fatalf("Add Policy: %v", err)
	}

	testBatchEnforce(t, e, [][]interface{}{
		{"alice", "data1", "write"},
		{"alice", "data1", "read"},
		{"bob", "data2", "read"},
		{"bob", "data2", "write"},
		{"data1_deny_group", "data1", "read"},
		{"data1_deny_group", "data1", "write"},
		{"data2_allow_group", "data2", "read"},
		{"data2_allow_group", "data2", "write"},
	}, []bool{
		true, true, false, false, false, false, true, true,
	})
}

func TestFailedToLoadPolicy(t *testing.T) {
	e, _ := NewEnforcer("examples/rbac_with_pattern_model.conf", "examples/rbac_with_pattern_policy.csv")
	e.AddNamedMatchingFunc("g2", "matchingFunc", util.KeyMatch2)
	testEnforce(t, e, "alice", "/book/1", "GET", true)
	testEnforce(t, e, "bob", "/pen/3", "GET", true)
	e.SetAdapter(fileadapter.NewAdapter("not found"))
	_ = e.LoadPolicy()
	testEnforce(t, e, "alice", "/book/1", "GET", true)
	testEnforce(t, e, "bob", "/pen/3", "GET", true)
}

func TestReloadPolicyWithFunc(t *testing.T) {
	e, _ := NewEnforcer("examples/rbac_with_pattern_model.conf", "examples/rbac_with_pattern_policy.csv")
	e.AddNamedMatchingFunc("g2", "matchingFunc", util.KeyMatch2)
	testEnforce(t, e, "alice", "/book/1", "GET", true)
	testEnforce(t, e, "bob", "/pen/3", "GET", true)
	_ = e.LoadPolicy()
	testEnforce(t, e, "alice", "/book/1", "GET", true)
	testEnforce(t, e, "bob", "/pen/3", "GET", true)
}

func TestEvalPriority(t *testing.T) {
	e, _ := NewEnforcer("examples/eval_operator_model.conf", "examples/eval_operator_policy.csv")
	testEnforce(t, e, "admin", "users", "write", true)
	testEnforce(t, e, "admin", "none", "write", false)
	testEnforce(t, e, "user", "users", "write", false)
}

func TestLinkConditionFunc(t *testing.T) {
	TrueFunc := func(args ...string) (bool, error) {
		if len(args) != 0 {
			return args[0] == "_" || args[0] == "true", nil
		}
		return false, nil
	}

	FalseFunc := func(args ...string) (bool, error) {
		if len(args) != 0 {
			return args[0] == "_" || args[0] == "false", nil
		}
		return false, nil
	}

	m, _ := model.NewModelFromFile("examples/rbac_with_temporal_roles_model.conf")
	e, _ := NewEnforcer(m)

	_, _ = e.AddPolicies([][]string{
		{"alice", "data1", "read"},
		{"alice", "data1", "write"},
		{"data2_admin", "data2", "read"},
		{"data2_admin", "data2", "write"},
		{"data3_admin", "data3", "read"},
		{"data3_admin", "data3", "write"},
		{"data4_admin", "data4", "read"},
		{"data4_admin", "data4", "write"},
		{"data5_admin", "data5", "read"},
		{"data5_admin", "data5", "write"},
	})

	_, _ = e.AddGroupingPolicies([][]string{
		{"alice", "data2_admin", "_", "_"},
		{"alice", "data3_admin", "_", "_"},
		{"alice", "data4_admin", "_", "_"},
		{"alice", "data5_admin", "_", "_"},
	})

	e.AddNamedLinkConditionFunc("g", "alice", "data2_admin", TrueFunc)
	e.AddNamedLinkConditionFunc("g", "alice", "data3_admin", TrueFunc)
	e.AddNamedLinkConditionFunc("g", "alice", "data4_admin", FalseFunc)
	e.AddNamedLinkConditionFunc("g", "alice", "data5_admin", FalseFunc)

	e.SetNamedLinkConditionFuncParams("g", "alice", "data2_admin", "true")
	e.SetNamedLinkConditionFuncParams("g", "alice", "data3_admin", "not true")
	e.SetNamedLinkConditionFuncParams("g", "alice", "data4_admin", "false")
	e.SetNamedLinkConditionFuncParams("g", "alice", "data5_admin", "not false")

	testEnforce(t, e, "alice", "data1", "read", true)
	testEnforce(t, e, "alice", "data1", "write", true)
	testEnforce(t, e, "alice", "data2", "read", true)
	testEnforce(t, e, "alice", "data2", "write", true)
	testEnforce(t, e, "alice", "data3", "read", false)
	testEnforce(t, e, "alice", "data3", "write", false)
	testEnforce(t, e, "alice", "data4", "read", true)
	testEnforce(t, e, "alice", "data4", "write", true)
	testEnforce(t, e, "alice", "data5", "read", false)
	testEnforce(t, e, "alice", "data5", "write", false)

	m, _ = model.NewModelFromFile("examples/rbac_with_domain_temporal_roles_model.conf")
	e, _ = NewEnforcer(m)

	_, _ = e.AddPolicies([][]string{
		{"alice", "domain1", "data1", "read"},
		{"alice", "domain1", "data1", "write"},
		{"data2_admin", "domain2", "data2", "read"},
		{"data2_admin", "domain2", "data2", "write"},
		{"data3_admin", "domain3", "data3", "read"},
		{"data3_admin", "domain3", "data3", "write"},
		{"data4_admin", "domain4", "data4", "read"},
		{"data4_admin", "domain4", "data4", "write"},
		{"data5_admin", "domain5", "data5", "read"},
		{"data5_admin", "domain5", "data5", "write"},
	})

	_, _ = e.AddGroupingPolicies([][]string{
		{"alice", "data2_admin", "domain2", "_", "_"},
		{"alice", "data3_admin", "domain3", "_", "_"},
		{"alice", "data4_admin", "domain4", "_", "_"},
		{"alice", "data5_admin", "domain5", "_", "_"},
	})

	e.AddNamedDomainLinkConditionFunc("g", "alice", "data2_admin", "domain2", TrueFunc)
	e.AddNamedDomainLinkConditionFunc("g", "alice", "data3_admin", "domain3", TrueFunc)
	e.AddNamedDomainLinkConditionFunc("g", "alice", "data4_admin", "domain4", FalseFunc)
	e.AddNamedDomainLinkConditionFunc("g", "alice", "data5_admin", "domain5", FalseFunc)

	e.SetNamedDomainLinkConditionFuncParams("g", "alice", "data2_admin", "domain2", "true")
	e.SetNamedDomainLinkConditionFuncParams("g", "alice", "data3_admin", "domain3", "not true")
	e.SetNamedDomainLinkConditionFuncParams("g", "alice", "data4_admin", "domain4", "false")
	e.SetNamedDomainLinkConditionFuncParams("g", "alice", "data5_admin", "domain5", "not false")

	testDomainEnforce(t, e, "alice", "domain1", "data1", "read", true)
	testDomainEnforce(t, e, "alice", "domain1", "data1", "write", true)
	testDomainEnforce(t, e, "alice", "domain2", "data2", "read", true)
	testDomainEnforce(t, e, "alice", "domain2", "data2", "write", true)
	testDomainEnforce(t, e, "alice", "domain3", "data3", "read", false)
	testDomainEnforce(t, e, "alice", "domain3", "data3", "write", false)
	testDomainEnforce(t, e, "alice", "domain4", "data4", "read", true)
	testDomainEnforce(t, e, "alice", "domain4", "data4", "write", true)
	testDomainEnforce(t, e, "alice", "domain5", "data5", "read", false)
	testDomainEnforce(t, e, "alice", "domain5", "data5", "write", false)
}

func TestEnforcerWithDefaultDetector(t *testing.T) {
	// Test that default detector is enabled and detects cycles
	_, err := NewEnforcer("examples/rbac_model.conf", "examples/rbac_with_cycle_policy.csv")

	// Expect an error because the policy contains a cycle
	if err == nil {
		t.Error("Expected cycle detection error when loading policy with cycle, but got nil")
	} else {
		errMsg := err.Error()
		if !strings.Contains(errMsg, "cycle detected") {
			t.Errorf("Expected error message to contain 'cycle detected', got: %s", errMsg)
		}
	}
}

func TestEnforcerRunDetections(t *testing.T) {
	// Test explicit RunDetections() call
	e, _ := NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")

	// Should not error on valid policy
	err := e.RunDetections()
	if err != nil {
		t.Errorf("Expected no error when running detections on valid policy, but got: %v", err)
	}

	// Now add a cycle manually
	_, _ = e.AddGroupingPolicy("alice", "data2_admin")
	_, _ = e.AddGroupingPolicy("data2_admin", "super_admin")
	_, _ = e.AddGroupingPolicy("super_admin", "alice")

	// Should detect the cycle
	err = e.RunDetections()
	if err == nil {
		t.Error("Expected cycle detection error, but got nil")
	} else {
		errMsg := err.Error()
		if !strings.Contains(errMsg, "cycle detected") {
			t.Errorf("Expected error message to contain 'cycle detected', got: %s", errMsg)
		}
	}
}

func TestEnforcerSetDetector(t *testing.T) {
	// Test SetDetector() method
	e, _ := NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")

	// Create a custom detector
	customDetector := detector.NewDefaultDetector()
	e.SetDetector(customDetector)

	// Should still work with custom detector
	err := e.RunDetections()
	if err != nil {
		t.Errorf("Expected no error with custom detector, but got: %v", err)
	}
}

func TestEnforcerSetDetectors(t *testing.T) {
	// Test SetDetectors() method
	e, _ := NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")

	// Create multiple detectors
	detectors := []detector.Detector{
		detector.NewDefaultDetector(),
		detector.NewDefaultDetector(),
	}
	e.SetDetectors(detectors)

	// Should work with multiple detectors
	err := e.RunDetections()
	if err != nil {
		t.Errorf("Expected no error with multiple detectors, but got: %v", err)
	}
}
