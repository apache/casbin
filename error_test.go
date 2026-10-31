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

	fileadapter "github.com/casbin/casbin/v3/persist/file-adapter"
	"github.com/casbin/casbin/v3/util"
)

func TestPathError(t *testing.T) {
	_, err := NewEnforcer("hope_this_path_wont_exist", "")
	if err == nil {
		t.Errorf("Should be error here.")
	} else {
		t.Log("Test on error: ")
		t.Log(err.Error())
	}
}

func TestEnforcerParamError(t *testing.T) {
	_, err := NewEnforcer(1, 2, 3)
	if err == nil {
		t.Errorf("Should not be error here.")
	} else {
		t.Log("Test on error: ")
		t.Log(err.Error())
	}

	_, err2 := NewEnforcer(1, "2")
	if err2 == nil {
		t.Errorf("Should not be error here.")
	} else {
		t.Log("Test on error: ")
		t.Log(err2.Error())
	}
}

func TestModelError(t *testing.T) {
	_, err := NewEnforcer("examples/error/error_model.conf", "examples/error/error_policy.csv")
	if err == nil {
		t.Errorf("Should be error here.")
	} else {
		t.Log("Test on error: ")
		t.Log(err.Error())
	}
}

// func TestPolicyError(t *testing.T) {
//	_, err := NewEnforcer("examples/basic_model.conf", "examples/error/error_policy.csv")
//	if err == nil {
//		t.Errorf("Should be error here.")
//	} else {
//		t.Log("Test on error: ")
//		t.Log(err.Error())
//	}
//}

func TestEnforceError(t *testing.T) {
	e, _ := NewEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")
	_, err := e.Enforce("wrong", "wrong")
	if err == nil {
		t.Errorf("Should be error here.")
	} else {
		t.Log("Test on error: ")
		t.Log(err.Error())
	}

	e, _ = NewEnforcer("examples/abac_rule_model.conf")
	_, err = e.Enforce("wang", "wang", "wang")
	if err == nil {
		t.Errorf("Should be error here.")
	} else {
		t.Log("Test on error: ")
		t.Log(err.Error())
	}
}

func TestNoError(t *testing.T) {
	e, _ := NewEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")

	err := e.LoadModel()
	if err != nil {
		t.Errorf("Should be no error here.")
		t.Log("Unexpected error: ")
		t.Log(err.Error())
	}

	err = e.LoadPolicy()
	if err != nil {
		t.Errorf("Should be no error here.")
		t.Log("Unexpected error: ")
		t.Log(err.Error())
	}

	err = e.SavePolicy()
	if err != nil {
		t.Errorf("Should be no error here.")
		t.Log("Unexpected error: ")
		t.Log(err.Error())
	}
}

func TestModelNoError(t *testing.T) {
	e, _ := NewEnforcer("examples/basic_model.conf", "examples/basic_policy.csv")

	e.modelPath = "hope_this_path_wont_exist"
	err := e.LoadModel()

	if err == nil {
		t.Errorf("Should be error here.")
	} else {
		t.Log("Test on error: ")
		t.Log(err.Error())
	}
}

func TestMockAdapterErrors(t *testing.T) {
	adapter := fileadapter.NewAdapterMock("examples/rbac_with_domains_policy.csv")
	adapter.SetMockErr("mock error")

	e, _ := NewEnforcer("examples/rbac_with_domains_model.conf", adapter)

	added, err := e.AddPolicy("admin", "domain3", "data1", "read")
	if added {
		t.Errorf("added should be false")
	}

	if err == nil {
		t.Errorf("Should be an error here.")
	} else {
		t.Log("Test on error: ")
		t.Log(err.Error())
	}

	rules := [][]string{
		{"admin", "domain4", "data1", "read"},
	}
	added, err = e.AddPolicies(rules)
	if added {
		t.Errorf("added should be false")
	}

	if err == nil {
		t.Errorf("Should be an error here.")
	} else {
		t.Log("Test on error: ")
		t.Log(err.Error())
	}

	removed, err2 := e.RemoveFilteredPolicy(1, "domain1", "data1")
	if removed {
		t.Errorf("removed should be false")
	}

	if err2 == nil {
		t.Errorf("Should be an error here.")
	} else {
		t.Log("Test on error: ")
		t.Log(err2.Error())
	}

	removed, err3 := e.RemovePolicy("admin", "domain2", "data2", "read")
	if removed {
		t.Errorf("removed should be false")
	}

	if err3 == nil {
		t.Errorf("Should be an error here.")
	} else {
		t.Log("Test on error: ")
		t.Log(err3.Error())
	}

	rules = [][]string{
		{"admin", "domain1", "data1", "read"},
	}
	removed, err = e.RemovePolicies(rules)
	if removed {
		t.Errorf("removed should be false")
	}

	if err == nil {
		t.Errorf("Should be an error here.")
	} else {
		t.Log("Test on error: ")
		t.Log(err.Error())
	}

	added, err4 := e.AddGroupingPolicy("bob", "admin2")
	if added {
		t.Errorf("added should be false")
	}

	if err4 == nil {
		t.Errorf("Should be an error here.")
	} else {
		t.Log("Test on error: ")
		t.Log(err4.Error())
	}

	added, err5 := e.AddNamedGroupingPolicy("g", []string{"eve", "admin2", "domain1"})
	if added {
		t.Errorf("added should be false")
	}

	if err5 == nil {
		t.Errorf("Should be an error here.")
	} else {
		t.Log("Test on error: ")
		t.Log(err5.Error())
	}

	added, err6 := e.AddNamedPolicy("p", []string{"admin2", "domain2", "data2", "write"})
	if added {
		t.Errorf("added should be false")
	}

	if err6 == nil {
		t.Errorf("Should be an error here.")
	} else {
		t.Log("Test on error: ")
		t.Log(err6.Error())
	}

	removed, err7 := e.RemoveGroupingPolicy("bob", "admin2")
	if removed {
		t.Errorf("removed should be false")
	}

	if err7 == nil {
		t.Errorf("Should be an error here.")
	} else {
		t.Log("Test on error: ")
		t.Log(err7.Error())
	}

	removed, err8 := e.RemoveFilteredGroupingPolicy(0, "bob")
	if removed {
		t.Errorf("removed should be false")
	}

	if err8 == nil {
		t.Errorf("Should be an error here.")
	} else {
		t.Log("Test on error: ")
		t.Log(err8.Error())
	}

	removed, err9 := e.RemoveNamedGroupingPolicy("g", []string{"alice", "admin", "domain1"})
	if removed {
		t.Errorf("removed should be false")
	}

	if err9 == nil {
		t.Errorf("Should be an error here.")
	} else {
		t.Log("Test on error: ")
		t.Log(err9.Error())
	}

	removed, err10 := e.RemoveFilteredNamedGroupingPolicy("g", 0, "eve")
	if removed {
		t.Errorf("removed should be false")
	}

	if err10 == nil {
		t.Errorf("Should be an error here.")
	} else {
		t.Log("Test on error: ")
		t.Log(err10.Error())
	}
}

func TestInvalidPatternInPolicy(t *testing.T) {
	e, err := NewEnforcer("examples/keymatch_model.conf")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.AddPolicy("alice", "/alice_data/*", "(GET"); err != nil {
		t.Fatal(err)
	}

	_, err = e.Enforce("alice", "/alice_data/resource1", "GET")
	if err == nil || strings.HasPrefix(err.Error(), "panic:") ||
		!strings.Contains(err.Error(), "regexMatch: error parsing regexp: missing closing ): `(GET`") {
		t.Errorf("Enforce returns %v, supposed to be a regexMatch parse error", err)
	}

	e, err = NewEnforcer("examples/rbac_with_pattern_model.conf", "examples/rbac_with_pattern_policy.csv")
	if err != nil {
		t.Fatal(err)
	}
	e.AddNamedMatchingFunc("g2", "matchingFunc", util.KeyMatch2)
	if _, err = e.AddNamedGroupingPolicy("g2", "/book/(1", "book_group"); err != nil {
		t.Fatal(err)
	}

	testEnforce(t, e, "alice", "/book/1", "GET", true)
	testEnforce(t, e, "alice", "/book/(1", "GET", true)
	if roles, err := e.GetNamedImplicitRolesForUser("g2", "/book/(1"); err != nil || len(roles) != 1 {
		t.Errorf("GetNamedImplicitRolesForUser returns %v %v, supposed to be [book_group]", roles, err)
	}
}

func TestPatternWithCaptureGroupInPolicy(t *testing.T) {
	e, err := NewEnforcer("examples/rbac_with_pattern_model.conf")
	if err != nil {
		t.Fatal(err)
	}
	e.AddNamedMatchingFunc("g2", "matchingFunc", util.KeyMatch4)
	if _, err = e.AddPolicy("alice", "book_group", "GET"); err != nil {
		t.Fatal(err)
	}
	if _, err = e.AddNamedGroupingPolicy("g2", "/(book|pen)/{id}/copy/{id}", "book_group"); err != nil {
		t.Fatal(err)
	}

	testEnforce(t, e, "alice", "/book/1/copy/1", "GET", true)
	testEnforce(t, e, "alice", "/pen/1/copy/1", "GET", true)
	testEnforce(t, e, "alice", "/book/1/copy/2", "GET", false)
	testEnforce(t, e, "alice", "/cup/1/copy/1", "GET", false)
	if roles, err := e.GetNamedImplicitRolesForUser("g2", "/book/1/copy/1"); err != nil || len(roles) != 1 {
		t.Errorf("GetNamedImplicitRolesForUser returns %v %v, supposed to be [book_group]", roles, err)
	}
}
