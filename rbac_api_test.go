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
	"log"
	"sort"
	"testing"

	"github.com/casbin/casbin/v3/constant"
	"github.com/casbin/casbin/v3/errors"
	"github.com/casbin/casbin/v3/model"
	defaultrolemanager "github.com/casbin/casbin/v3/rbac/default-role-manager"
	"github.com/casbin/casbin/v3/util"
)

func testGetRoles(t *testing.T, e *Enforcer, res []string, name string, domain ...string) {
	t.Helper()
	myRes, err := e.GetRolesForUser(name, domain...)
	if err != nil {
		t.Error("Roles for ", name, " could not be fetched: ", err.Error())
	}
	t.Log("Roles for ", name, ": ", myRes)

	if !util.SetEquals(res, myRes) {
		t.Error("Roles for ", name, ": ", myRes, ", supposed to be ", res)
	}
}

func testGetUsers(t *testing.T, e *Enforcer, res []string, name string, domain ...string) {
	t.Helper()
	myRes, err := e.GetUsersForRole(name, domain...)
	switch err {
	case nil:
		break
	case errors.ErrNameNotFound:
		t.Log("No name found")
	default:
		t.Error("Users for ", name, " could not be fetched: ", err.Error())
	}
	t.Log("Users for ", name, ": ", myRes)

	if !util.SetEquals(res, myRes) {
		t.Error("Users for ", name, ": ", myRes, ", supposed to be ", res)
	}
}

func testHasRole(t *testing.T, e *Enforcer, name string, role string, res bool, domain ...string) {
	t.Helper()
	myRes, err := e.HasRoleForUser(name, role, domain...)
	if err != nil {
		t.Error("HasRoleForUser returned an error: ", err.Error())
	}
	t.Log(name, " has role ", role, ": ", myRes)

	if res != myRes {
		t.Error(name, " has role ", role, ": ", myRes, ", supposed to be ", res)
	}
}

func TestRoleAPI(t *testing.T) {
	e, _ := NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")

	testGetRoles(t, e, []string{"data2_admin"}, "alice")
	testGetRoles(t, e, []string{}, "bob")
	testGetRoles(t, e, []string{}, "data2_admin")
	testGetRoles(t, e, []string{}, "non_exist")

	testHasRole(t, e, "alice", "data1_admin", false)
	testHasRole(t, e, "alice", "data2_admin", true)

	_, _ = e.AddRoleForUser("alice", "data1_admin")

	testGetRoles(t, e, []string{"data1_admin", "data2_admin"}, "alice")
	testGetRoles(t, e, []string{}, "bob")
	testGetRoles(t, e, []string{}, "data2_admin")

	_, _ = e.DeleteRoleForUser("alice", "data1_admin")

	testGetRoles(t, e, []string{"data2_admin"}, "alice")
	testGetRoles(t, e, []string{}, "bob")
	testGetRoles(t, e, []string{}, "data2_admin")

	_, _ = e.DeleteRolesForUser("alice")

	testGetRoles(t, e, []string{}, "alice")
	testGetRoles(t, e, []string{}, "bob")
	testGetRoles(t, e, []string{}, "data2_admin")

	_, _ = e.AddRoleForUser("alice", "data1_admin")
	_, _ = e.DeleteUser("alice")

	testGetRoles(t, e, []string{}, "alice")
	testGetRoles(t, e, []string{}, "bob")
	testGetRoles(t, e, []string{}, "data2_admin")

	_, _ = e.AddRoleForUser("alice", "data2_admin")

	testEnforce(t, e, "alice", "data1", "read", false)
	testEnforce(t, e, "alice", "data1", "write", false)
	testEnforce(t, e, "alice", "data2", "read", true)
	testEnforce(t, e, "alice", "data2", "write", true)
	testEnforce(t, e, "bob", "data1", "read", false)
	testEnforce(t, e, "bob", "data1", "write", false)
	testEnforce(t, e, "bob", "data2", "read", false)
	testEnforce(t, e, "bob", "data2", "write", true)

	_, _ = e.DeleteRole("data2_admin")

	testEnforce(t, e, "alice", "data1", "read", false)
	testEnforce(t, e, "alice", "data1", "write", false)
	testEnforce(t, e, "alice", "data2", "read", false)
	testEnforce(t, e, "alice", "data2", "write", false)
	testEnforce(t, e, "bob", "data1", "read", false)
	testEnforce(t, e, "bob", "data1", "write", false)
	testEnforce(t, e, "bob", "data2", "read", false)
	testEnforce(t, e, "bob", "data2", "write", true)
}

func TestRoleAPI_Domains(t *testing.T) {
	e, _ := NewEnforcer("examples/rbac_with_domains_model.conf", "examples/rbac_with_domains_policy.csv")

	testHasRole(t, e, "alice", "admin", true, "domain1")
	testHasRole(t, e, "alice", "admin", false, "domain2")
	testGetRoles(t, e, []string{"admin"}, "alice", "domain1")
	testGetRoles(t, e, []string{}, "bob", "domain1")
	testGetRoles(t, e, []string{}, "admin", "domain1")
	testGetRoles(t, e, []string{}, "non_exist", "domain1")
	testGetRoles(t, e, []string{}, "alice", "domain2")
	testGetRoles(t, e, []string{"admin"}, "bob", "domain2")
	testGetRoles(t, e, []string{}, "admin", "domain2")
	testGetRoles(t, e, []string{}, "non_exist", "domain2")

	_, _ = e.DeleteRoleForUser("alice", "admin", "domain1")
	_, _ = e.AddRoleForUser("bob", "admin", "domain1")

	testGetRoles(t, e, []string{}, "alice", "domain1")
	testGetRoles(t, e, []string{"admin"}, "bob", "domain1")
	testGetRoles(t, e, []string{}, "admin", "domain1")
	testGetRoles(t, e, []string{}, "non_exist", "domain1")
	testGetRoles(t, e, []string{}, "alice", "domain2")
	testGetRoles(t, e, []string{"admin"}, "bob", "domain2")
	testGetRoles(t, e, []string{}, "admin", "domain2")
	testGetRoles(t, e, []string{}, "non_exist", "domain2")

	_, _ = e.AddRoleForUser("alice", "admin", "domain1")
	_, _ = e.DeleteRolesForUser("bob", "domain1")

	testGetRoles(t, e, []string{"admin"}, "alice", "domain1")
	testGetRoles(t, e, []string{}, "bob", "domain1")
	testGetRoles(t, e, []string{}, "admin", "domain1")
	testGetRoles(t, e, []string{}, "non_exist", "domain1")
	testGetRoles(t, e, []string{}, "alice", "domain2")
	testGetRoles(t, e, []string{"admin"}, "bob", "domain2")
	testGetRoles(t, e, []string{}, "admin", "domain2")
	testGetRoles(t, e, []string{}, "non_exist", "domain2")

	_, _ = e.AddRolesForUser("bob", []string{"admin", "admin1", "admin2"}, "domain1")

	testGetRoles(t, e, []string{"admin", "admin1", "admin2"}, "bob", "domain1")

	testGetPermissions(t, e, "admin", [][]string{{"admin", "domain1", "data1", "read"}, {"admin", "domain1", "data1", "write"}}, "domain1")
	testGetPermissions(t, e, "admin", [][]string{{"admin", "domain2", "data2", "read"}, {"admin", "domain2", "data2", "write"}}, "domain2")
}

func TestEnforcer_AddRolesForUser(t *testing.T) {
	e, _ := NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")

	_, _ = e.AddRolesForUser("alice", []string{"data1_admin", "data2_admin", "data3_admin"})
	// The "alice" already has "data2_admin" , it will be return false. So "alice" just has "data2_admin".
	testGetRoles(t, e, []string{"data2_admin"}, "alice")
	// delete role
	_, _ = e.DeleteRoleForUser("alice", "data2_admin")

	_, _ = e.AddRolesForUser("alice", []string{"data1_admin", "data2_admin", "data3_admin"})
	testGetRoles(t, e, []string{"data1_admin", "data2_admin", "data3_admin"}, "alice")
	testEnforce(t, e, "alice", "data1", "read", true)
	testEnforce(t, e, "alice", "data2", "read", true)
	testEnforce(t, e, "alice", "data2", "write", true)
}

func testGetPermissions(t *testing.T, e *Enforcer, name string, res [][]string, domain ...string) {
	t.Helper()
	myRes, err := e.GetPermissionsForUser(name, domain...)
	if err != nil {
		t.Error(err.Error())
	}
	t.Log("Permissions for ", name, ": ", myRes)

	if !util.Array2DEquals(res, myRes) {
		t.Error("Permissions for ", name, ": ", myRes, ", supposed to be ", res)
	}
}

func testHasPermission(t *testing.T, e *Enforcer, name string, permission []string, res bool) {
	t.Helper()
	myRes, err := e.HasPermissionForUser(name, permission...)
	if err != nil {
		t.Error(err.Error())
	}

	t.Log(name, " has permission ", util.ArrayToString(permission), ": ", myRes)

	if res != myRes {
		t.Error(name, " has permission ", util.ArrayToString(permission), ": ", myRes, ", supposed to be ", res)
	}
}

func testGetNamedPermissionsForUser(t *testing.T, e *Enforcer, ptype string, name string, res [][]string, domain ...string) {
	t.Helper()
	myRes, err := e.GetNamedPermissionsForUser(ptype, name, domain...)
	if err != nil {
		t.Error(err.Error())
	}
	t.Log("Named permissions for ", name, ": ", myRes)

	if !util.Array2DEquals(res, myRes) {
		t.Error("Named permissions for ", name, ": ", myRes, ", supposed to be ", res)
	}
}

func TestPermissionAPI(t *testing.T) {
	e, _ := NewEnforcer("examples/basic_without_resources_model.conf", "examples/basic_without_resources_policy.csv")

	testEnforceWithoutUsers(t, e, "alice", "read", true)
	testEnforceWithoutUsers(t, e, "alice", "write", false)
	testEnforceWithoutUsers(t, e, "bob", "read", false)
	testEnforceWithoutUsers(t, e, "bob", "write", true)

	testGetPermissions(t, e, "alice", [][]string{{"alice", "read"}})
	testGetPermissions(t, e, "bob", [][]string{{"bob", "write"}})

	testHasPermission(t, e, "alice", []string{"read"}, true)
	testHasPermission(t, e, "alice", []string{"write"}, false)
	testHasPermission(t, e, "bob", []string{"read"}, false)
	testHasPermission(t, e, "bob", []string{"write"}, true)

	_, _ = e.DeletePermission("read")

	testEnforceWithoutUsers(t, e, "alice", "read", false)
	testEnforceWithoutUsers(t, e, "alice", "write", false)
	testEnforceWithoutUsers(t, e, "bob", "read", false)
	testEnforceWithoutUsers(t, e, "bob", "write", true)

	_, _ = e.AddPermissionForUser("bob", "read")

	testEnforceWithoutUsers(t, e, "alice", "read", false)
	testEnforceWithoutUsers(t, e, "alice", "write", false)
	testEnforceWithoutUsers(t, e, "bob", "read", true)
	testEnforceWithoutUsers(t, e, "bob", "write", true)

	_, _ = e.AddPermissionsForUser("jack",
		[]string{"read"},
		[]string{"write"})

	testEnforceWithoutUsers(t, e, "jack", "read", true)
	testEnforceWithoutUsers(t, e, "bob", "write", true)

	_, _ = e.DeletePermissionForUser("bob", "read")

	testEnforceWithoutUsers(t, e, "alice", "read", false)
	testEnforceWithoutUsers(t, e, "alice", "write", false)
	testEnforceWithoutUsers(t, e, "bob", "read", false)
	testEnforceWithoutUsers(t, e, "bob", "write", true)

	_, _ = e.DeletePermissionsForUser("bob")

	testEnforceWithoutUsers(t, e, "alice", "read", false)
	testEnforceWithoutUsers(t, e, "alice", "write", false)
	testEnforceWithoutUsers(t, e, "bob", "read", false)
	testEnforceWithoutUsers(t, e, "bob", "write", false)

	e, _ = NewEnforcer("examples/rbac_with_multiple_policy_model.conf", "examples/rbac_with_multiple_policy_policy.csv")
	testGetNamedPermissionsForUser(t, e, "p", "user", [][]string{{"user", "/data", "GET"}})
	testGetNamedPermissionsForUser(t, e, "p2", "user", [][]string{{"user", "view"}})
}

func testGetImplicitRoles(t *testing.T, e *Enforcer, name string, res []string) {
	t.Helper()
	myRes, _ := e.GetImplicitRolesForUser(name)
	t.Log("Implicit roles for ", name, ": ", myRes)

	if !util.SetEquals(res, myRes) {
		t.Error("Implicit roles for ", name, ": ", myRes, ", supposed to be ", res)
	}
}

func testGetImplicitRolesInDomain(t *testing.T, e *Enforcer, name string, domain string, res []string) {
	t.Helper()
	myRes, _ := e.GetImplicitRolesForUser(name, domain)
	t.Log("Implicit roles in domain ", domain, " for ", name, ": ", myRes)

	if !util.SetEquals(res, myRes) {
		t.Error("Implicit roles in domain ", domain, " for ", name, ": ", myRes, ", supposed to be ", res)
	}
}

func TestImplicitRoleAPI(t *testing.T) {
	e, _ := NewEnforcer("examples/rbac_model.conf", "examples/rbac_with_hierarchy_policy.csv")

	testGetPermissions(t, e, "alice", [][]string{{"alice", "data1", "read"}})
	testGetPermissions(t, e, "bob", [][]string{{"bob", "data2", "write"}})

	testGetImplicitRoles(t, e, "alice", []string{"admin", "data1_admin", "data2_admin"})
	testGetImplicitRoles(t, e, "bob", []string{})

	e, _ = NewEnforcer("examples/rbac_with_pattern_model.conf", "examples/rbac_with_pattern_policy.csv")

	e.GetRoleManager().AddMatchingFunc("matcher", util.KeyMatch)
	e.AddNamedMatchingFunc("g2", "matcher", util.KeyMatch)

	// testGetImplicitRoles(t, e, "cathy", []string{"/book/1/2/3/4/5", "pen_admin", "/book/*", "book_group"})
	testGetImplicitRoles(t, e, "cathy", []string{"/book/1/2/3/4/5", "pen_admin"})
	testGetRoles(t, e, []string{"/book/1/2/3/4/5", "pen_admin"}, "cathy")
}

func testGetImplicitPermissions(t *testing.T, e *Enforcer, name string, res [][]string, domain ...string) {
	t.Helper()
	myRes, _ := e.GetImplicitPermissionsForUser(name, domain...)
	t.Log("Implicit permissions for ", name, ": ", myRes)

	if !util.Set2DEquals(res, myRes) {
		t.Error("Implicit permissions for ", name, ": ", myRes, ", supposed to be ", res)
	}
}

func testGetImplicitPermissionsWithDomain(t *testing.T, e *Enforcer, name string, domain string, res [][]string) {
	t.Helper()
	myRes, _ := e.GetImplicitPermissionsForUser(name, domain)
	t.Log("Implicit permissions for", name, "under", domain, ":", myRes)

	if !util.Set2DEquals(res, myRes) {
		t.Error("Implicit permissions for", name, "under", domain, ":", myRes, ", supposed to be ", res)
	}
}

func testGetNamedImplicitPermissions(t *testing.T, e *Enforcer, ptype string, gtype string, name string, res [][]string) {
	t.Helper()
	myRes, _ := e.GetNamedImplicitPermissionsForUser(ptype, gtype, name)
	t.Log("Named implicit permissions for ", name, ": ", myRes)

	if !util.Set2DEquals(res, myRes) {
		t.Error("Named implicit permissions for ", name, ": ", myRes, ", supposed to be ", res)
	}
}

func TestImplicitPermissionAPI(t *testing.T) {
	e, _ := NewEnforcer("examples/rbac_model.conf", "examples/rbac_with_hierarchy_policy.csv")

	testGetPermissions(t, e, "alice", [][]string{{"alice", "data1", "read"}})
	testGetPermissions(t, e, "bob", [][]string{{"bob", "data2", "write"}})

	testGetImplicitPermissions(t, e, "alice", [][]string{{"alice", "data1", "read"}, {"data1_admin", "data1", "read"}, {"data1_admin", "data1", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})
	testGetImplicitPermissions(t, e, "bob", [][]string{{"bob", "data2", "write"}})

	e, _ = NewEnforcer("examples/rbac_with_domain_pattern_model.conf", "examples/rbac_with_domain_pattern_policy.csv")
	e.AddNamedDomainMatchingFunc("g", "KeyMatch", util.KeyMatch)

	testGetImplicitPermissions(t, e, "admin", [][]string{{"admin", "domain1", "data1", "read"}, {"admin", "domain1", "data1", "write"}, {"admin", "domain1", "data3", "read"}}, "domain1")

	_, err := e.GetImplicitPermissionsForUser("admin", "domain1", "domain2")
	if err == nil {
		t.Error("GetImplicitPermissionsForUser should not support multiple domains")
	}

	testGetImplicitPermissions(t, e, "alice",
		[][]string{{"admin", "domain2", "data2", "read"}, {"admin", "domain2", "data2", "write"}, {"admin", "domain2", "data3", "read"}},
		"domain2")

	e, _ = NewEnforcer("examples/rbac_with_multiple_policy_model.conf", "examples/rbac_with_multiple_policy_policy.csv")

	testGetNamedImplicitPermissions(t, e, "p", "g", "alice", [][]string{{"user", "/data", "GET"}, {"admin", "/data", "POST"}})
	testGetNamedImplicitPermissions(t, e, "p2", "g", "alice", [][]string{{"user", "view"}, {"admin", "create"}})

	testGetNamedImplicitPermissions(t, e, "p", "g2", "alice", [][]string{{"user", "/data", "GET"}})
	testGetNamedImplicitPermissions(t, e, "p2", "g2", "alice", [][]string{{"user", "view"}})
}

func TestImplicitPermissionAPIWithDomain(t *testing.T) {
	e, _ := NewEnforcer("examples/rbac_with_domains_model.conf", "examples/rbac_with_hierarchy_with_domains_policy.csv")
	testGetImplicitPermissionsWithDomain(t, e, "alice", "domain1", [][]string{{"alice", "domain1", "data2", "read"}, {"role:reader", "domain1", "data1", "read"}, {"role:writer", "domain1", "data1", "write"}})
}

func testGetImplicitUsers(t *testing.T, e *Enforcer, res []string, permission ...string) {
	t.Helper()
	myRes, _ := e.GetImplicitUsersForPermission(permission...)
	t.Log("Implicit users for permission: ", permission, ": ", myRes)

	sort.Strings(res)
	sort.Strings(myRes)

	if !util.ArrayEquals(res, myRes) {
		t.Error("Implicit users for permission: ", permission, ": ", myRes, ", supposed to be ", res)
	}
}

func TestImplicitUserAPI(t *testing.T) {
	e, _ := NewEnforcer("examples/rbac_model.conf", "examples/rbac_with_hierarchy_policy.csv")

	testGetImplicitUsers(t, e, []string{"alice"}, "data1", "read")
	testGetImplicitUsers(t, e, []string{"alice"}, "data1", "write")
	testGetImplicitUsers(t, e, []string{"alice"}, "data2", "read")
	testGetImplicitUsers(t, e, []string{"alice", "bob"}, "data2", "write")

	e.ClearPolicy()
	_, _ = e.AddPolicy("admin", "data1", "read")
	_, _ = e.AddPolicy("bob", "data1", "read")
	_, _ = e.AddGroupingPolicy("alice", "admin")
	testGetImplicitUsers(t, e, []string{"alice", "bob"}, "data1", "read")
}

func testGetImplicitResourcesForUser(t *testing.T, e *Enforcer, res [][]string, user string, domain ...string) {
	t.Helper()
	myRes, _ := e.GetImplicitResourcesForUser(user, domain...)
	t.Log("Implicit resources for user: ", user, ": ", myRes)

	lessFunc := func(arr [][]string) func(int, int) bool {
		return func(i, j int) bool {
			policy1, policy2 := arr[i], arr[j]
			for k := range policy1 {
				if policy1[k] == policy2[k] {
					continue
				}
				return policy1[k] < policy2[k]
			}
			return true
		}
	}

	sort.Slice(res, lessFunc(res))
	sort.Slice(myRes, lessFunc(myRes))

	if !util.Array2DEquals(res, myRes) {
		t.Error("Implicit resources for user: ", user, ": ", myRes, ", supposed to be ", res)
	}
}

func TestGetImplicitResourcesForUser(t *testing.T) {
	e, _ := NewEnforcer("examples/rbac_with_pattern_model.conf", "examples/rbac_with_pattern_policy.csv")
	testGetImplicitResourcesForUser(t, e, [][]string{
		{"alice", "/pen/1", "GET"},
		{"alice", "/pen2/1", "GET"},
		{"alice", "/book/:id", "GET"},
		{"alice", "/book2/{id}", "GET"},
		{"alice", "/book/*", "GET"},
		{"alice", "book_group", "GET"},
	}, "alice")
	testGetImplicitResourcesForUser(t, e, [][]string{
		{"bob", "pen_group", "GET"},
		{"bob", "/pen/:id", "GET"},
		{"bob", "/pen2/{id}", "GET"},
	}, "bob")
	testGetImplicitResourcesForUser(t, e, [][]string{
		{"cathy", "pen_group", "GET"},
		{"cathy", "/pen/:id", "GET"},
		{"cathy", "/pen2/{id}", "GET"},
	}, "cathy")
}

func TestImplicitUsersForRole(t *testing.T) {
	e, _ := NewEnforcer("examples/rbac_with_pattern_model.conf", "examples/rbac_with_pattern_policy.csv")

	testGetImplicitUsersForRole(t, e, "book_admin", []string{"alice"})
	testGetImplicitUsersForRole(t, e, "pen_admin", []string{"cathy", "bob"})

	testGetImplicitUsersForRole(t, e, "book_group", []string{"/book/*", "/book/:id", "/book2/{id}"})
	testGetImplicitUsersForRole(t, e, "pen_group", []string{"/pen/:id", "/pen2/{id}"})
}

func testGetImplicitUsersForRole(t *testing.T, e *Enforcer, name string, res []string) {
	t.Helper()
	myRes, _ := e.GetImplicitUsersForRole(name)
	t.Log("Implicit users for ", name, ": ", myRes)
	sort.Strings(res)
	sort.Strings(myRes)

	if !util.SetEquals(res, myRes) {
		t.Error("Implicit users for ", name, ": ", myRes, ", supposed to be ", res)
	}
}

func TestExplicitPriorityModify(t *testing.T) {
	e, _ := NewEnforcer("examples/priority_model_explicit.conf", "examples/priority_policy_explicit.csv")

	testEnforce(t, e, "bob", "data2", "write", true)
	_, err := e.AddPolicy("1", "bob", "data2", "write", "deny")
	if err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}
	testEnforce(t, e, "bob", "data2", "write", false)

	_, err = e.DeletePermissionsForUser("bob")
	if err != nil {
		t.Fatalf("DeletePermissionForUser: %v", err)
	}
	testEnforce(t, e, "bob", "data2", "write", true)

	_, err = e.DeleteRole("data2_allow_group")
	if err != nil {
		t.Fatalf("DeleteRole: %v", err)
	}
	testEnforce(t, e, "bob", "data2", "write", false)
}

func TestCustomizedFieldIndex(t *testing.T) {
	e, _ := NewEnforcer("examples/priority_model_explicit_customized.conf",
		"examples/priority_policy_explicit_customized.csv")

	// Due to the customized priority token, the enforcer failed to handle the priority.
	testEnforce(t, e, "bob", "data2", "read", true)

	// set PriorityIndex and reload
	e.SetFieldIndex("p", constant.PriorityIndex, 0)
	err := e.LoadPolicy()
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	testEnforce(t, e, "bob", "data2", "read", false)

	testEnforce(t, e, "bob", "data2", "write", true)
	_, err = e.AddPolicy("1", "data2", "write", "deny", "bob")
	if err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}
	testEnforce(t, e, "bob", "data2", "write", false)

	// Due to the customized subject token, the enforcer will raise an error before SetFieldIndex.
	_, err = e.DeletePermissionsForUser("bob")
	if err == nil {
		t.Fatalf("Failed to warning SetFieldIndex")
	}

	e.SetFieldIndex("p", constant.SubjectIndex, 4)

	_, err = e.DeletePermissionsForUser("bob")
	if err != nil {
		t.Fatalf("DeletePermissionForUser: %v", err)
	}
	testEnforce(t, e, "bob", "data2", "write", true)

	_, err = e.DeleteRole("data2_allow_group")
	if err != nil {
		t.Fatalf("DeleteRole: %v", err)
	}
	testEnforce(t, e, "bob", "data2", "write", false)
}

func testGetAllowedObjectConditions(t *testing.T, e *Enforcer, user string, act string, prefix string, res []string, expectedErr error) {
	myRes, actualErr := e.GetAllowedObjectConditions(user, act, prefix)

	if actualErr != expectedErr {
		t.Error("actual Err: ", actualErr, ", supposed to be ", expectedErr)
	}
	if actualErr == nil {
		log.Print("Policy: ", myRes)
		if !util.ArrayEquals(res, myRes) {
			t.Error("Policy: ", myRes, ", supposed to be ", res)
		}
	}
}

func TestGetAllowedObjectConditions(t *testing.T) {
	e, _ := NewEnforcer("examples/object_conditions_model.conf", "examples/object_conditions_policy.csv")
	testGetAllowedObjectConditions(t, e, "alice", "read", "r.obj.", []string{"price < 25", "category_id = 2"}, nil)
	testGetAllowedObjectConditions(t, e, "admin", "read", "r.obj.", []string{"category_id = 2"}, nil)
	testGetAllowedObjectConditions(t, e, "bob", "write", "r.obj.", []string{"author = bob"}, nil)

	// test ErrEmptyCondition
	testGetAllowedObjectConditions(t, e, "alice", "write", "r.obj.", []string{}, errors.ErrEmptyCondition)
	testGetAllowedObjectConditions(t, e, "bob", "read", "r.obj.", []string{}, errors.ErrEmptyCondition)

	// test ErrObjCondition
	// should : e.AddPolicy("alice", "r.obj.price > 50", "read")
	ok, _ := e.AddPolicy("alice", "price > 50", "read")
	if ok {
		testGetAllowedObjectConditions(t, e, "alice", "read", "r.obj.", []string{}, errors.ErrObjCondition)
	}

	// test prefix
	e.ClearPolicy()
	err := e.GetRoleManager().DeleteLink("alice", "admin")
	if err != nil {
		panic(err)
	}
	ok, _ = e.AddPolicies([][]string{
		{"alice", "r.book.price < 25", "read"},
		{"admin", "r.book.category_id = 2", "read"},
		{"bob", "r.book.author = bob", "write"},
	})
	if ok {
		testGetAllowedObjectConditions(t, e, "alice", "read", "r.book.", []string{"price < 25"}, nil)
		testGetAllowedObjectConditions(t, e, "admin", "read", "r.book.", []string{"category_id = 2"}, nil)
		testGetAllowedObjectConditions(t, e, "bob", "write", "r.book.", []string{"author = bob"}, nil)
	}
}

func testGetImplicitUsersForResource(t *testing.T, e *Enforcer, res [][]string, resource string, domain ...string) {
	t.Helper()
	myRes, err := e.GetImplicitUsersForResource(resource)
	if err != nil {
		panic(err)
	}

	if !util.Set2DEquals(res, myRes) {
		t.Error("Implicit users for ", resource, "in domain ", domain, " : ", myRes, ", supposed to be ", res)
	} else {
		t.Log("Implicit users for ", resource, "in domain ", domain, " : ", myRes)
	}
}

func TestGetImplicitUsersForResource(t *testing.T) {
	e, _ := NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")
	testGetImplicitUsersForResource(t, e, [][]string{{"alice", "data1", "read"}}, "data1")
	testGetImplicitUsersForResource(t, e, [][]string{
		{"bob", "data2", "write"},
		{"alice", "data2", "read"},
		{"alice", "data2", "write"},
	}, "data2")

	// test duplicate permissions
	_, _ = e.AddGroupingPolicy("alice", "data2_admin_2")
	_, _ = e.AddPolicies([][]string{{"data2_admin_2", "data2", "read"}, {"data2_admin_2", "data2", "write"}})
	testGetImplicitUsersForResource(t, e, [][]string{
		{"bob", "data2", "write"},
		{"alice", "data2", "read"},
		{"alice", "data2", "write"},
	}, "data2")
}

func TestGetImplicitUsersForResourceWithResourceRoles(t *testing.T) {
	e, _ := NewEnforcer("examples/rbac_with_resource_roles_model.conf", "examples/rbac_with_resource_roles_policy.csv")

	// Test data1 resource - should return users who have access through g2 relationships
	data1Users, err := e.GetNamedImplicitUsersForResource("g2", "data1")
	if err != nil {
		t.Fatalf("GetNamedImplicitUsersForResource failed: %v", err)
	}

	expectedData1Users := 2 // [alice data1 read] + [alice data_group write]
	if len(data1Users) != expectedData1Users {
		t.Errorf("Expected %d users for data1 resource, got %d: %v", expectedData1Users, len(data1Users), data1Users)
	}

	// Test data2 resource - should return users who have access through g2 relationships
	data2Users, err := e.GetNamedImplicitUsersForResource("g2", "data2")
	if err != nil {
		t.Fatalf("GetNamedImplicitUsersForResource failed: %v", err)
	}

	expectedData2Users := 2 // [bob data2 write] + [alice data_group write]
	if len(data2Users) != expectedData2Users {
		t.Errorf("Expected %d users for data2 resource, got %d: %v", expectedData2Users, len(data2Users), data2Users)
	}

	// Test with "g" policy type - should return users who have access through g relationships
	data1UsersG, err := e.GetNamedImplicitUsersForResource("g", "data1")
	if err != nil {
		t.Fatalf("GetNamedImplicitUsersForResource with g failed: %v", err)
	}

	expectedData1UsersG := 1 // [alice data1 read] only
	if len(data1UsersG) != expectedData1UsersG {
		t.Errorf("Expected %d users for data1 resource with g policy, got %d: %v", expectedData1UsersG, len(data1UsersG), data1UsersG)
	}
}

func testGetImplicitUsersForResourceByDomain(t *testing.T, e *Enforcer, res [][]string, resource string, domain string) {
	t.Helper()
	myRes, err := e.GetImplicitUsersForResourceByDomain(resource, domain)
	if err != nil {
		panic(err)
	}

	if !util.Set2DEquals(res, myRes) {
		t.Error("Implicit users for ", resource, "in domain ", domain, " : ", myRes, ", supposed to be ", res)
	} else {
		t.Log("Implicit users for ", resource, "in domain ", domain, " : ", myRes)
	}
}

func TestGetImplicitUsersForResourceByDomain(t *testing.T) {
	e, _ := NewEnforcer("examples/rbac_with_domains_model.conf", "examples/rbac_with_domains_policy.csv")
	testGetImplicitUsersForResourceByDomain(t, e, [][]string{
		{"alice", "domain1", "data1", "read"},
		{"alice", "domain1", "data1", "write"},
	}, "data1", "domain1")

	testGetImplicitUsersForResourceByDomain(t, e, [][]string{}, "data2", "domain1")

	testGetImplicitUsersForResourceByDomain(t, e, [][]string{
		{"bob", "domain2", "data2", "read"},
		{"bob", "domain2", "data2", "write"},
	}, "data2", "domain2")
}

func TestConditional(t *testing.T) {
	e, _ := NewEnforcer("examples/rbac_with_domains_conditional_model.conf", "examples/rbac_with_domains_conditional_policy.csv")
	g, _ := e.GetNamedGroupingPolicy("g")
	for _, gp := range g {
		e.AddNamedDomainLinkConditionFunc("g", gp[0], gp[1], gp[2], util.TimeMatchFunc)
	}

	testDomainEnforce(t, e, "alice", "domain1", "service1", "/list", true)
	testDomainEnforce(t, e, "bob", "domain2", "service2", "/broadcast", true)
	testDomainEnforce(t, e, "jack", "domain1", "service1", "/list", false)
	testGetImplicitRolesInDomain(t, e, "alice", "domain1", []string{"test1"})
	testGetRolesInDomain(t, e, "alice", "domain1", []string{"test1"})
	testGetUsersInDomain(t, e, "test1", "domain1", []string{"alice"})
}

func TestMaxHierarchyLevelConsistency(t *testing.T) {
	// Test consistency behavior under different maxHierarchyLevel values
	testCases := []struct {
		maxLevel int
		name     string
	}{
		{1, "maxHierarchyLevel=1"},
		{2, "maxHierarchyLevel=2"},
		{3, "maxHierarchyLevel=3"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Use model files from examples
			e, err := NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")
			if err != nil {
				t.Fatalf("Failed to create enforcer: %v", err)
			}

			// Set the maximum hierarchy level for role manager
			rm := defaultrolemanager.NewRoleManager(tc.maxLevel)
			e.SetRoleManager(rm)

			// Add role hierarchy: level0 -> level1 -> level2 -> level3 -> level4
			_, err = e.AddRoleForUser("level0", "level1")
			if err != nil {
				t.Fatalf("Failed to add role for user: %v", err)
			}
			_, err = e.AddRoleForUser("level1", "level2")
			if err != nil {
				t.Fatalf("Failed to add role for user: %v", err)
			}
			_, err = e.AddRoleForUser("level2", "level3")
			if err != nil {
				t.Fatalf("Failed to add role for user: %v", err)
			}
			_, err = e.AddRoleForUser("level3", "level4")
			if err != nil {
				t.Fatalf("Failed to add role for user: %v", err)
			}

			// Test HasLink method
			t.Run("HasLink", func(t *testing.T) {
				for i := 1; i <= 4; i++ {
					hasLink, err := rm.HasLink("level0", fmt.Sprintf("level%d", i))
					if err != nil {
						t.Fatalf("HasLink error: %v", err)
					}
					expected := i <= tc.maxLevel
					if hasLink != expected {
						t.Errorf("HasLink(level0, level%d): got %v, want %v", i, hasLink, expected)
					}
				}
			})

			// Test GetImplicitRolesForUser method
			t.Run("GetImplicitRolesForUser", func(t *testing.T) {
				implicitRoles, err := e.GetImplicitRolesForUser("level0")
				if err != nil {
					t.Fatalf("GetImplicitRolesForUser error: %v", err)
				}

				expectedCount := tc.maxLevel
				if len(implicitRoles) != expectedCount {
					t.Errorf("GetImplicitRolesForUser(level0): got %d roles %v, want %d roles",
						len(implicitRoles), implicitRoles, expectedCount)
				}

				// Verify that returned roles are correct
				for i := 1; i <= tc.maxLevel; i++ {
					expectedRole := fmt.Sprintf("level%d", i)
					found := false
					for _, role := range implicitRoles {
						if role == expectedRole {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("Expected role %s not found in implicit roles: %v", expectedRole, implicitRoles)
					}
				}
			})

			// Test GetImplicitUsersForRole method
			t.Run("GetImplicitUsersForRole", func(t *testing.T) {
				implicitUsers, err := e.GetImplicitUsersForRole("level4")
				if err != nil {
					t.Fatalf("GetImplicitUsersForRole error: %v", err)
				}

				expectedCount := tc.maxLevel
				if len(implicitUsers) != expectedCount {
					t.Errorf("GetImplicitUsersForRole(level4): got %d users %v, want %d users",
						len(implicitUsers), implicitUsers, expectedCount)
				}

				// Verify that returned users are correct (starting from level3 upward)
				for i := 0; i < tc.maxLevel; i++ {
					expectedUser := fmt.Sprintf("level%d", 3-i)
					found := false
					for _, user := range implicitUsers {
						if user == expectedUser {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("Expected user %s not found in implicit users: %v", expectedUser, implicitUsers)
					}
				}
			})

			// Test implicit roles for different users
			t.Run("DifferentUsersImplicitRoles", func(t *testing.T) {
				for i := 0; i <= 3; i++ {
					user := fmt.Sprintf("level%d", i)
					implicitRoles, err := e.GetImplicitRolesForUser(user)
					if err != nil {
						t.Fatalf("GetImplicitRolesForUser(%s) error: %v", user, err)
					}

					// Verify that the number of returned roles does not exceed maxHierarchyLevel
					if len(implicitRoles) > tc.maxLevel {
						t.Errorf("GetImplicitRolesForUser(%s): got %d roles, should not exceed maxHierarchyLevel %d",
							user, len(implicitRoles), tc.maxLevel)
					}
				}
			})
		})
	}
}

func testGetImplicitObjectPatternsForUser(t *testing.T, e *Enforcer, user string, domain string, action string, res []string) {
	t.Helper()
	myRes, err := e.GetImplicitObjectPatternsForUser(user, domain, action)
	if err != nil {
		t.Error("Implicit object patterns for ", user, " under domain ", domain, " with action ", action, " could not be fetched: ", err.Error())
	}
	t.Log("Implicit object patterns for ", user, " under domain ", domain, " with action ", action, ": ", myRes)

	if !util.SetEquals(res, myRes) {
		t.Error("Implicit object patterns for ", user, " under domain ", domain, " with action ", action, ": ", myRes, ", supposed to be ", res)
	}
}

func TestGetImplicitObjectPatternsForUser(t *testing.T) {
	// Test with domain pattern model
	e, _ := NewEnforcer("examples/rbac_with_domain_pattern_model.conf", "examples/rbac_with_domain_pattern_policy.csv")
	e.AddNamedDomainMatchingFunc("g", "KeyMatch", util.KeyMatch)

	// Test case 1: admin user with wildcard domain access
	testGetImplicitObjectPatternsForUser(t, e, "admin", "domain1", "read", []string{"data1", "data3"})
	testGetImplicitObjectPatternsForUser(t, e, "admin", "domain1", "write", []string{"data1"})

	// Test case 2: alice user inheriting admin role in domain2
	testGetImplicitObjectPatternsForUser(t, e, "alice", "domain2", "read", []string{"data2", "data3"})
	testGetImplicitObjectPatternsForUser(t, e, "alice", "domain2", "write", []string{"data2"})

	// Test case 3: bob user with specific domain access
	testGetImplicitObjectPatternsForUser(t, e, "bob", "domain2", "read", []string{"data2", "data3"})
	testGetImplicitObjectPatternsForUser(t, e, "bob", "domain2", "write", []string{"data2"})

	// Test case 4: non-existent domain (admin has wildcard access to data3)
	testGetImplicitObjectPatternsForUser(t, e, "admin", "non_existent", "read", []string{"data3"})

	// Test case 5: non-existent action
	testGetImplicitObjectPatternsForUser(t, e, "admin", "domain1", "non_existent", []string{})
}

func TestNamedPermissionsForUserWithDifferentColumnOrder(t *testing.T) {
	text := `
[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = sub, dom, obj, act
p2 = dom, sub, obj, act

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && r.obj == p.obj && r.act == p.act
`
	m, err := model.NewModelFromString(text)
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewEnforcer(m)
	if err != nil {
		t.Fatal(err)
	}

	if _, err = e.AddNamedPolicy("p2", "tenant1", "alice", "report1", "read"); err != nil {
		t.Fatal(err)
	}
	if _, err = e.AddNamedPolicy("p2", "tenant1", "bob", "report2", "read"); err != nil {
		t.Fatal(err)
	}

	got, err := e.GetNamedPermissionsForUser("p2", "alice")
	if err != nil {
		t.Fatal(err)
	}
	expected := [][]string{{"tenant1", "alice", "report1", "read"}}
	if !util.Array2DEquals(got, expected) {
		t.Errorf("GetNamedPermissionsForUser(\"p2\", \"alice\") = %v, want %v", got, expected)
	}

	got, err = e.GetNamedPermissionsForUser("p2", "alice", "tenant1")
	if err != nil {
		t.Fatal(err)
	}
	if !util.Array2DEquals(got, expected) {
		t.Errorf("GetNamedPermissionsForUser(\"p2\", \"alice\", \"tenant1\") = %v, want %v", got, expected)
	}
}
