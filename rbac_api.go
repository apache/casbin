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
	"strings"

	"github.com/casbin/casbin/v3/rbac"

	"github.com/casbin/casbin/v3/constant"
	"github.com/casbin/casbin/v3/errors"
	"github.com/casbin/casbin/v3/util"
)

// GetRolesForUser gets the roles that a user has.
func (e *Enforcer) GetRolesForUser(name string, domain ...string) ([]string, error) {
	rm := e.GetRoleManager()
	if rm == nil {
		return nil, fmt.Errorf("role manager is not initialized")
	}
	res, err := rm.GetRoles(name, domain...)
	return res, err
}

// GetUsersForRole gets the users that has a role.
func (e *Enforcer) GetUsersForRole(name string, domain ...string) ([]string, error) {
	rm := e.GetRoleManager()
	if rm == nil {
		return nil, fmt.Errorf("role manager is not initialized")
	}
	res, err := rm.GetUsers(name, domain...)
	return res, err
}

// HasRoleForUser determines whether a user has a role.
func (e *Enforcer) HasRoleForUser(name string, role string, domain ...string) (bool, error) {
	roles, err := e.GetRolesForUser(name, domain...)
	if err != nil {
		return false, err
	}
	hasRole := false
	for _, r := range roles {
		if r == role {
			hasRole = true
			break
		}
	}

	return hasRole, nil
}

// AddRoleForUser adds a role for a user.
// Returns false if the user already has the role (aka not affected).
func (e *Enforcer) AddRoleForUser(user string, role string, domain ...string) (bool, error) {
	args := []string{user, role}
	args = append(args, domain...)
	return e.AddGroupingPolicy(args)
}

// AddRolesForUser adds roles for a user.
// Returns false if the user already has the roles (aka not affected).
func (e *Enforcer) AddRolesForUser(user string, roles []string, domain ...string) (bool, error) {
	var rules [][]string
	for _, role := range roles {
		rule := []string{user, role}
		rule = append(rule, domain...)
		rules = append(rules, rule)
	}
	return e.AddGroupingPolicies(rules)
}

// DeleteRoleForUser deletes a role for a user.
// Returns false if the user does not have the role (aka not affected).
func (e *Enforcer) DeleteRoleForUser(user string, role string, domain ...string) (bool, error) {
	args := []string{user, role}
	args = append(args, domain...)
	return e.RemoveGroupingPolicy(args)
}

// DeleteRolesForUser deletes all roles for a user.
// Returns false if the user does not have any roles (aka not affected).
func (e *Enforcer) DeleteRolesForUser(user string, domain ...string) (bool, error) {
	var args []string
	if len(domain) == 0 {
		args = []string{user}
	} else if len(domain) > 1 {
		return false, errors.ErrDomainParameter
	} else {
		args = []string{user, "", domain[0]}
	}
	return e.RemoveFilteredGroupingPolicy(0, args...)
}

// DeleteUser deletes a user.
// Returns false if the user does not exist (aka not affected).
func (e *Enforcer) DeleteUser(user string) (bool, error) {
	var err error
	res1, err := e.RemoveFilteredGroupingPolicy(0, user)
	if err != nil {
		return res1, err
	}

	subIndex, err := e.GetFieldIndex("p", constant.SubjectIndex)
	if err != nil {
		return false, err
	}
	res2, err := e.RemoveFilteredPolicy(subIndex, user)
	return res1 || res2, err
}

// DeleteRole deletes a role.
// Returns false if the role does not exist (aka not affected).
func (e *Enforcer) DeleteRole(role string) (bool, error) {
	var err error
	res1, err := e.RemoveFilteredGroupingPolicy(0, role)
	if err != nil {
		return res1, err
	}

	res2, err := e.RemoveFilteredGroupingPolicy(1, role)
	if err != nil {
		return res1, err
	}

	subIndex, err := e.GetFieldIndex("p", constant.SubjectIndex)
	if err != nil {
		return false, err
	}
	res3, err := e.RemoveFilteredPolicy(subIndex, role)
	return res1 || res2 || res3, err
}

// DeletePermission deletes a permission.
// Returns false if the permission does not exist (aka not affected).
func (e *Enforcer) DeletePermission(permission ...string) (bool, error) {
	return e.RemoveFilteredPolicy(1, permission...)
}

// AddPermissionForUser adds a permission for a user or role.
// Returns false if the user or role already has the permission (aka not affected).
func (e *Enforcer) AddPermissionForUser(user string, permission ...string) (bool, error) {
	return e.AddPolicy(util.JoinSlice(user, permission...))
}

// AddPermissionsForUser adds multiple permissions for a user or role.
// Returns false if the user or role already has one of the permissions (aka not affected).
func (e *Enforcer) AddPermissionsForUser(user string, permissions ...[]string) (bool, error) {
	var rules [][]string
	for _, permission := range permissions {
		rules = append(rules, util.JoinSlice(user, permission...))
	}
	return e.AddPolicies(rules)
}

// DeletePermissionForUser deletes a permission for a user or role.
// Returns false if the user or role does not have the permission (aka not affected).
func (e *Enforcer) DeletePermissionForUser(user string, permission ...string) (bool, error) {
	return e.RemovePolicy(util.JoinSlice(user, permission...))
}

// DeletePermissionsForUser deletes permissions for a user or role.
// Returns false if the user or role does not have any permissions (aka not affected).
func (e *Enforcer) DeletePermissionsForUser(user string) (bool, error) {
	subIndex, err := e.GetFieldIndex("p", constant.SubjectIndex)
	if err != nil {
		return false, err
	}
	return e.RemoveFilteredPolicy(subIndex, user)
}

// GetPermissionsForUser gets permissions for a user or role.
func (e *Enforcer) GetPermissionsForUser(user string, domain ...string) ([][]string, error) {
	return e.GetNamedPermissionsForUser("p", user, domain...)
}

// GetNamedPermissionsForUser gets permissions for a user or role by named policy.
func (e *Enforcer) GetNamedPermissionsForUser(ptype string, user string, domain ...string) ([][]string, error) {
	permission := make([][]string, 0)
	for pType, assertion := range e.model["p"] {
		if pType != ptype {
			continue
		}
		args := make([]string, len(assertion.Tokens))
		subIndex, err := e.GetFieldIndex(ptype, constant.SubjectIndex)
		if err != nil {
			subIndex = 0
		}
		args[subIndex] = user

		if len(domain) > 0 {
			var index int
			index, err = e.GetFieldIndex(ptype, constant.DomainIndex)
			if err != nil {
				return permission, err
			}
			args[index] = domain[0]
		}
		perm, err := e.GetFilteredNamedPolicy(ptype, 0, args...)
		if err != nil {
			return permission, err
		}
		permission = append(permission, perm...)
	}
	return permission, nil
}

// HasPermissionForUser determines whether a user has a permission.
func (e *Enforcer) HasPermissionForUser(user string, permission ...string) (bool, error) {
	return e.HasPolicy(util.JoinSlice(user, permission...))
}

// GetImplicitRolesForUser gets implicit roles that a user has.
// Compared to GetRolesForUser(), this function retrieves indirect roles besides direct roles.
// For example:
// g, alice, role:admin
// g, role:admin, role:user
//
// GetRolesForUser("alice") can only get: ["role:admin"].
// But GetImplicitRolesForUser("alice") will get: ["role:admin", "role:user"].
func (e *Enforcer) GetImplicitRolesForUser(name string, domain ...string) ([]string, error) {
	var res []string

	for rm := range e.rmMap {
		roles, err := e.GetNamedImplicitRolesForUser(rm, name, domain...)
		if err != nil {
			return nil, err
		}
		res = append(res, roles...)
	}

	for crm := range e.condRmMap {
		roles, err := e.GetNamedImplicitRolesForUser(crm, name, domain...)
		if err != nil {
			return nil, err
		}
		res = append(res, roles...)
	}

	return res, nil
}

// GetNamedImplicitRolesForUser gets implicit roles that a user has by named role definition.
// Compared to GetImplicitRolesForUser(), this function retrieves indirect roles besides direct roles.
// For example:
// g, alice, role:admin
// g, role:admin, role:user
// g2, alice, role:admin2
//
// GetImplicitRolesForUser("alice") can only get: ["role:admin", "role:user"].
// But GetNamedImplicitRolesForUser("g2", "alice") will get: ["role:admin2"].
func (e *Enforcer) GetNamedImplicitRolesForUser(ptype string, name string, domain ...string) ([]string, error) {
	rm := e.GetNamedRoleManager(ptype)
	if rm == nil {
		return nil, fmt.Errorf("role manager %s is not initialized", ptype)
	}

	// Use the role manager's GetImplicitRoles method which respects maxHierarchyLevel
	return rm.GetImplicitRoles(name, domain...)
}

// GetImplicitUsersForRole gets implicit users for a role.
func (e *Enforcer) GetImplicitUsersForRole(name string, domain ...string) ([]string, error) {
	res := []string{}
	var rms []rbac.RoleManager

	for _, rm := range e.rmMap {
		rms = append(rms, rm)
	}
	for _, crm := range e.condRmMap {
		rms = append(rms, crm)
	}

	for _, rm := range rms {
		// Use the role manager's GetImplicitUsers method which respects maxHierarchyLevel
		users, err := rm.GetImplicitUsers(name, domain...)
		if err != nil && err.Error() != "error: name does not exist" {
			return nil, err
		}
		res = append(res, users...)
	}

	return res, nil
}

// GetImplicitPermissionsForUser gets implicit permissions for a user or role.
// Compared to GetPermissionsForUser(), this function retrieves permissions for inherited roles.
// For example:
// p, admin, data1, read
// p, alice, data2, read
// g, alice, admin
//
// GetPermissionsForUser("alice") can only get: [["alice", "data2", "read"]].
// But GetImplicitPermissionsForUser("alice") will get: [["admin", "data1", "read"], ["alice", "data2", "read"]].
func (e *Enforcer) GetImplicitPermissionsForUser(user string, domain ...string) ([][]string, error) {
	return e.GetNamedImplicitPermissionsForUser("p", "g", user, domain...)
}

// GetNamedImplicitPermissionsForUser gets implicit permissions for a user or role by named policy.
// Compared to GetNamedPermissionsForUser(), this function retrieves permissions for inherited roles.
// For example:
// p, admin, data1, read
// p2, admin, create
// g, alice, admin
//
// GetImplicitPermissionsForUser("alice") can only get: [["admin", "data1", "read"]], whose policy is default policy "p"
// But you can specify the named policy "p2" to get: [["admin", "create"]] by    GetNamedImplicitPermissionsForUser("p2","alice").
func (e *Enforcer) GetNamedImplicitPermissionsForUser(ptype string, gtype string, user string, domain ...string) ([][]string, error) {
	permission := make([][]string, 0)
	rm := e.GetNamedRoleManager(gtype)
	if rm == nil {
		return nil, fmt.Errorf("role manager %s is not initialized", gtype)
	}

	roles, err := e.GetNamedImplicitRolesForUser(gtype, user, domain...)
	if err != nil {
		return nil, err
	}
	policyRoles := make(map[string]struct{}, len(roles)+1)
	policyRoles[user] = struct{}{}
	for _, r := range roles {
		policyRoles[r] = struct{}{}
	}

	domainIndex, err := e.GetFieldIndex(ptype, constant.DomainIndex)
	for _, rule := range e.model["p"][ptype].Policy {
		if len(domain) == 0 {
			if _, ok := policyRoles[rule[0]]; ok {
				permission = append(permission, deepCopyPolicy(rule))
			}
			continue
		}
		if len(domain) > 1 {
			return nil, errors.ErrDomainParameter
		}
		if err != nil {
			return nil, err
		}
		d := domain[0]
		matched := rm.Match(d, rule[domainIndex])
		if !matched {
			continue
		}
		if _, ok := policyRoles[rule[0]]; ok {
			newRule := deepCopyPolicy(rule)
			newRule[domainIndex] = d
			permission = append(permission, newRule)
		}
	}
	return permission, nil
}

// GetImplicitUsersForPermission gets implicit users for a permission.
// For example:
// p, admin, data1, read
// p, bob, data1, read
// g, alice, admin
//
// GetImplicitUsersForPermission("data1", "read") will get: ["alice", "bob"].
// Note: only users will be returned, roles (2nd arg in "g") will be excluded.
func (e *Enforcer) GetImplicitUsersForPermission(permission ...string) ([]string, error) {
	pSubjects, err := e.GetAllSubjects()
	if err != nil {
		return nil, err
	}
	gInherit, err := e.model.GetValuesForFieldInPolicyAllTypes("g", 1)
	if err != nil {
		return nil, err
	}
	gSubjects, err := e.model.GetValuesForFieldInPolicyAllTypes("g", 0)
	if err != nil {
		return nil, err
	}

	subjects := append(pSubjects, gSubjects...)
	util.ArrayRemoveDuplicates(&subjects)

	subjects = util.SetSubtract(subjects, gInherit)

	res := []string{}
	for _, user := range subjects {
		req := util.JoinSliceAny(user, permission...)
		allowed, err := e.Enforce(req...)
		if err != nil {
			return nil, err
		}

		if allowed {
			res = append(res, user)
		}
	}

	return res, nil
}

// GetDomainsForUser gets all domains.
func (e *Enforcer) GetDomainsForUser(user string) ([]string, error) {
	var domains []string
	for _, rm := range e.rmMap {
		domain, err := rm.GetDomains(user)
		if err != nil {
			return nil, err
		}
		domains = append(domains, domain...)
	}
	for _, crm := range e.condRmMap {
		domain, err := crm.GetDomains(user)
		if err != nil {
			return nil, err
		}
		domains = append(domains, domain...)
	}
	return domains, nil
}

// GetImplicitResourcesForUser returns all policies that user obtaining in domain.
func (e *Enforcer) GetImplicitResourcesForUser(user string, domain ...string) ([][]string, error) {
	permissions, err := e.GetImplicitPermissionsForUser(user, domain...)
	if err != nil {
		return nil, err
	}
	res := make([][]string, 0)
	for _, permission := range permissions {
		if permission[0] == user {
			res = append(res, permission)
			continue
		}
		resLocal := [][]string{{user}}
		tokensLength := len(permission)
		t := make([][]string, 1, tokensLength)
		for _, token := range permission[1:] {
			tokens, err := e.GetImplicitUsersForRole(token, domain...)
			if err != nil {
				return nil, err
			}
			tokens = append(tokens, token)
			t = append(t, tokens)
		}
		for i := 1; i < tokensLength; i++ {
			n := make([][]string, 0)
			for _, tokens := range t[i] {
				for _, policy := range resLocal {
					t := append([]string(nil), policy...)
					t = append(t, tokens)
					n = append(n, t)
				}
			}
			resLocal = n
		}
		res = append(res, resLocal...)
	}
	return res, nil
}

// deepCopyPolicy returns a deepcopy version of the policy to prevent changing policies through returned slice.
func deepCopyPolicy(src []string) []string {
	newRule := make([]string, len(src))
	copy(newRule, src)
	return newRule
}

// GetAllowedObjectConditions returns a string array of object conditions that the user can access.
// For example: conditions, err := e.GetAllowedObjectConditions("alice", "read", "r.obj.")
// Note:
//
// 0. prefix: You can customize the prefix of the object conditions, and "r.obj." is commonly used as a prefix.
// After removing the prefix, the remaining part is the condition of the object.
// If there is an obj policy that does not meet the prefix requirement, an errors.ERR_OBJ_CONDITION will be returned.
//
// 1. If the 'objectConditions' array is empty, return errors.ERR_EMPTY_CONDITION
// This error is returned because some data adapters' ORM return full table data by default
// when they receive an empty condition, which tends to behave contrary to expectations.(e.g. GORM)
// If you are using an adapter that does not behave like this, you can choose to ignore this error.
func (e *Enforcer) GetAllowedObjectConditions(user string, action string, prefix string) ([]string, error) {
	permissions, err := e.GetImplicitPermissionsForUser(user)
	if err != nil {
		return nil, err
	}

	var objectConditions []string
	for _, policy := range permissions {
		// policy {sub, obj, act}
		if policy[2] == action {
			if !strings.HasPrefix(policy[1], prefix) {
				return nil, errors.ErrObjCondition
			}
			objectConditions = append(objectConditions, strings.TrimPrefix(policy[1], prefix))
		}
	}

	if len(objectConditions) == 0 {
		return nil, errors.ErrEmptyCondition
	}

	return objectConditions, nil
}

// removeDuplicatePermissions Convert permissions to string as a hash to deduplicate.
func removeDuplicatePermissions(permissions [][]string) [][]string {
	permissionsSet := make(map[string]bool)
	res := make([][]string, 0)
	for _, permission := range permissions {
		permissionStr := util.ArrayToString(permission)
		if permissionsSet[permissionStr] {
			continue
		}
		permissionsSet[permissionStr] = true
		res = append(res, permission)
	}
	return res
}

// GetImplicitUsersForResource return implicit user based on resource.
// for example:
// p, alice, data1, read
// p, bob, data2, write
// p, data2_admin, data2, read
// p, data2_admin, data2, write
// g, alice, data2_admin
// GetImplicitUsersForResource("data2") will return [[bob data2 write] [alice data2 read] [alice data2 write]]
// GetImplicitUsersForResource("data1") will return [[alice data1 read]]
// Note: only users will be returned, roles (2nd arg in "g") will be excluded.
func (e *Enforcer) GetImplicitUsersForResource(resource string) ([][]string, error) {
	return e.GetNamedImplicitUsersForResource("g", resource)
}

// GetNamedImplicitUsersForResource return implicit user based on resource with named policy support.
// This function handles resource role relationships through named policies (e.g., g2, g3, etc.).
// for example:
// p, admin_group, admin_data, *
// g, admin, admin_group
// g2, app, admin_data
// GetNamedImplicitUsersForResource("g2", "app") will return users who have access to admin_data through g2 relationship.
func (e *Enforcer) GetNamedImplicitUsersForResource(ptype string, resource string) ([][]string, error) {
	permissions := make([][]string, 0)
	subjectIndex, _ := e.GetFieldIndex("p", "sub")
	objectIndex, _ := e.GetFieldIndex("p", "obj")
	rm := e.GetRoleManager()
	if rm == nil {
		return nil, fmt.Errorf("role manager is not initialized")
	}

	isRole := make(map[string]bool)
	roles, err := e.GetAllRoles()
	if err != nil {
		return nil, err
	}
	for _, role := range roles {
		isRole[role] = true
	}

	// Get all resource types that the resource can access through ptype (e.g., g2)
	ptypePolicies, _ := e.GetNamedGroupingPolicy(ptype)
	resourceAccessibleResourceTypes := make(map[string]bool)

	for _, ptypePolicy := range ptypePolicies {
		if ptypePolicy[0] == resource { // ptypePolicy[0] is the resource
			resourceAccessibleResourceTypes[ptypePolicy[1]] = true // ptypePolicy[1] is the resource type it can access
		}
	}

	for _, rule := range e.model["p"]["p"].Policy {
		obj := rule[objectIndex]
		sub := rule[subjectIndex]

		// Check if this policy is directly for the resource OR for a resource type the resource can access
		if obj == resource || resourceAccessibleResourceTypes[obj] {
			if !isRole[sub] {
				permissions = append(permissions, rule)
			} else {
				users, err := rm.GetUsers(sub)
				if err != nil {
					continue
				}

				for _, user := range users {
					implicitUserRule := deepCopyPolicy(rule)
					implicitUserRule[subjectIndex] = user
					permissions = append(permissions, implicitUserRule)
				}
			}
		}
	}

	res := removeDuplicatePermissions(permissions)
	return res, nil
}

// GetImplicitUsersForResourceByDomain return implicit user based on resource and domain.
// Compared to GetImplicitUsersForResource, domain is supported.
func (e *Enforcer) GetImplicitUsersForResourceByDomain(resource string, domain string) ([][]string, error) {
	permissions := make([][]string, 0)
	subjectIndex, _ := e.GetFieldIndex("p", "sub")
	objectIndex, _ := e.GetFieldIndex("p", "obj")
	domIndex, _ := e.GetFieldIndex("p", "dom")
	rm := e.GetRoleManager()
	if rm == nil {
		return nil, fmt.Errorf("role manager is not initialized")
	}

	isRole := make(map[string]bool)

	if roles, err := e.GetAllRolesByDomain(domain); err != nil {
		return nil, err
	} else {
		for _, role := range roles {
			isRole[role] = true
		}
	}

	for _, rule := range e.model["p"]["p"].Policy {
		obj := rule[objectIndex]
		if obj != resource {
			continue
		}

		sub := rule[subjectIndex]

		if !isRole[sub] {
			permissions = append(permissions, rule)
		} else {
			if domain != rule[domIndex] {
				continue
			}
			users, err := rm.GetUsers(sub, domain)
			if err != nil {
				return nil, err
			}

			for _, user := range users {
				implicitUserRule := deepCopyPolicy(rule)
				implicitUserRule[subjectIndex] = user
				permissions = append(permissions, implicitUserRule)
			}
		}
	}

	res := removeDuplicatePermissions(permissions)
	return res, nil
}

// GetImplicitObjectPatternsForUser returns all object patterns (with wildcards) that a user has for a given domain and action.
// For example:
// p, admin, chronicle/123, location/*, read
// p, user, chronicle/456, location/789, read
// g, alice, admin
// g, bob, user
//
// GetImplicitObjectPatternsForUser("alice", "chronicle/123", "read") will return ["location/*"].
// GetImplicitObjectPatternsForUser("bob", "chronicle/456", "read") will return ["location/789"].
func (e *Enforcer) GetImplicitObjectPatternsForUser(user string, domain string, action string) ([]string, error) {
	roles, err := e.GetImplicitRolesForUser(user, domain)
	if err != nil {
		return nil, err
	}

	subjects := append([]string{user}, roles...)
	subjectIndex, _ := e.GetFieldIndex("p", constant.SubjectIndex)
	domainIndex, _ := e.GetFieldIndex("p", constant.DomainIndex)
	objectIndex, _ := e.GetFieldIndex("p", constant.ObjectIndex)
	actionIndex, _ := e.GetFieldIndex("p", constant.ActionIndex)

	patterns := make(map[string]struct{})
	for _, rule := range e.model["p"]["p"].Policy {
		sub := rule[subjectIndex]
		matched := false
		for _, subject := range subjects {
			if sub == subject {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}

		if !e.matchDomain(domainIndex, domain, rule) {
			continue
		}

		ruleAction := rule[actionIndex]
		if ruleAction != action && ruleAction != "*" {
			continue
		}

		obj := rule[objectIndex]
		patterns[obj] = struct{}{}
	}

	result := make([]string, 0, len(patterns))
	for pattern := range patterns {
		result = append(result, pattern)
	}

	return result, nil
}

// matchDomain checks if the domain matches the rule domain using pattern matching.
func (e *Enforcer) matchDomain(domainIndex int, domain string, rule []string) bool {
	if domainIndex < 0 || domain == "" {
		return true
	}
	ruleDomain := rule[domainIndex]
	if ruleDomain == domain {
		return true
	}
	for _, rm := range e.rmMap {
		if rm.Match(domain, ruleDomain) {
			return true
		}
	}
	for _, crm := range e.condRmMap {
		if crm.Match(domain, ruleDomain) {
			return true
		}
	}
	return false
}
