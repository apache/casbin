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

package model

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/casbin/casbin/v3/constant"
	"github.com/casbin/casbin/v3/rbac"
	"github.com/casbin/casbin/v3/util"
)

type (
	PolicyOp int
)

const (
	PolicyAdd PolicyOp = iota
	PolicyRemove
)

const DefaultSep = ","

// BuildIncrementalRoleLinks provides incremental build the role inheritance relations.
func (model Model) BuildIncrementalRoleLinks(rmMap map[string]rbac.RoleManager, op PolicyOp, sec string, ptype string, rules [][]string) error {
	if sec == "g" && rmMap[ptype] != nil {
		_, err := model.GetAssertion(sec, ptype)
		if err != nil {
			return err
		}
		return model[sec][ptype].buildIncrementalRoleLinks(rmMap[ptype], op, rules)
	}
	return nil
}

// BuildRoleLinks initializes the roles in RBAC.
func (model Model) BuildRoleLinks(rmMap map[string]rbac.RoleManager) error {
	model.PrintPolicy()
	for ptype, ast := range model["g"] {
		if rm := rmMap[ptype]; rm != nil {
			err := ast.buildRoleLinks(rm)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// BuildIncrementalConditionalRoleLinks provides incremental build the role inheritance relations.
func (model Model) BuildIncrementalConditionalRoleLinks(condRmMap map[string]rbac.ConditionalRoleManager, op PolicyOp, sec string, ptype string, rules [][]string) error {
	if sec == "g" && condRmMap[ptype] != nil {
		_, err := model.GetAssertion(sec, ptype)
		if err != nil {
			return err
		}
		return model[sec][ptype].buildIncrementalConditionalRoleLinks(condRmMap[ptype], op, rules)
	}
	return nil
}

// BuildConditionalRoleLinks initializes the roles in RBAC.
func (model Model) BuildConditionalRoleLinks(condRmMap map[string]rbac.ConditionalRoleManager) error {
	model.PrintPolicy()
	for ptype, ast := range model["g"] {
		if condRm := condRmMap[ptype]; condRm != nil {
			err := ast.buildConditionalRoleLinks(condRm)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// PrintPolicy prints the policy to log.
func (model Model) PrintPolicy() {
	// Logger has been removed - this is now a no-op
}

// ClearPolicy clears all current policy.
func (model Model) ClearPolicy() {
	for _, ast := range model["p"] {
		ast.Policy = nil
		ast.PolicyMap = map[string]int{}
		ast.PolicyVersion++
	}

	for _, ast := range model["g"] {
		ast.Policy = nil
		ast.PolicyMap = map[string]int{}
		ast.PolicyVersion++
	}
}

// GetPolicy gets all rules in a policy.
func (model Model) GetPolicy(sec string, ptype string) ([][]string, error) {
	_, err := model.GetAssertion(sec, ptype)
	if err != nil {
		return nil, err
	}
	return model[sec][ptype].Policy, nil
}

// GetFilteredPolicy gets rules based on field filters from a policy.
func (model Model) GetFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) ([][]string, error) {
	_, err := model.GetAssertion(sec, ptype)
	if err != nil {
		return nil, err
	}
	res := [][]string{}

	for _, rule := range model[sec][ptype].Policy {
		matched := true
		for i, fieldValue := range fieldValues {
			if fieldValue != "" && rule[fieldIndex+i] != fieldValue {
				matched = false
				break
			}
		}

		if matched {
			res = append(res, rule)
		}
	}

	return res, nil
}

// HasPolicyEx determines whether a model has the specified policy rule with error.
func (model Model) HasPolicyEx(sec string, ptype string, rule []string) (bool, error) {
	assertion, err := model.GetAssertion(sec, ptype)
	if err != nil {
		return false, err
	}
	switch sec {
	case "p":
		if len(rule) != len(assertion.Tokens) {
			return false, fmt.Errorf(
				"invalid policy rule size: expected %d, got %d, rule: %v",
				len(model["p"][ptype].Tokens),
				len(rule),
				rule)
		}
	case "g":
		if len(rule) < len(assertion.Tokens) {
			return false, fmt.Errorf(
				"invalid policy rule size: expected %d, got %d, rule: %v",
				len(model["g"][ptype].Tokens),
				len(rule),
				rule)
		}
	}
	return model.HasPolicy(sec, ptype, rule)
}

// HasPolicy determines whether a model has the specified policy rule.
func (model Model) HasPolicy(sec string, ptype string, rule []string) (bool, error) {
	_, err := model.GetAssertion(sec, ptype)
	if err != nil {
		return false, err
	}
	_, ok := model[sec][ptype].PolicyMap[strings.Join(rule, DefaultSep)]
	return ok, nil
}

// HasPolicies determines whether a model has any of the specified policies. If one is found we return true.
func (model Model) HasPolicies(sec string, ptype string, rules [][]string) (bool, error) {
	for i := 0; i < len(rules); i++ {
		ok, err := model.HasPolicy(sec, ptype, rules[i])
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}

	return false, nil
}

// AddPolicy adds a policy rule to the model.
func (model Model) AddPolicy(sec string, ptype string, rule []string) error {
	assertion, err := model.GetAssertion(sec, ptype)
	if err != nil {
		return err
	}
	assertion.Policy = append(assertion.Policy, rule)
	assertion.PolicyMap[strings.Join(rule, DefaultSep)] = len(model[sec][ptype].Policy) - 1
	assertion.PolicyVersion++

	hasPriority := false
	if _, ok := assertion.FieldIndexMap[constant.PriorityIndex]; ok {
		hasPriority = true
	}
	if sec == "p" && hasPriority {
		if idxInsert, err := strconv.Atoi(rule[assertion.FieldIndexMap[constant.PriorityIndex]]); err == nil {
			i := len(assertion.Policy) - 1
			for ; i > 0; i-- {
				idx, err := strconv.Atoi(assertion.Policy[i-1][assertion.FieldIndexMap[constant.PriorityIndex]])
				if err != nil || idx <= idxInsert {
					break
				}
				assertion.Policy[i] = assertion.Policy[i-1]
				assertion.PolicyMap[strings.Join(assertion.Policy[i-1], DefaultSep)]++
			}
			assertion.Policy[i] = rule
			assertion.PolicyMap[strings.Join(rule, DefaultSep)] = i
		}
	}
	return nil
}

// AddPolicies adds policy rules to the model.
func (model Model) AddPolicies(sec string, ptype string, rules [][]string) error {
	_, err := model.AddPoliciesWithAffected(sec, ptype, rules)
	return err
}

// AddPoliciesWithAffected adds policy rules to the model, and returns affected rules.
func (model Model) AddPoliciesWithAffected(sec string, ptype string, rules [][]string) ([][]string, error) {
	_, err := model.GetAssertion(sec, ptype)
	if err != nil {
		return nil, err
	}
	var affected [][]string
	for _, rule := range rules {
		hashKey := strings.Join(rule, DefaultSep)
		_, ok := model[sec][ptype].PolicyMap[hashKey]
		if ok {
			continue
		}
		affected = append(affected, rule)
		err = model.AddPolicy(sec, ptype, rule)
		if err != nil {
			return affected, err
		}
	}
	return affected, err
}

// RemovePolicy removes a policy rule from the model.
func (model Model) RemovePolicy(sec string, ptype string, rule []string) (bool, error) {
	ast, err := model.GetAssertion(sec, ptype)
	if err != nil {
		return false, err
	}
	key := strings.Join(rule, DefaultSep)
	index, ok := ast.PolicyMap[key]
	if !ok {
		return false, nil
	}

	// The order of Policy is significant: it carries the priority semantics of
	// the "priority(p_eft)" effector, both for explicit priority models and for
	// implicit ones where the priority is the policy order itself. So the rule
	// has to be shifted out instead of being swapped with the last one.
	ast.Policy = append(ast.Policy[:index], ast.Policy[index+1:]...)
	delete(ast.PolicyMap, key)
	for i := index; i < len(ast.Policy); i++ {
		ast.PolicyMap[strings.Join(ast.Policy[i], DefaultSep)] = i
	}
	ast.PolicyVersion++
	return true, nil
}

// UpdatePolicy updates a policy rule from the model.
func (model Model) UpdatePolicy(sec string, ptype string, oldRule []string, newRule []string) (bool, error) {
	_, err := model.GetAssertion(sec, ptype)
	if err != nil {
		return false, err
	}
	oldPolicy := strings.Join(oldRule, DefaultSep)
	index, ok := model[sec][ptype].PolicyMap[oldPolicy]
	if !ok {
		return false, nil
	}

	model[sec][ptype].Policy[index] = newRule
	delete(model[sec][ptype].PolicyMap, oldPolicy)
	model[sec][ptype].PolicyMap[strings.Join(newRule, DefaultSep)] = index
	model[sec][ptype].PolicyVersion++

	return true, nil
}

// UpdatePolicies updates a policy rule from the model.
func (model Model) UpdatePolicies(sec string, ptype string, oldRules, newRules [][]string) (bool, error) {
	assertion, err := model.GetAssertion(sec, ptype)
	if err != nil {
		return false, err
	}
	if len(oldRules) != len(newRules) {
		return false, fmt.Errorf("the length of oldRules should be equal to the length of newRules, but got the length of oldRules is %d, the length of newRules is %d", len(oldRules), len(newRules))
	}

	// Resolve all indexes before writing, since newRules may reuse keys of oldRules.
	indexes := make([]int, len(oldRules))
	seen := make(map[int]bool, len(oldRules))
	for i, oldRule := range oldRules {
		index, ok := assertion.PolicyMap[strings.Join(oldRule, DefaultSep)]
		if !ok || seen[index] {
			return false, nil
		}
		seen[index] = true
		indexes[i] = index
	}

	for _, oldRule := range oldRules {
		delete(assertion.PolicyMap, strings.Join(oldRule, DefaultSep))
	}
	for i, newRule := range newRules {
		assertion.Policy[indexes[i]] = newRule
		assertion.PolicyMap[strings.Join(newRule, DefaultSep)] = indexes[i]
	}
	assertion.PolicyVersion++

	return true, nil
}

// RemovePolicies removes policy rules from the model.
func (model Model) RemovePolicies(sec string, ptype string, rules [][]string) (bool, error) {
	affected, err := model.RemovePoliciesWithAffected(sec, ptype, rules)
	return len(affected) != 0, err
}

// RemovePoliciesWithAffected removes policy rules from the model, and returns affected rules.
func (model Model) RemovePoliciesWithAffected(sec string, ptype string, rules [][]string) ([][]string, error) {
	assertion, err := model.GetAssertion(sec, ptype)
	if err != nil {
		return nil, err
	}

	var affected [][]string
	removeSet := make(map[string]struct{}, len(rules))

	for _, rule := range rules {
		key := strings.Join(rule, DefaultSep)
		if _, ok := assertion.PolicyMap[key]; !ok {
			continue
		}
		if _, exists := removeSet[key]; exists {
			continue
		}
		affected = append(affected, rule)
		removeSet[key] = struct{}{}
	}

	if len(removeSet) == 0 {
		return affected, nil
	}

	compactPolicy := assertion.Policy[:0]
	compactPolicyMap := make(map[string]int, len(assertion.Policy)-len(removeSet))
	for _, policyRule := range assertion.Policy {
		key := strings.Join(policyRule, DefaultSep)
		if _, ok := removeSet[key]; ok {
			continue
		}
		compactPolicyMap[key] = len(compactPolicy)
		compactPolicy = append(compactPolicy, policyRule)
	}

	assertion.Policy = compactPolicy
	assertion.PolicyMap = compactPolicyMap
	assertion.PolicyVersion++

	return affected, nil
}

// RemoveFilteredPolicy removes policy rules based on field filters from the model.
func (model Model) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) (bool, [][]string, error) {
	_, err := model.GetAssertion(sec, ptype)
	if err != nil {
		return false, nil, err
	}
	var tmp [][]string
	var effects [][]string
	res := false
	model[sec][ptype].PolicyMap = map[string]int{}

	for _, rule := range model[sec][ptype].Policy {
		matched := true
		for i, fieldValue := range fieldValues {
			if fieldValue != "" && rule[fieldIndex+i] != fieldValue {
				matched = false
				break
			}
		}

		if matched {
			effects = append(effects, rule)
		} else {
			tmp = append(tmp, rule)
			model[sec][ptype].PolicyMap[strings.Join(rule, DefaultSep)] = len(tmp) - 1
		}
	}

	if len(tmp) != len(model[sec][ptype].Policy) {
		model[sec][ptype].Policy = tmp
		model[sec][ptype].PolicyVersion++
		res = true
	}

	return res, effects, nil
}

// GetValuesForFieldInPolicy gets all values for a field for all rules in a policy, duplicated values are removed.
func (model Model) GetValuesForFieldInPolicy(sec string, ptype string, fieldIndex int) ([]string, error) {
	values := []string{}

	_, err := model.GetAssertion(sec, ptype)
	if err != nil {
		return nil, err
	}

	for _, rule := range model[sec][ptype].Policy {
		values = append(values, rule[fieldIndex])
	}

	util.ArrayRemoveDuplicates(&values)

	return values, nil
}

// GetValuesForFieldInPolicyAllTypes gets all values for a field for all rules in a policy of all ptypes, duplicated values are removed.
func (model Model) GetValuesForFieldInPolicyAllTypes(sec string, fieldIndex int) ([]string, error) {
	values := []string{}

	for ptype := range model[sec] {
		v, err := model.GetValuesForFieldInPolicy(sec, ptype, fieldIndex)
		if err != nil {
			return nil, err
		}
		values = append(values, v...)
	}

	util.ArrayRemoveDuplicates(&values)

	return values, nil
}

// GetValuesForFieldInPolicyAllTypesByName gets all values for a field for all rules in a policy of all ptypes, duplicated values are removed.
func (model Model) GetValuesForFieldInPolicyAllTypesByName(sec string, field string) ([]string, error) {
	values := []string{}

	for ptype := range model[sec] {
		// GetFieldIndex will return (-1, err) if field is not found, ignore it
		index, err := model.GetFieldIndex(ptype, field)
		if err != nil {
			continue
		}
		v, err := model.GetValuesForFieldInPolicy(sec, ptype, index)
		if err != nil {
			return nil, err
		}
		values = append(values, v...)
	}

	util.ArrayRemoveDuplicates(&values)

	return values, nil
}
