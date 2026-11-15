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
	"errors"
	"fmt"
	"strings"

	"github.com/casbin/casbin/v3/constant"
	"github.com/casbin/casbin/v3/util"
	"github.com/casbin/govaluate"
)

// GetAllSubjects gets the list of subjects that show up in the current policy.
func (e *Enforcer) GetAllSubjects() ([]string, error) {
	return e.model.GetValuesForFieldInPolicyAllTypesByName("p", constant.SubjectIndex)
}

// GetAllNamedSubjects gets the list of subjects that show up in the current named policy.
func (e *Enforcer) GetAllNamedSubjects(ptype string) ([]string, error) {
	fieldIndex, err := e.model.GetFieldIndex(ptype, constant.SubjectIndex)
	if err != nil {
		return nil, err
	}
	return e.model.GetValuesForFieldInPolicy("p", ptype, fieldIndex)
}

// GetAllObjects gets the list of objects that show up in the current policy.
func (e *Enforcer) GetAllObjects() ([]string, error) {
	return e.model.GetValuesForFieldInPolicyAllTypesByName("p", constant.ObjectIndex)
}

// GetAllNamedObjects gets the list of objects that show up in the current named policy.
func (e *Enforcer) GetAllNamedObjects(ptype string) ([]string, error) {
	fieldIndex, err := e.model.GetFieldIndex(ptype, constant.ObjectIndex)
	if err != nil {
		return nil, err
	}
	return e.model.GetValuesForFieldInPolicy("p", ptype, fieldIndex)
}

// GetAllActions gets the list of actions that show up in the current policy.
func (e *Enforcer) GetAllActions() ([]string, error) {
	return e.model.GetValuesForFieldInPolicyAllTypesByName("p", constant.ActionIndex)
}

// GetAllNamedActions gets the list of actions that show up in the current named policy.
func (e *Enforcer) GetAllNamedActions(ptype string) ([]string, error) {
	fieldIndex, err := e.model.GetFieldIndex(ptype, constant.ActionIndex)
	if err != nil {
		return nil, err
	}
	return e.model.GetValuesForFieldInPolicy("p", ptype, fieldIndex)
}

// GetAllRoles gets the list of roles that show up in the current policy.
func (e *Enforcer) GetAllRoles() ([]string, error) {
	return e.model.GetValuesForFieldInPolicyAllTypes("g", 1)
}

// GetAllNamedRoles gets the list of roles that show up in the current named policy.
func (e *Enforcer) GetAllNamedRoles(ptype string) ([]string, error) {
	return e.model.GetValuesForFieldInPolicy("g", ptype, 1)
}

// GetAllUsers gets the list of users that show up in the current policy.
// Users are subjects that are not roles (i.e., subjects that do not appear as the second element in any grouping policy).
func (e *Enforcer) GetAllUsers() ([]string, error) {
	subjects, err := e.GetAllSubjects()
	if err != nil {
		return nil, err
	}

	roles, err := e.GetAllRoles()
	if err != nil {
		return nil, err
	}

	users := util.SetSubtract(subjects, roles)
	return users, nil
}

// GetPolicy gets all the authorization rules in the policy.
func (e *Enforcer) GetPolicy() ([][]string, error) {
	return e.GetNamedPolicy("p")
}

// GetFilteredPolicy gets all the authorization rules in the policy, field filters can be specified.
func (e *Enforcer) GetFilteredPolicy(fieldIndex int, fieldValues ...string) ([][]string, error) {
	return e.GetFilteredNamedPolicy("p", fieldIndex, fieldValues...)
}

// GetNamedPolicy gets all the authorization rules in the named policy.
func (e *Enforcer) GetNamedPolicy(ptype string) ([][]string, error) {
	return e.model.GetPolicy("p", ptype)
}

// GetFilteredNamedPolicy gets all the authorization rules in the named policy, field filters can be specified.
func (e *Enforcer) GetFilteredNamedPolicy(ptype string, fieldIndex int, fieldValues ...string) ([][]string, error) {
	return e.model.GetFilteredPolicy("p", ptype, fieldIndex, fieldValues...)
}

// GetGroupingPolicy gets all the role inheritance rules in the policy.
func (e *Enforcer) GetGroupingPolicy() ([][]string, error) {
	return e.GetNamedGroupingPolicy("g")
}

// GetFilteredGroupingPolicy gets all the role inheritance rules in the policy, field filters can be specified.
func (e *Enforcer) GetFilteredGroupingPolicy(fieldIndex int, fieldValues ...string) ([][]string, error) {
	return e.GetFilteredNamedGroupingPolicy("g", fieldIndex, fieldValues...)
}

// GetNamedGroupingPolicy gets all the role inheritance rules in the policy.
func (e *Enforcer) GetNamedGroupingPolicy(ptype string) ([][]string, error) {
	return e.model.GetPolicy("g", ptype)
}

// GetFilteredNamedGroupingPolicy gets all the role inheritance rules in the policy, field filters can be specified.
func (e *Enforcer) GetFilteredNamedGroupingPolicy(ptype string, fieldIndex int, fieldValues ...string) ([][]string, error) {
	return e.model.GetFilteredPolicy("g", ptype, fieldIndex, fieldValues...)
}

// GetFilteredNamedPolicyWithMatcher gets rules based on matcher from the policy.
func (e *Enforcer) GetFilteredNamedPolicyWithMatcher(ptype string, matcher string) ([][]string, error) {
	var res [][]string
	var err error

	functions := e.getMatcherFunctions()

	var expString string
	if matcher == "" {
		return res, fmt.Errorf("matcher is empty")
	} else {
		expString = util.RemoveComments(util.EscapeAssertion(matcher))
	}

	var expression *govaluate.EvaluableExpression

	expression, err = govaluate.NewEvaluableExpressionWithFunctions(expString, functions)
	if err != nil {
		return res, err
	}

	pTokens := make(map[string]int, len(e.model["p"][ptype].Tokens))
	for i, token := range e.model["p"][ptype].Tokens {
		pTokens[token] = i
	}

	parameters := enforceParameters{
		pTokens: pTokens,
	}

	if policyLen := len(e.model["p"][ptype].Policy); policyLen != 0 && strings.Contains(expString, ptype+"_") {
		for _, pvals := range e.model["p"][ptype].Policy {
			if len(e.model["p"][ptype].Tokens) != len(pvals) {
				return res, fmt.Errorf(
					"invalid policy size: expected %d, got %d, pvals: %v",
					len(e.model["p"][ptype].Tokens),
					len(pvals),
					pvals)
			}

			parameters.pVals = pvals

			result, err := expression.Eval(parameters)
			if err != nil {
				return res, err
			}

			switch result := result.(type) {
			case bool:
				if result {
					res = append(res, pvals)
				}
			case float64:
				if result != 0 {
					res = append(res, pvals)
				}
			default:
				return res, errors.New("matcher result should be bool, int or float")
			}
		}
	}
	return res, nil
}

// HasPolicy determines whether an authorization rule exists.
func (e *Enforcer) HasPolicy(params ...interface{}) (bool, error) {
	return e.HasNamedPolicy("p", params...)
}

// HasNamedPolicy determines whether a named authorization rule exists.
func (e *Enforcer) HasNamedPolicy(ptype string, params ...interface{}) (bool, error) {
	if strSlice, ok := params[0].([]string); len(params) == 1 && ok {
		return e.model.HasPolicy("p", ptype, strSlice)
	}

	policy := make([]string, 0)
	for _, param := range params {
		policy = append(policy, param.(string))
	}

	return e.model.HasPolicy("p", ptype, policy)
}

// AddPolicy adds an authorization rule to the current policy.
// If the rule already exists, the function returns false and the rule will not be added.
// Otherwise the function returns true by adding the new rule.
func (e *Enforcer) AddPolicy(params ...interface{}) (bool, error) {
	return e.AddNamedPolicy("p", params...)
}

// AddPolicies adds authorization rules to the current policy.
// If the rule already exists, the function returns false for the corresponding rule and the rule will not be added.
// Otherwise the function returns true for the corresponding rule by adding the new rule.
func (e *Enforcer) AddPolicies(rules [][]string) (bool, error) {
	return e.AddNamedPolicies("p", rules)
}

// AddPoliciesEx adds authorization rules to the current policy.
// If the rule already exists, the rule will not be added.
// But unlike AddPolicies, other non-existent rules are added instead of returning false directly.
func (e *Enforcer) AddPoliciesEx(rules [][]string) (bool, error) {
	return e.AddNamedPoliciesEx("p", rules)
}

// AddNamedPolicy adds an authorization rule to the current named policy.
// If the rule already exists, the function returns false and the rule will not be added.
// Otherwise the function returns true by adding the new rule.
func (e *Enforcer) AddNamedPolicy(ptype string, params ...interface{}) (bool, error) {
	if strSlice, ok := params[0].([]string); len(params) == 1 && ok {
		strSlice = append(make([]string, 0, len(strSlice)), strSlice...)
		return e.addPolicy("p", ptype, strSlice)
	}
	policy := make([]string, 0)
	for _, param := range params {
		policy = append(policy, param.(string))
	}

	return e.addPolicy("p", ptype, policy)
}

// AddNamedPolicies adds authorization rules to the current named policy.
// If the rule already exists, the function returns false for the corresponding rule and the rule will not be added.
// Otherwise the function returns true for the corresponding by adding the new rule.
func (e *Enforcer) AddNamedPolicies(ptype string, rules [][]string) (bool, error) {
	return e.addPolicies("p", ptype, rules, false)
}

// AddNamedPoliciesEx adds authorization rules to the current named policy.
// If the rule already exists, the rule will not be added.
// But unlike AddNamedPolicies, other non-existent rules are added instead of returning false directly.
func (e *Enforcer) AddNamedPoliciesEx(ptype string, rules [][]string) (bool, error) {
	return e.addPolicies("p", ptype, rules, true)
}

// RemovePolicy removes an authorization rule from the current policy.
func (e *Enforcer) RemovePolicy(params ...interface{}) (bool, error) {
	return e.RemoveNamedPolicy("p", params...)
}

// UpdatePolicy updates an authorization rule from the current policy.
func (e *Enforcer) UpdatePolicy(oldPolicy []string, newPolicy []string) (bool, error) {
	return e.UpdateNamedPolicy("p", oldPolicy, newPolicy)
}

func (e *Enforcer) UpdateNamedPolicy(ptype string, p1 []string, p2 []string) (bool, error) {
	return e.updatePolicy("p", ptype, p1, p2)
}

// UpdatePolicies updates authorization rules from the current policies.
func (e *Enforcer) UpdatePolicies(oldPolices [][]string, newPolicies [][]string) (bool, error) {
	return e.UpdateNamedPolicies("p", oldPolices, newPolicies)
}

func (e *Enforcer) UpdateNamedPolicies(ptype string, p1 [][]string, p2 [][]string) (bool, error) {
	return e.updatePolicies("p", ptype, p1, p2)
}

func (e *Enforcer) UpdateFilteredPolicies(newPolicies [][]string, fieldIndex int, fieldValues ...string) (bool, error) {
	return e.UpdateFilteredNamedPolicies("p", newPolicies, fieldIndex, fieldValues...)
}

func (e *Enforcer) UpdateFilteredNamedPolicies(ptype string, newPolicies [][]string, fieldIndex int, fieldValues ...string) (bool, error) {
	return e.updateFilteredPolicies("p", ptype, newPolicies, fieldIndex, fieldValues...)
}

// RemovePolicies removes authorization rules from the current policy.
func (e *Enforcer) RemovePolicies(rules [][]string) (bool, error) {
	return e.RemoveNamedPolicies("p", rules)
}

// RemoveFilteredPolicy removes an authorization rule from the current policy, field filters can be specified.
func (e *Enforcer) RemoveFilteredPolicy(fieldIndex int, fieldValues ...string) (bool, error) {
	return e.RemoveFilteredNamedPolicy("p", fieldIndex, fieldValues...)
}

// RemoveNamedPolicy removes an authorization rule from the current named policy.
func (e *Enforcer) RemoveNamedPolicy(ptype string, params ...interface{}) (bool, error) {
	if strSlice, ok := params[0].([]string); len(params) == 1 && ok {
		return e.removePolicy("p", ptype, strSlice)
	}
	policy := make([]string, 0)
	for _, param := range params {
		policy = append(policy, param.(string))
	}

	return e.removePolicy("p", ptype, policy)
}

// RemoveNamedPolicies removes authorization rules from the current named policy.
func (e *Enforcer) RemoveNamedPolicies(ptype string, rules [][]string) (bool, error) {
	return e.removePolicies("p", ptype, rules)
}

// RemoveFilteredNamedPolicy removes an authorization rule from the current named policy, field filters can be specified.
func (e *Enforcer) RemoveFilteredNamedPolicy(ptype string, fieldIndex int, fieldValues ...string) (bool, error) {
	return e.removeFilteredPolicy("p", ptype, fieldIndex, fieldValues)
}

// HasGroupingPolicy determines whether a role inheritance rule exists.
func (e *Enforcer) HasGroupingPolicy(params ...interface{}) (bool, error) {
	return e.HasNamedGroupingPolicy("g", params...)
}

// HasNamedGroupingPolicy determines whether a named role inheritance rule exists.
func (e *Enforcer) HasNamedGroupingPolicy(ptype string, params ...interface{}) (bool, error) {
	if strSlice, ok := params[0].([]string); len(params) == 1 && ok {
		return e.model.HasPolicy("g", ptype, strSlice)
	}

	policy := make([]string, 0)
	for _, param := range params {
		policy = append(policy, param.(string))
	}

	return e.model.HasPolicy("g", ptype, policy)
}

// AddGroupingPolicy adds a role inheritance rule to the current policy.
// If the rule already exists, the function returns false and the rule will not be added.
// Otherwise the function returns true by adding the new rule.
func (e *Enforcer) AddGroupingPolicy(params ...interface{}) (bool, error) {
	return e.AddNamedGroupingPolicy("g", params...)
}

// AddGroupingPolicies adds role inheritance rules to the current policy.
// If the rule already exists, the function returns false for the corresponding policy rule and the rule will not be added.
// Otherwise the function returns true for the corresponding policy rule by adding the new rule.
func (e *Enforcer) AddGroupingPolicies(rules [][]string) (bool, error) {
	return e.AddNamedGroupingPolicies("g", rules)
}

// AddGroupingPoliciesEx adds role inheritance rules to the current policy.
// If the rule already exists, the rule will not be added.
// But unlike AddGroupingPolicies, other non-existent rules are added instead of returning false directly.
func (e *Enforcer) AddGroupingPoliciesEx(rules [][]string) (bool, error) {
	return e.AddNamedGroupingPoliciesEx("g", rules)
}

// AddNamedGroupingPolicy adds a named role inheritance rule to the current policy.
// If the rule already exists, the function returns false and the rule will not be added.
// Otherwise the function returns true by adding the new rule.
func (e *Enforcer) AddNamedGroupingPolicy(ptype string, params ...interface{}) (bool, error) {
	var ruleAdded bool
	var err error
	if strSlice, ok := params[0].([]string); len(params) == 1 && ok {
		ruleAdded, err = e.addPolicy("g", ptype, strSlice)
	} else {
		policy := make([]string, 0)
		for _, param := range params {
			policy = append(policy, param.(string))
		}

		ruleAdded, err = e.addPolicy("g", ptype, policy)
	}

	return ruleAdded, err
}

// AddNamedGroupingPolicies adds named role inheritance rules to the current policy.
// If the rule already exists, the function returns false for the corresponding policy rule and the rule will not be added.
// Otherwise the function returns true for the corresponding policy rule by adding the new rule.
func (e *Enforcer) AddNamedGroupingPolicies(ptype string, rules [][]string) (bool, error) {
	return e.addPolicies("g", ptype, rules, false)
}

// AddNamedGroupingPoliciesEx adds named role inheritance rules to the current policy.
// If the rule already exists, the rule will not be added.
// But unlike AddNamedGroupingPolicies, other non-existent rules are added instead of returning false directly.
func (e *Enforcer) AddNamedGroupingPoliciesEx(ptype string, rules [][]string) (bool, error) {
	return e.addPolicies("g", ptype, rules, true)
}

// RemoveGroupingPolicy removes a role inheritance rule from the current policy.
func (e *Enforcer) RemoveGroupingPolicy(params ...interface{}) (bool, error) {
	return e.RemoveNamedGroupingPolicy("g", params...)
}

// RemoveGroupingPolicies removes role inheritance rules from the current policy.
func (e *Enforcer) RemoveGroupingPolicies(rules [][]string) (bool, error) {
	return e.RemoveNamedGroupingPolicies("g", rules)
}

// RemoveFilteredGroupingPolicy removes a role inheritance rule from the current policy, field filters can be specified.
func (e *Enforcer) RemoveFilteredGroupingPolicy(fieldIndex int, fieldValues ...string) (bool, error) {
	return e.RemoveFilteredNamedGroupingPolicy("g", fieldIndex, fieldValues...)
}

// RemoveNamedGroupingPolicy removes a role inheritance rule from the current named policy.
func (e *Enforcer) RemoveNamedGroupingPolicy(ptype string, params ...interface{}) (bool, error) {
	var ruleRemoved bool
	var err error
	if strSlice, ok := params[0].([]string); len(params) == 1 && ok {
		ruleRemoved, err = e.removePolicy("g", ptype, strSlice)
	} else {
		policy := make([]string, 0)
		for _, param := range params {
			policy = append(policy, param.(string))
		}

		ruleRemoved, err = e.removePolicy("g", ptype, policy)
	}

	return ruleRemoved, err
}

// RemoveNamedGroupingPolicies removes role inheritance rules from the current named policy.
func (e *Enforcer) RemoveNamedGroupingPolicies(ptype string, rules [][]string) (bool, error) {
	return e.removePolicies("g", ptype, rules)
}

func (e *Enforcer) UpdateGroupingPolicy(oldRule []string, newRule []string) (bool, error) {
	return e.UpdateNamedGroupingPolicy("g", oldRule, newRule)
}

// UpdateGroupingPolicies updates authorization rules from the current policies.
func (e *Enforcer) UpdateGroupingPolicies(oldRules [][]string, newRules [][]string) (bool, error) {
	return e.UpdateNamedGroupingPolicies("g", oldRules, newRules)
}

func (e *Enforcer) UpdateNamedGroupingPolicy(ptype string, oldRule []string, newRule []string) (bool, error) {
	return e.updatePolicy("g", ptype, oldRule, newRule)
}

func (e *Enforcer) UpdateNamedGroupingPolicies(ptype string, oldRules [][]string, newRules [][]string) (bool, error) {
	return e.updatePolicies("g", ptype, oldRules, newRules)
}

// RemoveFilteredNamedGroupingPolicy removes a role inheritance rule from the current named policy, field filters can be specified.
func (e *Enforcer) RemoveFilteredNamedGroupingPolicy(ptype string, fieldIndex int, fieldValues ...string) (bool, error) {
	return e.removeFilteredPolicy("g", ptype, fieldIndex, fieldValues)
}

// AddFunction adds a customized function.
func (e *Enforcer) AddFunction(name string, function govaluate.ExpressionFunction) {
	e.fm.AddFunction(name, function)
}

func (e *Enforcer) SelfAddPolicy(sec string, ptype string, rule []string) (bool, error) {
	return e.addPolicyWithoutNotify(sec, ptype, rule)
}

func (e *Enforcer) SelfAddPolicies(sec string, ptype string, rules [][]string) (bool, error) {
	return e.addPoliciesWithoutNotify(sec, ptype, rules, false)
}

func (e *Enforcer) SelfAddPoliciesEx(sec string, ptype string, rules [][]string) (bool, error) {
	return e.addPoliciesWithoutNotify(sec, ptype, rules, true)
}

func (e *Enforcer) SelfRemovePolicy(sec string, ptype string, rule []string) (bool, error) {
	return e.removePolicyWithoutNotify(sec, ptype, rule)
}

func (e *Enforcer) SelfRemovePolicies(sec string, ptype string, rules [][]string) (bool, error) {
	return e.removePoliciesWithoutNotify(sec, ptype, rules)
}

func (e *Enforcer) SelfRemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) (bool, error) {
	return e.removeFilteredPolicyWithoutNotify(sec, ptype, fieldIndex, fieldValues)
}

func (e *Enforcer) SelfUpdatePolicy(sec string, ptype string, oldRule, newRule []string) (bool, error) {
	return e.updatePolicyWithoutNotify(sec, ptype, oldRule, newRule)
}

func (e *Enforcer) SelfUpdatePolicies(sec string, ptype string, oldRules, newRules [][]string) (bool, error) {
	return e.updatePoliciesWithoutNotify(sec, ptype, oldRules, newRules)
}
