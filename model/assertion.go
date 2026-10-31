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
	"errors"
	"strings"
	"sync"

	"github.com/casbin/casbin/v3/rbac"
)

// Assertion represents an expression in a section of the model.
// For example: r = sub, obj, act.
type Assertion struct {
	Key             string
	Value           string
	Tokens          []string
	ParamsTokens    []string
	Policy          [][]string
	PolicyMap       map[string]int
	PolicyVersion   uint64
	RM              rbac.RoleManager
	CondRM          rbac.ConditionalRoleManager
	FieldIndexMap   map[string]int
	FieldIndexMutex sync.RWMutex
}

func (ast *Assertion) buildIncrementalRoleLinks(rm rbac.RoleManager, op PolicyOp, rules [][]string) error {
	ast.RM = rm
	count := strings.Count(ast.Value, "_")
	if count < 2 {
		return errors.New("the number of \"_\" in role definition should be at least 2")
	}

	for _, rule := range rules {
		if len(rule) < count {
			return errors.New("grouping policy elements do not meet role definition")
		}
		if len(rule) > count {
			rule = rule[:count]
		}
		switch op {
		case PolicyAdd:
			err := rm.AddLink(rule[0], rule[1], rule[2:]...)
			if err != nil {
				return err
			}
		case PolicyRemove:
			err := rm.DeleteLink(rule[0], rule[1], rule[2:]...)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (ast *Assertion) buildRoleLinks(rm rbac.RoleManager) error {
	ast.RM = rm
	count := strings.Count(ast.Value, "_")
	if count < 2 {
		return errors.New("the number of \"_\" in role definition should be at least 2")
	}
	for _, rule := range ast.Policy {
		if len(rule) < count {
			return errors.New("grouping policy elements do not meet role definition")
		}
		if len(rule) > count {
			rule = rule[:count]
		}
		err := ast.RM.AddLink(rule[0], rule[1], rule[2:]...)
		if err != nil {
			return err
		}
	}

	return nil
}

func (ast *Assertion) buildIncrementalConditionalRoleLinks(condRM rbac.ConditionalRoleManager, op PolicyOp, rules [][]string) error {
	ast.CondRM = condRM
	count := strings.Count(ast.Value, "_")
	if count < 2 {
		return errors.New("the number of \"_\" in role definition should be at least 2")
	}

	for _, rule := range rules {
		if len(rule) < count {
			return errors.New("grouping policy elements do not meet role definition")
		}
		if len(rule) > count {
			rule = rule[:count]
		}

		var err error
		domainRule := rule[2:len(ast.Tokens)]

		switch op {
		case PolicyAdd:
			err = ast.addConditionalRoleLink(rule, domainRule)
		case PolicyRemove:
			err = ast.CondRM.DeleteLink(rule[0], rule[1], rule[2:]...)
		}
		if err != nil {
			return err
		}
	}

	return nil
}

func (ast *Assertion) buildConditionalRoleLinks(condRM rbac.ConditionalRoleManager) error {
	ast.CondRM = condRM
	count := strings.Count(ast.Value, "_")
	if count < 2 {
		return errors.New("the number of \"_\" in role definition should be at least 2")
	}
	for _, rule := range ast.Policy {
		if len(rule) < count {
			return errors.New("grouping policy elements do not meet role definition")
		}
		if len(rule) > count {
			rule = rule[:count]
		}

		domainRule := rule[2:len(ast.Tokens)]

		err := ast.addConditionalRoleLink(rule, domainRule)
		if err != nil {
			return err
		}
	}

	return nil
}

// addConditionalRoleLink adds Link to rbac.ConditionalRoleManager and sets the parameters for LinkConditionFunc.
func (ast *Assertion) addConditionalRoleLink(rule []string, domainRule []string) error {
	var err error
	if len(domainRule) == 0 {
		err = ast.CondRM.AddLink(rule[0], rule[1])
		if err == nil {
			ast.CondRM.SetLinkConditionFuncParams(rule[0], rule[1], rule[len(ast.Tokens):]...)
		}
	} else {
		domain := domainRule[0]
		err = ast.CondRM.AddLink(rule[0], rule[1], domain)
		if err == nil {
			ast.CondRM.SetDomainLinkConditionFuncParams(rule[0], rule[1], domain, rule[len(ast.Tokens):]...)
		}
	}
	return err
}

func (ast *Assertion) copy() *Assertion {
	tokens := append([]string(nil), ast.Tokens...)
	policy := make([][]string, len(ast.Policy))

	for i, p := range ast.Policy {
		policy[i] = append(policy[i], p...)
	}
	policyMap := make(map[string]int)
	for k, v := range ast.PolicyMap {
		policyMap[k] = v
	}

	ast.FieldIndexMutex.RLock()
	fieldIndexMap := make(map[string]int)
	for k, v := range ast.FieldIndexMap {
		fieldIndexMap[k] = v
	}
	ast.FieldIndexMutex.RUnlock()

	newAst := &Assertion{
		Key:           ast.Key,
		Value:         ast.Value,
		PolicyMap:     policyMap,
		PolicyVersion: ast.PolicyVersion,
		Tokens:        tokens,
		Policy:        policy,
		FieldIndexMap: fieldIndexMap,
		ParamsTokens:  append([]string(nil), ast.ParamsTokens...),
		RM:            ast.RM,
		CondRM:        ast.CondRM,
	}

	return newAst
}
