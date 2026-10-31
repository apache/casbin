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
	"container/list"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/casbin/casbin/v3/config"
	"github.com/casbin/casbin/v3/constant"
	"github.com/casbin/casbin/v3/util"
)

// Model represents the whole access control model.
type Model map[string]AssertionMap

// AssertionMap is the collection of assertions, can be "r", "p", "g", "e", "m".
type AssertionMap map[string]*Assertion

const (
	defaultDomain    string = ""
	defaultSeparator string = "::"
)

var sectionNameMap = map[string]string{
	"r": "request_definition",
	"p": "policy_definition",
	"g": "role_definition",
	"e": "policy_effect",
	"m": "matchers",
	"c": "constraint_definition",
}

// Minimal required sections for a model to be valid.
var requiredSections = []string{"r", "p", "e", "m"}

func loadAssertion(model Model, cfg config.ConfigInterface, sec string, key string) bool {
	value := cfg.String(sectionNameMap[sec] + "::" + key)
	return model.AddDef(sec, key, value)
}

var paramsRegex = regexp.MustCompile(`\((.*?)\)`)

// getParamsToken Get ParamsToken from Assertion.Value.
func getParamsToken(value string) []string {
	paramsString := paramsRegex.FindString(value)
	if paramsString == "" {
		return nil
	}
	paramsString = strings.TrimSuffix(strings.TrimPrefix(paramsString, "("), ")")
	return strings.Split(paramsString, ",")
}

// AddDef adds an assertion to the model.
func (model Model) AddDef(sec string, key string, value string) bool {
	if value == "" {
		return false
	}

	ast := Assertion{}
	ast.Key = key
	ast.Value = value
	ast.PolicyMap = make(map[string]int)
	ast.FieldIndexMap = make(map[string]int)

	switch sec {
	case "r", "p":
		ast.Tokens = strings.Split(ast.Value, ",")
		for i := range ast.Tokens {
			ast.Tokens[i] = key + "_" + strings.TrimSpace(ast.Tokens[i])
		}
	case "g":
		ast.ParamsTokens = getParamsToken(ast.Value)
		ast.Tokens = strings.Split(ast.Value, ",")
		ast.Tokens = ast.Tokens[:len(ast.Tokens)-len(ast.ParamsTokens)]
	default:
		ast.Value = util.RemoveComments(util.EscapeAssertion(ast.Value))
	}

	if sec == "m" {
		// Escape backslashes in string literals to match CSV parsing behavior
		ast.Value = util.EscapeStringLiterals(ast.Value)

		if strings.Contains(ast.Value, "in") {
			ast.Value = strings.ReplaceAll(strings.ReplaceAll(ast.Value, "[", "("), "]", ")")
		}
	}

	_, ok := model[sec]
	if !ok {
		model[sec] = make(AssertionMap)
	}

	model[sec][key] = &ast
	return true
}

func getKeySuffix(i int) string {
	if i == 1 {
		return ""
	}

	return strconv.Itoa(i)
}

func loadSection(model Model, cfg config.ConfigInterface, sec string) {
	i := 1
	for {
		if !loadAssertion(model, cfg, sec, sec+getKeySuffix(i)) {
			break
		} else {
			i++
		}
	}
}

// NewModel creates an empty model.
func NewModel() Model {
	m := make(Model)

	return m
}

// NewModelFromFile creates a model from a .CONF file.
func NewModelFromFile(path string) (Model, error) {
	m := NewModel()

	err := m.LoadModel(path)
	if err != nil {
		return nil, err
	}

	return m, nil
}

// NewModelFromString creates a model from a string which contains model text.
func NewModelFromString(text string) (Model, error) {
	m := NewModel()

	err := m.LoadModelFromText(text)
	if err != nil {
		return nil, err
	}

	return m, nil
}

// LoadModel loads the model from model CONF file.
func (model Model) LoadModel(path string) error {
	cfg, err := config.NewConfig(path)
	if err != nil {
		return err
	}

	return model.loadModelFromConfig(cfg)
}

// LoadModelFromText loads the model from the text.
func (model Model) LoadModelFromText(text string) error {
	cfg, err := config.NewConfigFromText(text)
	if err != nil {
		return err
	}

	return model.loadModelFromConfig(cfg)
}

// loadModelFromConfig loads the model from a config interface.
// It loads all sections defined in sectionNameMap and validates that required sections are present.
// If constraint_definition section exists, it validates all constraints against the current policy.
// Note: Constraint validation is performed during model loading, which may affect loading performance
// and can cause model loading to fail if constraints are violated or invalid.
func (model Model) loadModelFromConfig(cfg config.ConfigInterface) error {
	for s := range sectionNameMap {
		loadSection(model, cfg, s)
	}
	ms := make([]string, 0)
	for _, rs := range requiredSections {
		if !model.hasSection(rs) {
			ms = append(ms, sectionNameMap[rs])
		}
	}
	if len(ms) > 0 {
		return fmt.Errorf("missing required sections: %s", strings.Join(ms, ","))
	}

	// Validate constraints after model is loaded
	if err := model.ValidateConstraints(); err != nil {
		return err
	}

	return nil
}

func (model Model) hasSection(sec string) bool {
	section := model[sec]
	return section != nil
}

func (model Model) GetAssertion(sec string, ptype string) (*Assertion, error) {
	if model[sec] == nil {
		return nil, fmt.Errorf("missing required section %s", sec)
	}
	if model[sec][ptype] == nil {
		return nil, fmt.Errorf("missing required definition %s in section %s", ptype, sec)
	}
	return model[sec][ptype], nil
}

// PrintModel prints the model to the log.
func (model Model) PrintModel() {
	// Logger has been removed - this is now a no-op
}

func (model Model) SortPoliciesBySubjectHierarchy() error {
	if model["e"]["e"].Value != constant.SubjectPriorityEffect {
		return nil
	}
	g, err := model.GetAssertion("g", "g")
	if err != nil {
		return err
	}
	subIndex := 0
	for ptype, assertion := range model["p"] {
		domainIndex, err := model.GetFieldIndex(ptype, constant.DomainIndex)
		if err != nil {
			domainIndex = -1
		}
		policies := assertion.Policy
		subjectHierarchyMap, err := getSubjectHierarchyMap(g.Policy)
		if err != nil {
			return err
		}
		sort.SliceStable(policies, func(i, j int) bool {
			domain1, domain2 := defaultDomain, defaultDomain
			if domainIndex != -1 {
				domain1 = policies[i][domainIndex]
				domain2 = policies[j][domainIndex]
			}
			name1, name2 := getNameWithDomain(domain1, policies[i][subIndex]), getNameWithDomain(domain2, policies[j][subIndex])
			p1 := subjectHierarchyMap[name1]
			p2 := subjectHierarchyMap[name2]
			return p1 > p2
		})
		for i, policy := range assertion.Policy {
			assertion.PolicyMap[strings.Join(policy, ",")] = i
		}
		assertion.PolicyVersion++
	}
	return nil
}

func getSubjectHierarchyMap(policies [][]string) (map[string]int, error) {
	subjectHierarchyMap := make(map[string]int)
	// Tree structure of role
	policyMap := make(map[string][]string)
	for _, policy := range policies {
		if len(policy) < 2 {
			return nil, errors.New("policy g expect 2 more params")
		}
		domain := defaultDomain
		if len(policy) != 2 {
			domain = policy[2]
		}
		child := getNameWithDomain(domain, policy[0])
		parent := getNameWithDomain(domain, policy[1])
		policyMap[parent] = append(policyMap[parent], child)
		if _, ok := subjectHierarchyMap[child]; !ok {
			subjectHierarchyMap[child] = 0
		}
		if _, ok := subjectHierarchyMap[parent]; !ok {
			subjectHierarchyMap[parent] = 0
		}
		subjectHierarchyMap[child] = 1
	}
	// Use queues for levelOrder
	queue := list.New()
	for k, v := range subjectHierarchyMap {
		root := k
		if v != 0 {
			continue
		}
		lv := 0
		queue.PushBack(root)
		for queue.Len() != 0 {
			sz := queue.Len()
			for i := 0; i < sz; i++ {
				node := queue.Front()
				queue.Remove(node)
				nodeValue := node.Value.(string)
				subjectHierarchyMap[nodeValue] = lv
				if _, ok := policyMap[nodeValue]; ok {
					for _, child := range policyMap[nodeValue] {
						queue.PushBack(child)
					}
				}
			}
			lv++
		}
	}
	return subjectHierarchyMap, nil
}

func getNameWithDomain(domain string, name string) string {
	return domain + defaultSeparator + name
}

func (model Model) SortPoliciesByPriority() error {
	for ptype, assertion := range model["p"] {
		priorityIndex, err := model.GetFieldIndex(ptype, constant.PriorityIndex)
		if err != nil {
			continue
		}
		policies := assertion.Policy
		sort.SliceStable(policies, func(i, j int) bool {
			p1, err := strconv.Atoi(policies[i][priorityIndex])
			if err != nil {
				return true
			}
			p2, err := strconv.Atoi(policies[j][priorityIndex])
			if err != nil {
				return true
			}
			return p1 < p2
		})
		for i, policy := range assertion.Policy {
			assertion.PolicyMap[strings.Join(policy, ",")] = i
		}
		assertion.PolicyVersion++
	}
	return nil
}

var (
	pPattern = regexp.MustCompile("^p_")
	rPattern = regexp.MustCompile("^r_")
)

func (model Model) ToText() string {
	tokenPatterns := make(map[string]string)

	for _, ptype := range []string{"r", "p"} {
		for _, token := range model[ptype][ptype].Tokens {
			tokenPatterns[token] = rPattern.ReplaceAllString(pPattern.ReplaceAllString(token, "p."), "r.")
		}
	}
	if strings.Contains(model["e"]["e"].Value, "p_eft") {
		tokenPatterns["p_eft"] = "p.eft"
	}
	s := strings.Builder{}
	writeString := func(sec string) {
		for ptype := range model[sec] {
			value := model[sec][ptype].Value
			for tokenPattern, newToken := range tokenPatterns {
				value = strings.ReplaceAll(value, tokenPattern, newToken)
			}
			fmt.Fprintf(&s, "%s = %s\n", sec, value)
		}
	}
	s.WriteString("[request_definition]\n")
	writeString("r")
	s.WriteString("[policy_definition]\n")
	writeString("p")
	if _, ok := model["g"]; ok {
		s.WriteString("[role_definition]\n")
		for ptype := range model["g"] {
			fmt.Fprintf(&s, "%s = %s\n", ptype, model["g"][ptype].Value)
		}
	}
	if _, ok := model["c"]; ok {
		s.WriteString("[constraint_definition]\n")
		for ptype := range model["c"] {
			fmt.Fprintf(&s, "%s = %s\n", ptype, model["c"][ptype].Value)
		}
	}
	s.WriteString("[policy_effect]\n")
	writeString("e")
	s.WriteString("[matchers]\n")
	writeString("m")
	return s.String()
}

func (model Model) Copy() Model {
	newModel := NewModel()

	for sec, m := range model {
		newAstMap := make(AssertionMap)
		for ptype, ast := range m {
			newAstMap[ptype] = ast.copy()
		}
		newModel[sec] = newAstMap
	}

	return newModel
}

func (model Model) GetFieldIndex(ptype string, field string) (int, error) {
	assertion := model["p"][ptype]

	assertion.FieldIndexMutex.RLock()
	if index, ok := assertion.FieldIndexMap[field]; ok {
		assertion.FieldIndexMutex.RUnlock()
		return index, nil
	}
	assertion.FieldIndexMutex.RUnlock()

	pattern := fmt.Sprintf("%s_"+field, ptype)
	index := -1
	for i, token := range assertion.Tokens {
		if token == pattern {
			index = i
			break
		}
	}
	if index == -1 {
		return index, fmt.Errorf(field + " index is not set, please use enforcer.SetFieldIndex() to set index")
	}

	assertion.FieldIndexMutex.Lock()
	assertion.FieldIndexMap[field] = index
	assertion.FieldIndexMutex.Unlock()

	return index, nil
}
