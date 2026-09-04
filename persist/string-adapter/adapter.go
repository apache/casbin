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

package stringadapter

import (
	"bytes"
	"errors"
	"strings"

	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist"
)

// Adapter is the string adapter for Casbin.
// It can load policy from string or save policy to string.
type Adapter struct {
	Line string
}

// NewAdapter is the constructor for Adapter.
func NewAdapter(line string) *Adapter {
	return &Adapter{
		Line: line,
	}
}

// LoadPolicy loads all policy rules from the storage.
func (a *Adapter) LoadPolicy(model model.Model) error {
	if a.Line == "" {
		return errors.New("invalid line, line cannot be empty")
	}
	strs := strings.Split(a.Line, "\n")
	for _, str := range strs {
		if str == "" {
			continue
		}
		if err := persist.LoadPolicyLine(str, model); err != nil {
			return err
		}
	}

	return nil
}

// SavePolicy saves all policy rules to the storage.
func (a *Adapter) SavePolicy(model model.Model) error {
	var tmp bytes.Buffer
	for ptype, ast := range model["p"] {
		for _, rule := range ast.Policy {
			line, err := persist.PolicyLineToCsv(ptype, rule)
			if err != nil {
				return err
			}
			tmp.WriteString(line)
			tmp.WriteString("\n")
		}
	}

	for ptype, ast := range model["g"] {
		for _, rule := range ast.Policy {
			line, err := persist.PolicyLineToCsv(ptype, rule)
			if err != nil {
				return err
			}
			tmp.WriteString(line)
			tmp.WriteString("\n")
		}
	}
	a.Line = strings.TrimRight(tmp.String(), "\n")
	return nil
}

// AddPolicy adds a policy rule to the storage.
func (a *Adapter) AddPolicy(sec string, ptype string, rule []string) error {
	return errors.New("not implemented")
}

// RemovePolicy removes a policy rule from the storage.
func (a *Adapter) RemovePolicy(sec string, ptype string, rule []string) error {
	a.Line = ""
	return nil
}

// RemoveFilteredPolicy removes policy rules that match the filter from the storage.
func (a *Adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	return errors.New("not implemented")
}
