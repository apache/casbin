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

package persist

import (
	"bytes"
	"encoding/csv"
	"errors"
	"strings"

	"github.com/casbin/casbin/v3/model"
)

// LoadPolicyLine loads a text line as a policy rule to model.
func LoadPolicyLine(line string, m model.Model) error {
	if line == "" || strings.HasPrefix(line, "#") {
		return nil
	}

	r := csv.NewReader(strings.NewReader(line))
	r.Comma = ','
	r.Comment = '#'
	r.TrimLeadingSpace = true

	tokens, err := r.Read()
	if err != nil {
		return err
	}

	return LoadPolicyArray(tokens, m)
}

// PolicyLineToCsv serializes a policy type and its rule fields into a CSV-safe line.
// Fields are separated by ", " to match the conventional layout of Casbin policy
// files, which LoadPolicyLine accepts because its reader trims leading spaces.
// Fields containing commas are properly quoted so the line can be round-tripped
// through LoadPolicyLine without corruption.
func PolicyLineToCsv(ptype string, rule []string) (string, error) {
	record := append([]string{ptype}, rule...)

	// Each field is written as its own single-field record so that the standard
	// library decides on quoting, then the fields are joined with ", ".
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	fields := make([]string, 0, len(record))
	for _, field := range record {
		buf.Reset()
		if err := w.Write([]string{field}); err != nil {
			return "", err
		}
		w.Flush()
		if err := w.Error(); err != nil {
			return "", err
		}
		fields = append(fields, strings.TrimRight(buf.String(), "\r\n"))
	}

	return strings.Join(fields, ", "), nil
}

// LoadPolicyArray loads a policy rule to model.
func LoadPolicyArray(rule []string, m model.Model) error {
	if len(rule) == 0 || rule[0] == "" {
		return errors.New("invalid policy rule: missing policy type")
	}
	key := rule[0]
	sec := key[:1]
	ok, err := m.HasPolicyEx(sec, key, rule[1:])
	if err != nil {
		return err
	}
	if ok {
		return nil // skip duplicated policy
	}

	err = m.AddPolicy(sec, key, rule[1:])
	if err != nil {
		return err
	}

	return nil
}

// Adapter is the interface for Casbin adapters.
type Adapter interface {
	// LoadPolicy loads all policy rules from the storage.
	LoadPolicy(model model.Model) error
	// SavePolicy saves all policy rules to the storage.
	SavePolicy(model model.Model) error

	// AddPolicy adds a policy rule to the storage.
	// This is part of the Auto-Save feature.
	AddPolicy(sec string, ptype string, rule []string) error
	// RemovePolicy removes a policy rule from the storage.
	// This is part of the Auto-Save feature.
	RemovePolicy(sec string, ptype string, rule []string) error
	// RemoveFilteredPolicy removes policy rules that match the filter from the storage.
	// This is part of the Auto-Save feature.
	RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error
}
