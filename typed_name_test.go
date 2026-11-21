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
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"
)

type typedNameCases struct {
	Valid []struct {
		Type  string   `json:"type"`
		Parts []string `json:"parts"`
		Name  string   `json:"name"`
	} `json:"valid"`
	Invalid []string `json:"invalid"`
}

func TestTypedNameConformance(t *testing.T) {
	data, err := os.ReadFile("conformance/typed_names.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases typedNameCases
	if err = json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}

	seen := map[string]bool{}
	for _, c := range cases.Valid {
		name := TypedName(c.Type, c.Parts[0], c.Parts[1:]...)
		if name != c.Name {
			t.Errorf("TypedName(%q, %q) = %q, want %q", c.Type, c.Parts, name, c.Name)
		}
		if seen[name] {
			t.Errorf("TypedName(%q, %q) = %q is not unique", c.Type, c.Parts, name)
		}
		seen[name] = true

		typ, parts, err := ParseTypedName(c.Name)
		if err != nil || typ != c.Type || !reflect.DeepEqual(parts, c.Parts) {
			t.Errorf("ParseTypedName(%q) = %q, %q, %v, want %q, %q", c.Name, typ, parts, err, c.Type, c.Parts)
		}
	}

	for _, s := range cases.Invalid {
		if _, _, err := ParseTypedName(s); !errors.Is(err, ErrInvalidTypedName) {
			t.Errorf("ParseTypedName(%q) error = %v, want ErrInvalidTypedName", s, err)
		}
	}
}

func TestTypedNameEnforce(t *testing.T) {
	e, err := NewEnforcer("examples/rbac_model.conf")
	if err != nil {
		t.Fatal(err)
	}

	user := func(name string) string { return TypedName("user", name) }
	group := TypedName("group", "admins")
	org := TypedName("org", "acme_t_dev")
	team := TypedName("team", "acme", "dev")

	rules := [][]string{
		{group, "data1", "write"},
		{org, "org_data", "read"},
		{team, "team_data", "read"},
	}
	if _, err = e.AddPolicies(rules); err != nil {
		t.Fatal(err)
	}
	links := [][]string{
		{user("bob"), group},
		{user("carol"), org},
		{user("dave"), team},
	}
	if _, err = e.AddGroupingPolicies(links); err != nil {
		t.Fatal(err)
	}

	testEnforce(t, e, user("bob"), "data1", "write", true)
	testEnforce(t, e, user("admins"), "data1", "write", false)
	testEnforce(t, e, user("carol"), "org_data", "read", true)
	testEnforce(t, e, user("carol"), "team_data", "read", false)
	testEnforce(t, e, user("dave"), "team_data", "read", true)
	testEnforce(t, e, user("dave"), "org_data", "read", false)

	if _, err = e.AddGroupingPolicy(user("dave"), org); err != nil {
		t.Fatal(err)
	}
	roles, err := e.GetRolesForUser(user("dave"))
	if err != nil {
		t.Fatal(err)
	}
	if teams := FilterTypedNames(roles, "team"); !reflect.DeepEqual(teams, []string{team}) {
		t.Errorf("FilterTypedNames(%q, team) = %q, want %q", roles, teams, []string{team})
	}
	if res := FilterTypedNames([]string{"admins", user("x")}, "group"); len(res) != 0 {
		t.Errorf("FilterTypedNames = %q, want none", res)
	}
}
