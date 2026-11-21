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
	"strings"
)

// ErrInvalidTypedName is returned by ParseTypedName for a string that TypedName cannot produce.
var ErrInvalidTypedName = errors.New("invalid typed name")

var typedNameEscaper = strings.NewReplacer("%", "%25", ":", "%3A", "/", "%2F")

// TypedName returns the name of an entity of the given type, such as a user, group or team,
// for use in policies and requests. A name made of several parts, such as a team inside an
// organization, is passed as several parts.
//
// Different types or parts always give different names, whatever characters they contain,
// so a user named "admins" never matches the group "admins", and the organization
// "acme_t_dev" never matches the team "dev" of "acme":
//
//	TypedName("user", "admins")      // user:admins
//	TypedName("group", "admins")     // group:admins
//	TypedName("team", "acme", "dev") // team:acme/dev
//	TypedName("org", "acme/dev")     // org:acme%2Fdev
func TypedName(typ string, name string, parts ...string) string {
	var b strings.Builder
	b.WriteString(typedNameEscaper.Replace(typ))
	b.WriteByte(':')
	b.WriteString(typedNameEscaper.Replace(name))
	for _, part := range parts {
		b.WriteByte('/')
		b.WriteString(typedNameEscaper.Replace(part))
	}
	return b.String()
}

// ParseTypedName returns the type and parts of a name made by TypedName.
// It returns ErrInvalidTypedName for any other string.
func ParseTypedName(s string) (string, []string, error) {
	i := strings.IndexByte(s, ':')
	if i < 0 {
		return "", nil, ErrInvalidTypedName
	}
	typ, ok := unescapeTypedName(s[:i])
	if !ok {
		return "", nil, ErrInvalidTypedName
	}
	parts := strings.Split(s[i+1:], "/")
	for j, part := range parts {
		if parts[j], ok = unescapeTypedName(part); !ok {
			return "", nil, ErrInvalidTypedName
		}
	}
	return typ, parts, nil
}

// FilterTypedNames returns the names of the given type, for example the teams among
// the roles returned by GetImplicitRolesForUser.
func FilterTypedNames(names []string, typ string) []string {
	res := []string{}
	for _, name := range names {
		if t, _, err := ParseTypedName(name); err == nil && t == typ {
			res = append(res, name)
		}
	}
	return res
}

func unescapeTypedName(s string) (string, bool) {
	if strings.ContainsAny(s, ":/") {
		return "", false
	}
	if !strings.Contains(s, "%") {
		return s, true
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			b.WriteByte(s[i])
			continue
		}
		if i+3 > len(s) {
			return "", false
		}
		switch s[i : i+3] {
		case "%25":
			b.WriteByte('%')
		case "%3A":
			b.WriteByte(':')
		case "%2F":
			b.WriteByte('/')
		default:
			return "", false
		}
		i += 2
	}
	return b.String(), true
}
