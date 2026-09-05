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

package authztest

import (
	"fmt"
	"sort"
	"strings"

	"github.com/casbin/casbin/v3/model"
)

// tokens extracts the declared field names ("sub", "obj", "act", ...) of a
// definition section, in declaration order. Casbin stores r/p tokens with a
// section prefix ("p_sub", "r_obj"); the prefix is stripped so callers see
// the names as written in the model file.
func tokens(m model.Model, sec, key string) []string {
	am := m[sec]
	if am == nil {
		return nil
	}
	a := am[key]
	if a == nil {
		return nil
	}
	prefix := key + "_"
	out := make([]string, len(a.Tokens))
	for i, t := range a.Tokens {
		out[i] = strings.TrimPrefix(t, prefix)
	}
	return out
}

func indexOf(ss []string, want string) int {
	for i, s := range ss {
		if s == want {
			return i
		}
	}
	return -1
}

// pad grows rvals to n entries with "?" so position labels stay aligned
// when the caller passes too few values.
func pad(rvals []interface{}, n int) []interface{} {
	if len(rvals) >= n {
		return rvals
	}
	out := make([]interface{}, n)
	copy(out, rvals)
	for i := len(rvals); i < n; i++ {
		out[i] = "?"
	}
	return out
}

func toStrings(rvals []interface{}) []string {
	out := make([]string, len(rvals))
	for i, v := range rvals {
		out[i] = fmt.Sprint(v)
	}
	return out
}

func sortMisses(ms []NearMiss) {
	sort.SliceStable(ms, func(i, j int) bool {
		si, sj := ms[i].Score(), ms[j].Score()
		if si != sj {
			return si > sj
		}
		// Fewer failed positions means closer; fully matched first.
		fi, fj := ms[i].FullyMatched(), ms[j].FullyMatched()
		if fi != fj {
			return fi
		}
		return len(ms[i].Failed) < len(ms[j].Failed)
	})
}

func formatRequest(rvals []interface{}) string {
	parts := make([]string, len(rvals))
	for i, v := range rvals {
		parts[i] = fmt.Sprint(v)
	}
	return "(" + strings.Join(parts, ", ") + ")"
}
