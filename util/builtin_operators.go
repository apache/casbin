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

package util

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/casbin/casbin/v3/rbac"

	"github.com/casbin/govaluate"
)

var (
	keyMatch2Re = regexp.MustCompile(`:[^/]+`)
	keyMatch3Re = regexp.MustCompile(`\{[^/]+\}`)
	keyMatch4Re = regexp.MustCompile(`{([^/]+)}`)
	keyMatch5Re = regexp.MustCompile(`\{[^/]+\}`)
	keyGet2Re1  = regexp.MustCompile(`:[^/]+`)
	keyGet3Re1  = regexp.MustCompile(`\{[^/]+?\}`) // non-greedy match of `{...}` to support multiple {} in `/.../`
	reCache     sync.Map                            // string -> *regexp.Regexp
)

// regexpMetaChars is exactly the set of characters that regexp.QuoteMeta escapes.
// It is spelled out instead of calling QuoteMeta so that keyMatchShortcut never
// allocates; TestRegexpMetaChars guards the two against drifting apart.
const regexpMetaChars = `\.+*?()|[]{}^$`

// keyMatchShortcut answers KeyMatch2/3/4/5 for the two cases that need no regexp
// work at all. ok reports whether matched is the final answer; when it is false
// the caller falls through to its unchanged rewrite-and-match path.
//
// The two cases are:
//
//  1. key2 == "*", the bare wildcard used as the "all domains" key. The regexp
//     path reaches the same answer via "^*$", which only works by accident (see
//     issue #330); making it explicit is both faster and less fragile.
//
//  2. key2 is plain, i.e. it holds no regexp metacharacter and none of the
//     matcher's own pattern characters (extraChars, ":" for KeyMatch2's :param
//     dialect; the "{}" and "*" of the other matchers are already metacharacters).
//     Then "^"+key2+"$" can only match key2 itself, so key1 == key2 is the answer.
//
// Case 2 has to stay conservative because RegexMatch embeds key2 unescaped: a
// stray metacharacter makes key2 behave as a regexp, so "acme.com" does match
// "acmeXcom", and key1 == key2 is not sufficient either ("^a+b$" does not match
// "a+b"). Any such key2 keeps taking the regexp path.
//
// This matters because a DomainMatchingFunc is called O(N*D) times while building
// role links, and real deployments mostly hold concrete domains ("team/123") that
// pay for the full pipeline only to come back false.
func keyMatchShortcut(key1 string, key2 string, extraChars string) (matched bool, ok bool) {
	if key2 == "*" {
		return true, true
	}

	if !strings.ContainsAny(key2, regexpMetaChars) && !strings.ContainsAny(key2, extraChars) {
		return key1 == key2, true
	}

	return false, false
}

// compiledPattern is the fully prepared form of a matcher's key2: the regexp that
// key1 is tested against, plus the names of the pattern variables in the order
// their capture groups appear (only KeyGet2/KeyGet3/KeyMatch4 use tokens).
//
// Everything in it is a pure function of key2, so it is built once per distinct
// key2 and reused afterwards.
type compiledPattern struct {
	re     *regexp.Regexp
	tokens []string
}

// patternCache memoizes compiledPattern by raw key2, one cache per matcher since
// each of them reads key2 in its own dialect. Only compiling the regexp used to be
// cached (see mustCompileOrGet), which still left every call rebuilding the regexp
// source with a chain of ReplaceAll passes just to look it up. Keying on key2
// instead makes the steady state a single map read.
//
// A policy holds a bounded set of patterns, so the cache converges to that set
// after the first pass; sync.Map suits that read-mostly shape.
type patternCache struct {
	m sync.Map // string -> *compiledPattern
}

func (c *patternCache) get(key2 string, build func(key2 string) *compiledPattern) *compiledPattern {
	if v, ok := c.m.Load(key2); ok {
		return v.(*compiledPattern)
	}

	p := build(key2)
	c.m.Store(key2, p)

	return p
}

var (
	keyMatch2Cache patternCache
	keyMatch3Cache patternCache
	keyMatch4Cache patternCache
	keyMatch5Cache patternCache
	keyGet2Cache   patternCache
	keyGet3Cache   patternCache
)

func mustCompileOrGet(key string) *regexp.Regexp {
	if v, ok := reCache.Load(key); ok {
		return v.(*regexp.Regexp)
	}

	re := regexp.MustCompile(key)
	actual, _ := reCache.LoadOrStore(key, re)
	return actual.(*regexp.Regexp)
}

// validate the variadic parameter size and type as string.
func validateVariadicArgs(expectedLen int, args ...interface{}) error {
	if len(args) != expectedLen {
		return fmt.Errorf("expected %d arguments, but got %d", expectedLen, len(args))
	}

	for _, p := range args {
		_, ok := p.(string)
		if !ok {
			return errors.New("argument must be a string")
		}
	}

	return nil
}

// validate the variadic string parameter size.
func validateVariadicStringArgs(expectedLen int, args ...string) error {
	if len(args) != expectedLen {
		return fmt.Errorf("expected %d arguments, but got %d", expectedLen, len(args))
	}
	return nil
}

// KeyMatch determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
// For example, "/foo/bar" matches "/foo/*".
func KeyMatch(key1 string, key2 string) bool {
	i := strings.Index(key2, "*")
	if i == -1 {
		return key1 == key2
	}

	if len(key1) > i {
		return key1[:i] == key2[:i]
	}
	return key1 == key2[:i]
}

// KeyMatchFunc is the wrapper for KeyMatch.
func KeyMatchFunc(args ...interface{}) (interface{}, error) {
	if err := validateVariadicArgs(2, args...); err != nil {
		return false, fmt.Errorf("%s: %w", "keyMatch", err)
	}

	name1 := args[0].(string)
	name2 := args[1].(string)

	return KeyMatch(name1, name2), nil
}

// KeyGet returns the matched part
// For example, "/foo/bar/foo" matches "/foo/*"
// "bar/foo" will been returned.
func KeyGet(key1, key2 string) string {
	i := strings.Index(key2, "*")
	if i == -1 {
		return ""
	}
	if len(key1) > i {
		if key1[:i] == key2[:i] {
			return key1[i:]
		}
	}
	return ""
}

// KeyGetFunc is the wrapper for KeyGet.
func KeyGetFunc(args ...interface{}) (interface{}, error) {
	if err := validateVariadicArgs(2, args...); err != nil {
		return false, fmt.Errorf("%s: %w", "keyGet", err)
	}

	name1 := args[0].(string)
	name2 := args[1].(string)

	return KeyGet(name1, name2), nil
}

// KeyMatch2 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
// For example, "/foo/bar" matches "/foo/*", "/resource1" matches "/:resource".
func KeyMatch2(key1 string, key2 string) bool {
	if matched, ok := keyMatchShortcut(key1, key2, ":"); ok {
		return matched
	}

	return keyMatch2Cache.get(key2, buildKeyMatch2).re.MatchString(key1)
}

func buildKeyMatch2(key2 string) *compiledPattern {
	key2 = strings.ReplaceAll(key2, "/*", "/.*")

	key2 = keyMatch2Re.ReplaceAllString(key2, "$1[^/]+$2")

	return &compiledPattern{re: mustCompileOrGet("^" + key2 + "$")}
}

// KeyMatch2Func is the wrapper for KeyMatch2.
func KeyMatch2Func(args ...interface{}) (interface{}, error) {
	if err := validateVariadicArgs(2, args...); err != nil {
		return false, fmt.Errorf("%s: %w", "keyMatch2", err)
	}

	name1 := args[0].(string)
	name2 := args[1].(string)

	return KeyMatch2(name1, name2), nil
}

// KeyGet2 returns value matched pattern
// For example, "/resource1" matches "/:resource"
// if the pathVar == "resource", then "resource1" will be returned.
func KeyGet2(key1, key2 string, pathVar string) string {
	p := keyGet2Cache.get(key2, buildKeyGet2)

	values := p.re.FindAllStringSubmatch(key1, -1)
	if len(values) == 0 {
		return ""
	}
	for i, key := range p.tokens {
		if pathVar == key {
			return values[0][i+1]
		}
	}
	return ""
}

func buildKeyGet2(key2 string) *compiledPattern {
	key2 = strings.ReplaceAll(key2, "/*", "/.*")

	// The ":" is dropped here so that the lookup in KeyGet2 is a plain comparison.
	tokens := keyGet2Re1.FindAllString(key2, -1)
	for i, token := range tokens {
		tokens[i] = token[1:]
	}

	key2 = keyGet2Re1.ReplaceAllString(key2, "$1([^/]+)$2")

	return &compiledPattern{re: mustCompileOrGet("^" + key2 + "$"), tokens: tokens}
}

// KeyGet2Func is the wrapper for KeyGet2.
func KeyGet2Func(args ...interface{}) (interface{}, error) {
	if err := validateVariadicArgs(3, args...); err != nil {
		return false, fmt.Errorf("%s: %w", "keyGet2", err)
	}

	name1 := args[0].(string)
	name2 := args[1].(string)
	key := args[2].(string)

	return KeyGet2(name1, name2, key), nil
}

// KeyMatch3 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
// For example, "/foo/bar" matches "/foo/*", "/resource1" matches "/{resource}".
func KeyMatch3(key1 string, key2 string) bool {
	if matched, ok := keyMatchShortcut(key1, key2, ""); ok {
		return matched
	}

	return keyMatch3Cache.get(key2, buildKeyMatch3).re.MatchString(key1)
}

func buildKeyMatch3(key2 string) *compiledPattern {
	key2 = strings.ReplaceAll(key2, "/*", "/.*")
	key2 = keyMatch3Re.ReplaceAllString(key2, "$1[^/]+$2")

	return &compiledPattern{re: mustCompileOrGet("^" + key2 + "$")}
}

// KeyMatch3Func is the wrapper for KeyMatch3.
func KeyMatch3Func(args ...interface{}) (interface{}, error) {
	if err := validateVariadicArgs(2, args...); err != nil {
		return false, fmt.Errorf("%s: %w", "keyMatch3", err)
	}

	name1 := args[0].(string)
	name2 := args[1].(string)

	return KeyMatch3(name1, name2), nil
}

// KeyGet3 returns value matched pattern
// For example, "project/proj_project1_admin/" matches "project/proj_{project}_admin/"
// if the pathVar == "project", then "project1" will be returned.
func KeyGet3(key1, key2 string, pathVar string) string {
	p := keyGet3Cache.get(key2, buildKeyGet3)

	values := p.re.FindAllStringSubmatch(key1, -1)
	if len(values) == 0 {
		return ""
	}
	for i, key := range p.tokens {
		if pathVar == key {
			return values[0][i+1]
		}
	}
	return ""
}

func buildKeyGet3(key2 string) *compiledPattern {
	key2 = strings.ReplaceAll(key2, "/*", "/.*")

	// The surrounding "{}" is dropped here so that the lookup in KeyGet3 is a plain
	// comparison.
	tokens := keyGet3Re1.FindAllString(key2, -1)
	for i, token := range tokens {
		tokens[i] = token[1 : len(token)-1]
	}

	key2 = keyGet3Re1.ReplaceAllString(key2, "$1([^/]+?)$2")

	return &compiledPattern{re: mustCompileOrGet("^" + key2 + "$"), tokens: tokens}
}

// KeyGet3Func is the wrapper for KeyGet3.
func KeyGet3Func(args ...interface{}) (interface{}, error) {
	if err := validateVariadicArgs(3, args...); err != nil {
		return false, fmt.Errorf("%s: %w", "keyGet3", err)
	}

	name1 := args[0].(string)
	name2 := args[1].(string)
	key := args[2].(string)

	return KeyGet3(name1, name2, key), nil
}

// KeyMatch4 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
// Besides what KeyMatch3 does, KeyMatch4 can also match repeated patterns:
// "/parent/123/child/123" matches "/parent/{id}/child/{id}"
// "/parent/123/child/456" does not match "/parent/{id}/child/{id}"
// But KeyMatch3 will match both.
func KeyMatch4(key1 string, key2 string) bool {
	if matched, ok := keyMatchShortcut(key1, key2, ""); ok {
		return matched
	}

	p := keyMatch4Cache.get(key2, buildKeyMatch4)

	matches := p.re.FindStringSubmatch(key1)
	if matches == nil {
		return false
	}
	matches = matches[1:]

	if len(p.tokens) != len(matches) {
		panic(errors.New("KeyMatch4: number of tokens is not equal to number of values"))
	}

	values := map[string]string{}

	for key, token := range p.tokens {
		if _, ok := values[token]; !ok {
			values[token] = matches[key]
		}
		if values[token] != matches[key] {
			return false
		}
	}

	return true
}

func buildKeyMatch4(key2 string) *compiledPattern {
	key2 = strings.ReplaceAll(key2, "/*", "/.*")

	tokens := []string{}

	key2 = keyMatch4Re.ReplaceAllStringFunc(key2, func(s string) string {
		tokens = append(tokens, s[1:len(s)-1])
		return "([^/]+)"
	})

	return &compiledPattern{re: mustCompileOrGet("^" + key2 + "$"), tokens: tokens}
}

// KeyMatch4Func is the wrapper for KeyMatch4.
func KeyMatch4Func(args ...interface{}) (interface{}, error) {
	if err := validateVariadicArgs(2, args...); err != nil {
		return false, fmt.Errorf("%s: %w", "keyMatch4", err)
	}

	name1 := args[0].(string)
	name2 := args[1].(string)

	return KeyMatch4(name1, name2), nil
}

// KeyMatch5 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *
// For example,
// - "/foo/bar?status=1&type=2" matches "/foo/bar"
// - "/parent/child1" and "/parent/child1" matches "/parent/*"
// - "/parent/child1?status=1" matches "/parent/*".
func KeyMatch5(key1 string, key2 string) bool {
	i := strings.Index(key1, "?")

	if i != -1 {
		key1 = key1[:i]
	}

	// After the query string is stripped, so that key1 is compared in the same
	// shape the regexp path would have matched.
	if matched, ok := keyMatchShortcut(key1, key2, ""); ok {
		return matched
	}

	return keyMatch5Cache.get(key2, buildKeyMatch5).re.MatchString(key1)
}

func buildKeyMatch5(key2 string) *compiledPattern {
	key2 = strings.ReplaceAll(key2, "/*", "/.*")
	key2 = keyMatch5Re.ReplaceAllString(key2, "$1[^/]+$2")

	return &compiledPattern{re: mustCompileOrGet("^" + key2 + "$")}
}

// KeyMatch5Func is the wrapper for KeyMatch5.
func KeyMatch5Func(args ...interface{}) (interface{}, error) {
	if err := validateVariadicArgs(2, args...); err != nil {
		return false, fmt.Errorf("%s: %w", "keyMatch5", err)
	}

	name1 := args[0].(string)
	name2 := args[1].(string)

	return KeyMatch5(name1, name2), nil
}

// RegexMatch determines whether key1 matches the pattern of key2 in regular expression.
func RegexMatch(key1 string, key2 string) bool {
	return mustCompileOrGet(key2).MatchString(key1)
}

// RegexMatchFunc is the wrapper for RegexMatch.
func RegexMatchFunc(args ...interface{}) (interface{}, error) {
	if err := validateVariadicArgs(2, args...); err != nil {
		return false, fmt.Errorf("%s: %w", "regexMatch", err)
	}

	name1 := args[0].(string)
	name2 := args[1].(string)

	return RegexMatch(name1, name2), nil
}

// IPMatch determines whether IP address ip1 matches the pattern of IP address ip2, ip2 can be an IP address or a CIDR pattern.
// For example, "192.168.2.123" matches "192.168.2.0/24".
func IPMatch(ip1 string, ip2 string) bool {
	objIP1 := net.ParseIP(ip1)
	if objIP1 == nil {
		panic("invalid argument: ip1 in IPMatch() function is not an IP address.")
	}

	_, cidr, err := net.ParseCIDR(ip2)
	if err != nil {
		objIP2 := net.ParseIP(ip2)
		if objIP2 == nil {
			panic("invalid argument: ip2 in IPMatch() function is neither an IP address nor a CIDR.")
		}

		return objIP1.Equal(objIP2)
	}

	return cidr.Contains(objIP1)
}

// IPMatchFunc is the wrapper for IPMatch.
func IPMatchFunc(args ...interface{}) (interface{}, error) {
	if err := validateVariadicArgs(2, args...); err != nil {
		return false, fmt.Errorf("%s: %w", "ipMatch", err)
	}

	ip1 := args[0].(string)
	ip2 := args[1].(string)

	return IPMatch(ip1, ip2), nil
}

// GlobMatch determines whether key1 matches the pattern of key2 using glob pattern.
func GlobMatch(key1 string, key2 string) (bool, error) {
	return doublestar.Match(key2, key1)
}

// GlobMatchFunc is the wrapper for GlobMatch.
func GlobMatchFunc(args ...interface{}) (interface{}, error) {
	if err := validateVariadicArgs(2, args...); err != nil {
		return false, fmt.Errorf("%s: %w", "globMatch", err)
	}

	name1 := args[0].(string)
	name2 := args[1].(string)

	return GlobMatch(name1, name2)
}

// GenerateGFunction is the factory method of the g(_, _[, _]) function.
// If useCache is true, results are memoized per unique argument combination for performance.
// Set useCache to false when inputs are high-cardinality (e.g. UUIDs) to avoid unbounded memory growth.
func GenerateGFunction(rm rbac.RoleManager, useCache bool) govaluate.ExpressionFunction {
	memorized := sync.Map{}
	return func(args ...interface{}) (interface{}, error) {
		// Like all our other govaluate functions, all args are strings.

		if useCache {
			// Allocate and generate a cache key from the arguments...
			total := len(args)
			for _, a := range args {
				aStr := a.(string)
				total += len(aStr)
			}
			builder := strings.Builder{}
			builder.Grow(total)
			for _, arg := range args {
				builder.WriteByte(0)
				builder.WriteString(arg.(string))
			}
			key := builder.String()

			// ...and see if we've already calculated this.
			if v, found := memorized.Load(key); found {
				return v, nil
			}

			// If not, do the calculation.
			// There are guaranteed to be exactly 2 or 3 arguments.
			name1, name2 := args[0].(string), args[1].(string)
			var v interface{}
			if rm == nil {
				v = name1 == name2
			} else if len(args) == 2 {
				v, _ = rm.HasLink(name1, name2)
			} else {
				domain := args[2].(string)
				v, _ = rm.HasLink(name1, name2, domain)
			}

			memorized.Store(key, v)
			return v, nil
		}

		// No caching path.
		name1, name2 := args[0].(string), args[1].(string)
		var v interface{}
		if rm == nil {
			v = name1 == name2
		} else if len(args) == 2 {
			v, _ = rm.HasLink(name1, name2)
		} else {
			domain := args[2].(string)
			v, _ = rm.HasLink(name1, name2, domain)
		}
		return v, nil
	}
}

// GenerateConditionalGFunction is the factory method of the g(_, _[, _]) function with conditions.
func GenerateConditionalGFunction(crm rbac.ConditionalRoleManager) govaluate.ExpressionFunction {
	return func(args ...interface{}) (interface{}, error) {
		// Like all our other govaluate functions, all args are strings.
		var hasLink bool

		name1, name2 := args[0].(string), args[1].(string)
		if crm == nil {
			hasLink = name1 == name2
		} else if len(args) == 2 {
			hasLink, _ = crm.HasLink(name1, name2)
		} else {
			domain := args[2].(string)
			hasLink, _ = crm.HasLink(name1, name2, domain)
		}

		return hasLink, nil
	}
}

// builtin LinkConditionFunc

// TimeMatchFunc is the wrapper for TimeMatch.
func TimeMatchFunc(args ...string) (bool, error) {
	if err := validateVariadicStringArgs(2, args...); err != nil {
		return false, fmt.Errorf("%s: %w", "TimeMatch", err)
	}
	return TimeMatch(args[0], args[1])
}

// TimeMatch determines whether the current time is between startTime and endTime.
// You can use "_" to indicate that the parameter is ignored.
func TimeMatch(startTime, endTime string) (bool, error) {
	now := time.Now()
	if startTime != "_" {
		if start, err := time.Parse("2006-01-02 15:04:05", startTime); err != nil {
			return false, err
		} else if !now.After(start) {
			return false, nil
		}
	}

	if endTime != "_" {
		if end, err := time.Parse("2006-01-02 15:04:05", endTime); err != nil {
			return false, err
		} else if !now.Before(end) {
			return false, nil
		}
	}

	return true, nil
}
