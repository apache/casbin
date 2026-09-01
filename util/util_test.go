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
	"testing"
)

func testEscapeAssertion(t *testing.T, s string, res string) {
	t.Helper()
	myRes := EscapeAssertion(s)
	t.Logf("%s: %s", s, myRes)

	if myRes != res {
		t.Errorf("%s: %s, supposed to be %s", s, myRes, res)
	}
}

func TestEscapeAssertion(t *testing.T) {
	testEscapeAssertion(t, "r_sub == r_obj.value", "r_sub == r_obj.value")
	testEscapeAssertion(t, "p_sub == r_sub.value", "p_sub == r_sub.value")
	testEscapeAssertion(t, "r.attr.value == p.attr", "r_attr.value == p_attr")
	testEscapeAssertion(t, "r.attr.value == p.attr", "r_attr.value == p_attr")
	testEscapeAssertion(t, "r.attp.value || p.attr", "r_attp.value || p_attr")
	testEscapeAssertion(t, "r2.attr.value == p2.attr", "r2_attr.value == p2_attr")
	testEscapeAssertion(t, "r2.attp.value || p2.attr", "r2_attp.value || p2_attr")
	testEscapeAssertion(t, "r.attp.value &&p.attr", "r_attp.value &&p_attr")
	testEscapeAssertion(t, "r.attp.value >p.attr", "r_attp.value >p_attr")
	testEscapeAssertion(t, "r.attp.value <p.attr", "r_attp.value <p_attr")
	testEscapeAssertion(t, "r.attp.value +p.attr", "r_attp.value +p_attr")
	testEscapeAssertion(t, "r.attp.value -p.attr", "r_attp.value -p_attr")
	testEscapeAssertion(t, "r.attp.value *p.attr", "r_attp.value *p_attr")
	testEscapeAssertion(t, "r.attp.value /p.attr", "r_attp.value /p_attr")
	testEscapeAssertion(t, "!r.attp.value /p.attr", "!r_attp.value /p_attr")
	testEscapeAssertion(t, "g(r.sub, p.sub) == p.attr", "g(r_sub, p_sub) == p_attr")
	testEscapeAssertion(t, "g(r.sub,p.sub) == p.attr", "g(r_sub,p_sub) == p_attr")
	testEscapeAssertion(t, "(r.attp.value || p.attr)p.u", "(r_attp.value || p_attr)p_u")
	// Test that patterns inside strings are not escaped
	testEscapeAssertion(t, `r.sub == "a.p.p.l.e"`, `r_sub == "a.p.p.l.e"`)
	testEscapeAssertion(t, `r.sub == "test.p.value"`, `r_sub == "test.p.value"`)
}

func testRemoveComments(t *testing.T, s string, res string) {
	t.Helper()
	myRes := RemoveComments(s)
	t.Logf("%s: %s", s, myRes)

	if myRes != res {
		t.Errorf("%s: %s, supposed to be %s", s, myRes, res)
	}
}

func TestRemoveComments(t *testing.T) {
	testRemoveComments(t, "r.act == p.act # comments", "r.act == p.act")
	testRemoveComments(t, "r.act == p.act#comments", "r.act == p.act")
	testRemoveComments(t, "r.act == p.act###", "r.act == p.act")
	testRemoveComments(t, "### comments", "")
	testRemoveComments(t, "r.act == p.act", "r.act == p.act")
}

func testArrayEquals(t *testing.T, a []string, b []string, res bool) {
	t.Helper()
	myRes := ArrayEquals(a, b)
	t.Logf("%s == %s: %t", a, b, myRes)

	if myRes != res {
		t.Errorf("%s == %s: %t, supposed to be %t", a, b, myRes, res)
	}
}

func TestArrayEquals(t *testing.T) {
	testArrayEquals(t, []string{"a", "b", "c"}, []string{"a", "b", "c"}, true)
	testArrayEquals(t, []string{"a", "b", "c"}, []string{"a", "b"}, false)
	testArrayEquals(t, []string{"a", "b", "c"}, []string{"a", "c", "b"}, false)
	testArrayEquals(t, []string{"a", "b", "c"}, []string{}, false)
}

func testArray2DEquals(t *testing.T, a [][]string, b [][]string, res bool) {
	t.Helper()
	myRes := Array2DEquals(a, b)
	t.Logf("%s == %s: %t", a, b, myRes)

	if myRes != res {
		t.Errorf("%s == %s: %t, supposed to be %t", a, b, myRes, res)
	}
}

func TestArray2DEquals(t *testing.T) {
	testArray2DEquals(t, [][]string{{"a", "b", "c"}, {"1", "2", "3"}}, [][]string{{"a", "b", "c"}, {"1", "2", "3"}}, true)
	testArray2DEquals(t, [][]string{{"a", "b", "c"}, {"1", "2", "3"}}, [][]string{{"a", "b", "c"}}, false)
	testArray2DEquals(t, [][]string{{"a", "b", "c"}, {"1", "2", "3"}}, [][]string{{"a", "b", "c"}, {"1", "2"}}, false)
	testArray2DEquals(t, [][]string{{"a", "b", "c"}, {"1", "2", "3"}}, [][]string{{"1", "2", "3"}, {"a", "b", "c"}}, false)
	testArray2DEquals(t, [][]string{{"a", "b", "c"}, {"1", "2", "3"}}, [][]string{}, false)
}

func testSetEquals(t *testing.T, a []string, b []string, res bool) {
	t.Helper()
	myRes := SetEquals(a, b)
	t.Logf("%s == %s: %t", a, b, myRes)

	if myRes != res {
		t.Errorf("%s == %s: %t, supposed to be %t", a, b, myRes, res)
	}
}

func TestSetEquals(t *testing.T) {
	testSetEquals(t, []string{"a", "b", "c"}, []string{"a", "b", "c"}, true)
	testSetEquals(t, []string{"a", "b", "c"}, []string{"a", "b"}, false)
	testSetEquals(t, []string{"a", "b", "c"}, []string{"a", "c", "b"}, true)
	testSetEquals(t, []string{"a", "b", "c"}, []string{}, false)
}

func testContainEval(t *testing.T, s string, res bool) {
	t.Helper()
	myRes := HasEval(s)
	if myRes != res {
		t.Errorf("%s: %t, supposed to be %t", s, myRes, res)
	}
}

func TestContainEval(t *testing.T) {
	testContainEval(t, "eval() && a && b && c", true)
	testContainEval(t, "eval) && a && b && c", false)
	testContainEval(t, "eval)( && a && b && c", false)
	testContainEval(t, "eval(c * (a + b)) && a && b && c", true)
	testContainEval(t, "xeval() && a && b && c", false)
}

func testReplaceEval(t *testing.T, s string, rule string, res string) {
	t.Helper()
	myRes := ReplaceEval(s, rule)

	if myRes != res {
		t.Errorf("%s: %s supposed to be %s", s, myRes, res)
	}
}

func TestReplaceEval(t *testing.T) {
	testReplaceEval(t, "eval() && a && b && c", "a", "(a) && a && b && c")
	testReplaceEval(t, "eval() && a && b && c", "(a)", "((a)) && a && b && c")
}

func testGetEvalValue(t *testing.T, s string, res []string) {
	t.Helper()
	myRes := GetEvalValue(s)

	if !ArrayEquals(myRes, res) {
		t.Errorf("%s: %s supposed to be %s", s, myRes, res)
	}
}

func TestGetEvalValue(t *testing.T) {
	testGetEvalValue(t, "eval(a) && a && b && c", []string{"a"})
	testGetEvalValue(t, "a && eval(a) && b && c", []string{"a"})
	testGetEvalValue(t, "eval(a) && eval(b) && a && b && c", []string{"a", "b"})
	testGetEvalValue(t, "a && eval(a) && eval(b) && b && c", []string{"a", "b"})
}

func testReplaceEvalWithMap(t *testing.T, s string, sets map[string]string, res string) {
	t.Helper()
	myRes := ReplaceEvalWithMap(s, sets)

	if myRes != res {
		t.Errorf("%s: %s supposed to be %s", s, myRes, res)
	}
}

func TestReplaceEvalWithMap(t *testing.T) {
	testReplaceEvalWithMap(t, "eval(rule1)", map[string]string{"rule1": "a == b"}, "a == b")
	testReplaceEvalWithMap(t, "eval(rule1) && c && d", map[string]string{"rule1": "a == b"}, "a == b && c && d")
	testReplaceEvalWithMap(t, "eval(rule1)", nil, "eval(rule1)")
	testReplaceEvalWithMap(t, "eval(rule1) && c && d", nil, "eval(rule1) && c && d")
	testReplaceEvalWithMap(t, "eval(rule1) || eval(rule2)", map[string]string{"rule1": "a == b", "rule2": "a == c"}, "a == b || a == c")
	testReplaceEvalWithMap(t, "eval(rule1) || eval(rule2) && c && d", map[string]string{"rule1": "a == b", "rule2": "a == c"}, "a == b || a == c && c && d")
	testReplaceEvalWithMap(t, "eval(rule1) || eval(rule2)", map[string]string{"rule1": "a == b"}, "a == b || eval(rule2)")
	testReplaceEvalWithMap(t, "eval(rule1) || eval(rule2) && c && d", map[string]string{"rule1": "a == b"}, "a == b || eval(rule2) && c && d")
	testReplaceEvalWithMap(t, "eval(rule1) || eval(rule2)", map[string]string{"rule2": "a == b"}, "eval(rule1) || a == b")
	testReplaceEvalWithMap(t, "eval(rule1) || eval(rule2) && c && d", map[string]string{"rule2": "a == b"}, "eval(rule1) || a == b && c && d")
	testReplaceEvalWithMap(t, "eval(rule1) || eval(rule2)", nil, "eval(rule1) || eval(rule2)")
	testReplaceEvalWithMap(t, "eval(rule1) || eval(rule2) && c && d", nil, "eval(rule1) || eval(rule2) && c && d")
}

func testCacheGet(t *testing.T, c *LRUCache, key string, value interface{}, ok bool) {
	v, o := c.Get(key)
	if v != value || o != ok {
		t.Errorf("Get(%s): (%s, %t) supposed to be (%s, %t)", key, v, o, value, ok)
	}
}

func testCachePut(t *testing.T, c *LRUCache, key string, value interface{}) {
	c.Put(key, value)
	v, o := c.Get(key)
	if v != value || o != true {
		t.Errorf("Put(%s, %s): didn't add value", key, value)
	}
}

func testCacheEqual(t *testing.T, c *LRUCache, values []int) {
	cacheValues := []int{}
	for _, v := range c.m {
		cacheValues = append(cacheValues, v.value.(int))
	}

	if SetEqualsInt(values, cacheValues) == false {
		t.Errorf("cache values: %d supposed to be %d", cacheValues, values)
	}
}

func TestLRUCache(t *testing.T) {
	cache := NewLRUCache(3)
	testCachePut(t, cache, "one", 1)
	testCachePut(t, cache, "two", 2)
	testCacheGet(t, cache, "one", 1, true)
	testCachePut(t, cache, "three", 3)
	testCachePut(t, cache, "four", 4)
	testCacheGet(t, cache, "two", nil, false)
	testCacheEqual(t, cache, []int{1, 3, 4})
}

func testEscapeStringLiterals(t *testing.T, input string, expected string) {
	t.Helper()
	result := EscapeStringLiterals(input)
	t.Logf("Input: %q", input)
	t.Logf("Expected: %q", expected)
	t.Logf("Got: %q", result)

	if result != expected {
		t.Errorf("EscapeStringLiterals(%q) = %q, expected %q", input, result, expected)
	}
}

func TestEscapeStringLiterals(t *testing.T) {
	// Test single-quoted strings
	testEscapeStringLiterals(t, `'\1\2'`, `'\\1\\2'`)
	testEscapeStringLiterals(t, `'\n\t'`, `'\\n\\t'`)
	testEscapeStringLiterals(t, `'\\already\\escaped'`, `'\\\\already\\\\escaped'`)

	// Test double-quoted strings
	testEscapeStringLiterals(t, `"\1\2"`, `"\\1\\2"`)
	testEscapeStringLiterals(t, `"\n\t"`, `"\\n\\t"`)

	// Test expressions with string literals
	testEscapeStringLiterals(t, `regexMatch('\1\2', p.obj)`, `regexMatch('\\1\\2', p.obj)`)
	testEscapeStringLiterals(t, `regexMatch("\1\2", p.obj)`, `regexMatch("\\1\\2", p.obj)`)
	testEscapeStringLiterals(t, `r.sub == '\test'`, `r.sub == '\\test'`)

	// Test that non-ASCII (multi-byte UTF-8) string literals are preserved
	testEscapeStringLiterals(t, `r.sub == '香港'`, `r.sub == '香港'`)
	testEscapeStringLiterals(t, `r.obj == "café"`, `r.obj == "café"`)
	testEscapeStringLiterals(t, `keyMatch(r.obj, 'naïve\1')`, `keyMatch(r.obj, 'naïve\\1')`)

	// Test expressions without string literals
	testEscapeStringLiterals(t, `r.sub == p.sub`, `r.sub == p.sub`)
	testEscapeStringLiterals(t, `keyMatch(r.obj, p.obj)`, `keyMatch(r.obj, p.obj)`)

	// Test multiple strings in one expression
	testEscapeStringLiterals(t, `regexMatch('\1', '\2')`, `regexMatch('\\1', '\\2')`)

	// Test empty strings
	testEscapeStringLiterals(t, `''`, `''`)
	testEscapeStringLiterals(t, `""`, `""`)

	// Test strings with no backslashes
	testEscapeStringLiterals(t, `'hello'`, `'hello'`)
	testEscapeStringLiterals(t, `"world"`, `"world"`)
}

// The Set* comparisons answer a question about their arguments and must not
// rewrite them. They used to sort in place, and since the enforcer hands back
// slices that alias its own policy, comparing an answer permuted the stored
// rule - see the enforcer level regression test TestSet2DEqualsKeepsPolicyIntact.
func TestSetComparisonsDoNotModifyArguments(t *testing.T) {
	strs := []string{"c", "a", "b"}
	other := []string{"b", "c", "a"}
	if !SetEquals(strs, other) {
		t.Error("SetEquals should hold for the same members in another order")
	}
	if !ArrayEquals(strs, []string{"c", "a", "b"}) {
		t.Errorf("SetEquals reordered its first argument: %v", strs)
	}
	if !ArrayEquals(other, []string{"b", "c", "a"}) {
		t.Errorf("SetEquals reordered its second argument: %v", other)
	}

	ints := []int{3, 1, 2}
	otherInts := []int{2, 3, 1}
	if !SetEqualsInt(ints, otherInts) {
		t.Error("SetEqualsInt should hold for the same members in another order")
	}
	if ints[0] != 3 || ints[1] != 1 || ints[2] != 2 {
		t.Errorf("SetEqualsInt reordered its first argument: %v", ints)
	}
	if otherInts[0] != 2 || otherInts[1] != 3 || otherInts[2] != 1 {
		t.Errorf("SetEqualsInt reordered its second argument: %v", otherInts)
	}

	rules := [][]string{{"zoe", "data1", "read"}, {"amy", "data2", "write"}}
	want := [][]string{{"amy", "data2", "write"}, {"zoe", "data1", "read"}}
	if !Set2DEquals(rules, want) {
		t.Error("Set2DEquals should hold for the same rules in another order")
	}
	if !ArrayEquals(rules[0], []string{"zoe", "data1", "read"}) {
		t.Errorf("Set2DEquals reordered a row of its first argument: %v", rules)
	}
	if !ArrayEquals(want[1], []string{"zoe", "data1", "read"}) {
		t.Errorf("Set2DEquals reordered a row of its second argument: %v", want)
	}

	// The comparisons still discriminate after the change.
	if SetEquals([]string{"a", "b"}, []string{"a", "c"}) {
		t.Error("SetEquals should not hold for different members")
	}
	if SetEqualsInt([]int{1, 2}, []int{1, 3}) {
		t.Error("SetEqualsInt should not hold for different members")
	}
	if Set2DEquals(rules, [][]string{{"zoe", "data1", "read"}, {"amy", "data2", "read"}}) {
		t.Error("Set2DEquals should not hold for different rules")
	}
}

// TestLRUCachePutOverwritesAnExistingKey pins CAS-8: Put on a key already in
// the cache reuses that key's node for its links, so the new value has to be
// written onto it. Re-linking alone left the cache answering with the value the
// key was first stored with, and every later Put for that key was discarded
// without a word. Both the plain and the synchronised cache are driven, because
// the synchronised one delegates and would inherit the defect silently.
