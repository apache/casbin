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

func testKeyMatch(t *testing.T, key1 string, key2 string, res bool) {
	t.Helper()
	myRes := KeyMatch(key1, key2)
	t.Logf("%s < %s: %t", key1, key2, myRes)

	if myRes != res {
		t.Errorf("%s < %s: %t, supposed to be %t", key1, key2, !res, res)
	}
}

func TestKeyMatch(t *testing.T) {
	testKeyMatch(t, "/foo", "/foo", true)
	testKeyMatch(t, "/foo", "/foo*", true)
	testKeyMatch(t, "/foo", "/foo/*", false)
	testKeyMatch(t, "/foo/bar", "/foo", false)
	testKeyMatch(t, "/foo/bar", "/foo*", true)
	testKeyMatch(t, "/foo/bar", "/foo/*", true)
	testKeyMatch(t, "/foobar", "/foo", false)
	testKeyMatch(t, "/foobar", "/foo*", true)
	testKeyMatch(t, "/foobar", "/foo/*", false)
}

func testKeyGet(t *testing.T, key1 string, key2 string, res string) {
	t.Helper()
	myRes := KeyGet(key1, key2)
	t.Logf(`%s < %s: "%s"`, key1, key2, myRes)

	if myRes != res {
		t.Errorf(`%s < %s: "%s", supposed to be "%s"`, key1, key2, myRes, res)
	}
}

func TestKeyGet(t *testing.T) {
	testKeyGet(t, "/foo", "/foo", "")
	testKeyGet(t, "/foo", "/foo*", "")
	testKeyGet(t, "/foo", "/foo/*", "")
	testKeyGet(t, "/foo/bar", "/foo", "")
	testKeyGet(t, "/foo/bar", "/foo*", "/bar")
	testKeyGet(t, "/foo/bar", "/foo/*", "bar")
	testKeyGet(t, "/foobar", "/foo", "")
	testKeyGet(t, "/foobar", "/foo*", "bar")
	testKeyGet(t, "/foobar", "/foo/*", "")
}

func testKeyMatch2(t *testing.T, key1 string, key2 string, res bool) {
	t.Helper()
	myRes := KeyMatch2(key1, key2)
	t.Logf("%s < %s: %t", key1, key2, myRes)

	if myRes != res {
		t.Errorf("%s < %s: %t, supposed to be %t", key1, key2, !res, res)
	}
}

func testGlobMatch(t *testing.T, key1 string, key2 string, res bool) {
	t.Helper()
	myRes, err := GlobMatch(key1, key2)
	if err != nil {
		panic(err)
	}
	t.Logf("%s < %s: %t", key1, key2, myRes)

	if myRes != res {
		t.Errorf("%s < %s: %t, supposed to be %t", key1, key2, !res, res)
	}
}

func TestKeyMatch2(t *testing.T) {
	testKeyMatch2(t, "/foo", "/foo", true)
	testKeyMatch2(t, "/foo", "/foo*", true)
	testKeyMatch2(t, "/foo", "/foo/*", false)
	testKeyMatch2(t, "/foo/bar", "/foo", false)
	testKeyMatch2(t, "/foo/bar", "/foo*", false) // different with KeyMatch.
	testKeyMatch2(t, "/foo/bar", "/foo/*", true)
	testKeyMatch2(t, "/foobar", "/foo", false)
	testKeyMatch2(t, "/foobar", "/foo*", false) // different with KeyMatch.
	testKeyMatch2(t, "/foobar", "/foo/*", false)

	testKeyMatch2(t, "/", "/:resource", false)
	testKeyMatch2(t, "/resource1", "/:resource", true)
	testKeyMatch2(t, "/myid", "/:id/using/:resId", false)
	testKeyMatch2(t, "/myid/using/myresid", "/:id/using/:resId", true)

	testKeyMatch2(t, "/proxy/myid", "/proxy/:id/*", false)
	testKeyMatch2(t, "/proxy/myid/", "/proxy/:id/*", true)
	testKeyMatch2(t, "/proxy/myid/res", "/proxy/:id/*", true)
	testKeyMatch2(t, "/proxy/myid/res/res2", "/proxy/:id/*", true)
	testKeyMatch2(t, "/proxy/myid/res/res2/res3", "/proxy/:id/*", true)
	testKeyMatch2(t, "/proxy/", "/proxy/:id/*", false)

	testKeyMatch2(t, "/alice", "/:id", true)
	testKeyMatch2(t, "/alice/all", "/:id/all", true)
	testKeyMatch2(t, "/alice", "/:id/all", false)
	testKeyMatch2(t, "/alice/all", "/:id", false)

	testKeyMatch2(t, "/alice/all", "/:/all", false)
}

func testKeyGet2(t *testing.T, key1 string, key2 string, pathVar string, res string) {
	t.Helper()
	myRes := KeyGet2(key1, key2, pathVar)
	t.Logf(`%s < %s: %s = "%s"`, key1, key2, pathVar, myRes)

	if myRes != res {
		t.Errorf(`%s < %s: %s = "%s" supposed to be "%s"`, key1, key2, pathVar, myRes, res)
	}
}

func TestKeyGet2(t *testing.T) {
	testKeyGet2(t, "/foo", "/foo", "id", "")
	testKeyGet2(t, "/foo", "/foo*", "id", "")
	testKeyGet2(t, "/foo", "/foo/*", "id", "")
	testKeyGet2(t, "/foo/bar", "/foo", "id", "")
	testKeyGet2(t, "/foo/bar", "/foo*", "id", "")
	testKeyGet2(t, "/foo/bar", "/foo/*", "id", "")
	testKeyGet2(t, "/foobar", "/foo", "id", "")
	testKeyGet2(t, "/foobar", "/foo*", "id", "")
	testKeyGet2(t, "/foobar", "/foo/*", "id", "")

	testKeyGet2(t, "/", "/:resource", "resource", "")
	testKeyGet2(t, "/resource1", "/:resource", "resource", "resource1")
	testKeyGet2(t, "/myid", "/:id/using/:resId", "id", "")
	testKeyGet2(t, "/myid/using/myresid", "/:id/using/:resId", "id", "myid")
	testKeyGet2(t, "/myid/using/myresid", "/:id/using/:resId", "resId", "myresid")

	testKeyGet2(t, "/proxy/myid", "/proxy/:id/*", "id", "")
	testKeyGet2(t, "/proxy/myid/", "/proxy/:id/*", "id", "myid")
	testKeyGet2(t, "/proxy/myid/res", "/proxy/:id/*", "id", "myid")
	testKeyGet2(t, "/proxy/myid/res/res2", "/proxy/:id/*", "id", "myid")
	testKeyGet2(t, "/proxy/myid/res/res2/res3", "/proxy/:id/*", "id", "myid")
	testKeyGet2(t, "/proxy/myid/res/res2/res3", "/proxy/:id/res/*", "id", "myid")
	testKeyGet2(t, "/proxy/", "/proxy/:id/*", "id", "")

	testKeyGet2(t, "/alice", "/:id", "id", "alice")
	testKeyGet2(t, "/alice/all", "/:id/all", "id", "alice")
	testKeyGet2(t, "/alice", "/:id/all", "id", "")
	testKeyGet2(t, "/alice/all", "/:id", "id", "")

	testKeyGet2(t, "/alice/all", "/:/all", "", "")

	// Capture groups of the pattern's own must not shift which value a token gets.
	testKeyGet2(t, "/a/x/42", "/(a|b)/x/:id", "id", "42")
	testKeyGet2(t, "/42/a", "/:id/(a|b)", "id", "42")
	testKeyGet2(t, "/b/7/c/9", "/(a|b)/:x/(c|d)/:y", "y", "9")
}

func testKeyMatch3(t *testing.T, key1 string, key2 string, res bool) {
	t.Helper()
	myRes := KeyMatch3(key1, key2)
	t.Logf("%s < %s: %t", key1, key2, myRes)

	if myRes != res {
		t.Errorf("%s < %s: %t, supposed to be %t", key1, key2, !res, res)
	}
}

func TestKeyMatch3(t *testing.T) {
	// keyMatch3() is similar with KeyMatch2(), except using "/proxy/{id}" instead of "/proxy/:id".
	testKeyMatch3(t, "/foo", "/foo", true)
	testKeyMatch3(t, "/foo", "/foo*", true)
	testKeyMatch3(t, "/foo", "/foo/*", false)
	testKeyMatch3(t, "/foo/bar", "/foo", false)
	testKeyMatch3(t, "/foo/bar", "/foo*", false)
	testKeyMatch3(t, "/foo/bar", "/foo/*", true)
	testKeyMatch3(t, "/foobar", "/foo", false)
	testKeyMatch3(t, "/foobar", "/foo*", false)
	testKeyMatch3(t, "/foobar", "/foo/*", false)

	testKeyMatch3(t, "/", "/{resource}", false)
	testKeyMatch3(t, "/resource1", "/{resource}", true)
	testKeyMatch3(t, "/myid", "/{id}/using/{resId}", false)
	testKeyMatch3(t, "/myid/using/myresid", "/{id}/using/{resId}", true)

	testKeyMatch3(t, "/proxy/myid", "/proxy/{id}/*", false)
	testKeyMatch3(t, "/proxy/myid/", "/proxy/{id}/*", true)
	testKeyMatch3(t, "/proxy/myid/res", "/proxy/{id}/*", true)
	testKeyMatch3(t, "/proxy/myid/res/res2", "/proxy/{id}/*", true)
	testKeyMatch3(t, "/proxy/myid/res/res2/res3", "/proxy/{id}/*", true)
	testKeyMatch3(t, "/proxy/", "/proxy/{id}/*", false)

	testKeyMatch3(t, "/myid/using/myresid", "/{id/using/{resId}", false)
}

func testKeyGet3(t *testing.T, key1 string, key2 string, pathVar string, res string) {
	t.Helper()
	myRes := KeyGet3(key1, key2, pathVar)
	t.Logf(`%s < %s: %s = "%s"`, key1, key2, pathVar, myRes)

	if myRes != res {
		t.Errorf(`%s < %s: %s = "%s" supposed to be "%s"`, key1, key2, pathVar, myRes, res)
	}
}

func TestKeyGet3(t *testing.T) {
	// KeyGet3() is similar with KeyGet2(), except using "/proxy/{id}" instead of "/proxy/:id".
	testKeyGet3(t, "/foo", "/foo", "id", "")
	testKeyGet3(t, "/foo", "/foo*", "id", "")
	testKeyGet3(t, "/foo", "/foo/*", "id", "")
	testKeyGet3(t, "/foo/bar", "/foo", "id", "")
	testKeyGet3(t, "/foo/bar", "/foo*", "id", "")
	testKeyGet3(t, "/foo/bar", "/foo/*", "id", "")
	testKeyGet3(t, "/foobar", "/foo", "id", "")
	testKeyGet3(t, "/foobar", "/foo*", "id", "")
	testKeyGet3(t, "/foobar", "/foo/*", "id", "")

	testKeyGet3(t, "/", "/{resource}", "resource", "")
	testKeyGet3(t, "/resource1", "/{resource}", "resource", "resource1")
	testKeyGet3(t, "/myid", "/{id}/using/{resId}", "id", "")
	testKeyGet3(t, "/myid/using/myresid", "/{id}/using/{resId}", "id", "myid")
	testKeyGet3(t, "/myid/using/myresid", "/{id}/using/{resId}", "resId", "myresid")

	testKeyGet3(t, "/proxy/myid", "/proxy/{id}/*", "id", "")
	testKeyGet3(t, "/proxy/myid/", "/proxy/{id}/*", "id", "myid")
	testKeyGet3(t, "/proxy/myid/res", "/proxy/{id}/*", "id", "myid")
	testKeyGet3(t, "/proxy/myid/res/res2", "/proxy/{id}/*", "id", "myid")
	testKeyGet3(t, "/proxy/myid/res/res2/res3", "/proxy/{id}/*", "id", "myid")
	testKeyGet3(t, "/proxy/", "/proxy/{id}/*", "id", "")

	testKeyGet3(t, "/api/group1_group_name/project1_admin/info", "/api/{proj}_admin/info",
		"proj", "")
	testKeyGet3(t, "/{id/using/myresid", "/{id/using/{resId}", "resId", "myresid")
	testKeyGet3(t, "/{id/using/myresid/status}", "/{id/using/{resId}/status}", "resId", "myresid")

	testKeyGet3(t, "/proxy/myid/res/res2/res3", "/proxy/{id}/*/{res}", "res", "res3")
	testKeyGet3(t, "/api/project1_admin/info", "/api/{proj}_admin/info", "proj", "project1")
	testKeyGet3(t, "/api/group1_group_name/project1_admin/info", "/api/{g}_{gn}/{proj}_admin/info",
		"g", "group1")
	testKeyGet3(t, "/api/group1_group_name/project1_admin/info", "/api/{g}_{gn}/{proj}_admin/info",
		"gn", "group_name")
	testKeyGet3(t, "/api/group1_group_name/project1_admin/info", "/api/{g}_{gn}/{proj}_admin/info",
		"proj", "project1")

	testKeyGet3(t, "/a/x/42", "/(a|b)/x/{id}", "id", "42")
	testKeyGet3(t, "/42/a", "/{id}/(a|b)", "id", "42")
	testKeyGet3(t, "/b/7/c/9", "/(a|b)/{x}/(c|d)/{y}", "y", "9")
}

func testKeyMatch4(t *testing.T, key1 string, key2 string, res bool) {
	t.Helper()
	myRes := KeyMatch4(key1, key2)
	t.Logf("%s < %s: %t", key1, key2, myRes)

	if myRes != res {
		t.Errorf("%s < %s: %t, supposed to be %t", key1, key2, !res, res)
	}
}

func TestKeyMatch4(t *testing.T) {
	testKeyMatch4(t, "/parent/123/child/123", "/parent/{id}/child/{id}", true)
	testKeyMatch4(t, "/parent/123/child/456", "/parent/{id}/child/{id}", false)

	testKeyMatch4(t, "/parent/123/child/123", "/parent/{id}/child/{another_id}", true)
	testKeyMatch4(t, "/parent/123/child/456", "/parent/{id}/child/{another_id}", true)

	testKeyMatch4(t, "/parent/123/child/123/book/123", "/parent/{id}/child/{id}/book/{id}", true)
	testKeyMatch4(t, "/parent/123/child/123/book/456", "/parent/{id}/child/{id}/book/{id}", false)
	testKeyMatch4(t, "/parent/123/child/456/book/123", "/parent/{id}/child/{id}/book/{id}", false)
	testKeyMatch4(t, "/parent/123/child/456/book/", "/parent/{id}/child/{id}/book/{id}", false)
	testKeyMatch4(t, "/parent/123/child/456", "/parent/{id}/child/{id}/book/{id}", false)

	testKeyMatch4(t, "/parent/123/child/123", "/parent/{i/d}/child/{i/d}", false)

	testKeyMatch4(t, "/a/123/child/123", "/(a|b)/{id}/child/{id}", true)
	testKeyMatch4(t, "/a/123/child/456", "/(a|b)/{id}/child/{id}", false)
	testKeyMatch4(t, "/c/123/child/123", "/(a|b)/{id}/child/{id}", false)
	testKeyMatch4(t, "/123/x/123", "/{id}/(x|y)/{id}", true)
}

func testRegexMatch(t *testing.T, key1 string, key2 string, res bool) {
	t.Helper()
	myRes := RegexMatch(key1, key2)
	t.Logf("%s < %s: %t", key1, key2, myRes)

	if myRes != res {
		t.Errorf("%s < %s: %t, supposed to be %t", key1, key2, !res, res)
	}
}

func TestRegexMatch(t *testing.T) {
	testRegexMatch(t, "/topic/create", "/topic/create", true)
	testRegexMatch(t, "/topic/create/123", "/topic/create", true)
	testRegexMatch(t, "/topic/delete", "/topic/create", false)
	testRegexMatch(t, "/topic/edit", "/topic/edit/[0-9]+", false)
	testRegexMatch(t, "/topic/edit/123", "/topic/edit/[0-9]+", true)
	testRegexMatch(t, "/topic/edit/abc", "/topic/edit/[0-9]+", false)
	testRegexMatch(t, "/foo/delete/123", "/topic/delete/[0-9]+", false)
	testRegexMatch(t, "/topic/delete/0", "/topic/delete/[0-9]+", true)
	testRegexMatch(t, "/topic/edit/123s", "/topic/delete/[0-9]+", false)
	testRegexMatch(t, "/topic/edit/1", "/topic/edit/[0-9", false)
}

func TestInvalidPatternMatchesNothing(t *testing.T) {
	if KeyMatch2("/foo/(bar", "/foo/(bar") || KeyMatch3("/foo/(bar", "/foo/(bar") ||
		KeyMatch4("/foo/(bar", "/foo/(bar") || KeyMatch5("/foo/(bar", "/foo/(bar") {
		t.Error("an invalid pattern should match nothing")
	}
	if KeyGet2("/foo/(bar", "/:id/(bar", "id") != "" || KeyGet3("/foo/(bar", "/{id}/(bar", "id") != "" {
		t.Error("an invalid pattern should get nothing")
	}
}

func testIPMatch(t *testing.T, ip1 string, ip2 string, res bool) {
	t.Helper()
	myRes := IPMatch(ip1, ip2)
	t.Logf("%s < %s: %t", ip1, ip2, myRes)

	if myRes != res {
		t.Errorf("%s < %s: %t, supposed to be %t", ip1, ip2, !res, res)
	}
}

func TestIPMatch(t *testing.T) {
	testIPMatch(t, "192.168.2.123", "192.168.2.0/24", true)
	testIPMatch(t, "192.168.2.123", "192.168.3.0/24", false)
	testIPMatch(t, "192.168.2.123", "192.168.2.0/16", true)
	testIPMatch(t, "192.168.2.123", "192.168.2.123", true)
	testIPMatch(t, "192.168.2.123", "192.168.2.123/32", true)
	testIPMatch(t, "10.0.0.11", "10.0.0.0/8", true)
	testIPMatch(t, "11.0.0.123", "10.0.0.0/8", false)
}

func testRegexMatchFunc(t *testing.T, res bool, err string, args ...interface{}) {
	t.Helper()
	myRes, myErr := RegexMatchFunc(args...)
	myErrStr := ""

	if myErr != nil {
		myErrStr = myErr.Error()
	}

	if myRes != res || err != myErrStr {
		t.Errorf("%v returns %v %v, supposed to be %v %v", args, myRes, myErr, res, err)
	}
}

func testKeyMatchFunc(t *testing.T, res bool, err string, args ...interface{}) {
	t.Helper()
	myRes, myErr := KeyMatchFunc(args...)
	myErrStr := ""

	if myErr != nil {
		myErrStr = myErr.Error()
	}

	if myRes != res || err != myErrStr {
		t.Errorf("%v returns %v %v, supposed to be %v %v", args, myRes, myErr, res, err)
	}
}

func testKeyGetFunc(t *testing.T, res interface{}, err string, args ...interface{}) {
	t.Helper()
	myRes, myErr := KeyGetFunc(args...)
	myErrStr := ""

	if myErr != nil {
		myErrStr = myErr.Error()
	}

	if myRes != res || err != myErrStr {
		t.Errorf("%v returns %v %v, supposed to be %v %v", args, myRes, myErr, res, err)
	}
}

func testKeyMatch2Func(t *testing.T, res bool, err string, args ...interface{}) {
	t.Helper()
	myRes, myErr := KeyMatch2Func(args...)
	myErrStr := ""

	if myErr != nil {
		myErrStr = myErr.Error()
	}

	if myRes != res || err != myErrStr {
		t.Errorf("%v returns %v %v, supposed to be %v %v", args, myRes, myErr, res, err)
	}
}

func testKeyGet2Func(t *testing.T, res interface{}, err string, args ...interface{}) {
	t.Helper()
	myRes, myErr := KeyGet2Func(args...)
	myErrStr := ""

	if myErr != nil {
		myErrStr = myErr.Error()
	}

	if myRes != res || err != myErrStr {
		t.Errorf("%v returns %v %v, supposed to be %v %v", args, myRes, myErr, res, err)
	}
}

func testKeyMatch3Func(t *testing.T, res bool, err string, args ...interface{}) {
	t.Helper()
	myRes, myErr := KeyMatch3Func(args...)
	myErrStr := ""

	if myErr != nil {
		myErrStr = myErr.Error()
	}

	if myRes != res || err != myErrStr {
		t.Errorf("%v returns %v %v, supposed to be %v %v", args, myRes, myErr, res, err)
	}
}

func testKeyGet3Func(t *testing.T, res interface{}, err string, args ...interface{}) {
	t.Helper()
	myRes, myErr := KeyGet3Func(args...)
	myErrStr := ""

	if myErr != nil {
		myErrStr = myErr.Error()
	}

	if myRes != res || err != myErrStr {
		t.Errorf("%v returns %v %v, supposed to be %v %v", args, myRes, myErr, res, err)
	}
}

func testKeyMatch4Func(t *testing.T, res bool, err string, args ...interface{}) {
	t.Helper()
	myRes, myErr := KeyMatch4Func(args...)
	myErrStr := ""

	if myErr != nil {
		myErrStr = myErr.Error()
	}

	if myRes != res || err != myErrStr {
		t.Errorf("%v returns %v %v, supposed to be %v %v", args, myRes, myErr, res, err)
	}
}

func testKeyMatch5Func(t *testing.T, res bool, err string, args ...interface{}) {
	t.Helper()
	myRes, myErr := KeyMatch5Func(args...)
	myErrStr := ""

	if myErr != nil {
		myErrStr = myErr.Error()
	}

	if myRes != res || err != myErrStr {
		t.Errorf("%v returns %v %v, supposed to be %v %v", args, myRes, myErr, res, err)
	}
}

func testIPMatchFunc(t *testing.T, res bool, err string, args ...interface{}) {
	t.Helper()
	myRes, myErr := IPMatchFunc(args...)
	myErrStr := ""

	if myErr != nil {
		myErrStr = myErr.Error()
	}

	if myRes != res || err != myErrStr {
		t.Errorf("%v returns %v %v, supposed to be %v %v", args, myRes, myErr, res, err)
	}
}

func TestRegexMatchFunc(t *testing.T) {
	testRegexMatchFunc(t, false, "regexMatch: expected 2 arguments, but got 1", "/topic/create")
	testRegexMatchFunc(t, false, "regexMatch: expected 2 arguments, but got 3", "/topic/create/123", "/topic/create", "/topic/update")
	testRegexMatchFunc(t, false, "regexMatch: argument must be a string", "/topic/create", false)
	testRegexMatchFunc(t, true, "", "/topic/create/123", "/topic/create")
	testRegexMatchFunc(t, false, "regexMatch: error parsing regexp: missing closing ]: `[0-9`", "/topic/edit/1", "/topic/edit/[0-9")
	testRegexMatchFunc(t, false, "regexMatch: error parsing regexp: missing closing ): `(GET`", "GET", "(GET")
}

func TestKeyMatchFunc(t *testing.T) {
	testKeyMatchFunc(t, false, "keyMatch: expected 2 arguments, but got 1", "/foo")
	testKeyMatchFunc(t, false, "keyMatch: expected 2 arguments, but got 3", "/foo/create/123", "/foo/*", "/foo/update/123")
	testKeyMatchFunc(t, false, "keyMatch: argument must be a string", "/foo", true)
	testKeyMatchFunc(t, false, "", "/foo/bar", "/foo")
	testKeyMatchFunc(t, true, "", "/foo/bar", "/foo/*")
	testKeyMatchFunc(t, true, "", "/foo/bar", "/foo*")
}

func TestKeyGetFunc(t *testing.T) {
	testKeyGetFunc(t, false, "keyGet: expected 2 arguments, but got 1", "/foo")
	testKeyGetFunc(t, false, "keyGet: expected 2 arguments, but got 3", "/foo/bar", "/foo/*", "bar")
	testKeyGetFunc(t, false, "keyGet: argument must be a string", "/foo/bar", true)

	testKeyGetFunc(t, "", "", "/foo/bar", "/foo")
	testKeyGetFunc(t, "bar", "", "/foo/bar", "/foo/*")
	testKeyGetFunc(t, "/bar", "", "/foo/bar", "/foo*")
}

func TestKeyMatch2Func(t *testing.T) {
	testKeyMatch2Func(t, false, "keyMatch2: expected 2 arguments, but got 1", "/")
	testKeyMatch2Func(t, false, "keyMatch2: expected 2 arguments, but got 3", "/foo/create/123", "/*", "/foo/update/123")
	testKeyMatch2Func(t, false, "keyMatch2: argument must be a string", "/foo", true)

	testKeyMatch2Func(t, false, "", "/", "/:resource")
	testKeyMatch2Func(t, true, "", "/resource1", "/:resource")

	testKeyMatch2Func(t, true, "", "/foo", "/foo")
	testKeyMatch2Func(t, true, "", "/foo", "/foo*")
	testKeyMatch2Func(t, false, "", "/foo", "/foo/*")
	testKeyMatch2Func(t, false, "keyMatch2: error parsing regexp: missing closing ): `^/foo/(bar$`", "/foo/bar", "/foo/(bar")
}

func TestKeyGet2Func(t *testing.T) {
	testKeyGet2Func(t, false, "keyGet2: expected 3 arguments, but got 2", "/myid/using/myresid", "/:id/using/:resId")
	testKeyGet2Func(t, false, "keyGet2: expected 3 arguments, but got 4", "/myid/using/myresid", "/:id/using/:resId", "id", "resId")
	testKeyGet2Func(t, false, "keyGet2: argument must be a string", "/myid/using/myresid", "/:id/using/:resId", true)

	testKeyGet2Func(t, "myid", "", "/myid/using/myresid", "/:id/using/:resId", "id")
	testKeyGet2Func(t, "myresid", "", "/myid/using/myresid", "/:id/using/:resId", "resId")
	testKeyGet2Func(t, "", "", "/myid/using/myresid", "/:id/using/:resId", "missing")
	testKeyGet2Func(t, "", "keyGet2: error parsing regexp: missing closing ): `^/(?P<casbinToken0>[^/]+)/(using$`", "/myid/using", "/:id/(using", "id")
}

func TestKeyMatch3Func(t *testing.T) {
	testKeyMatch3Func(t, false, "keyMatch3: expected 2 arguments, but got 1", "/")
	testKeyMatch3Func(t, false, "keyMatch3: expected 2 arguments, but got 3", "/foo/create/123", "/*", "/foo/update/123")
	testKeyMatch3Func(t, false, "keyMatch3: argument must be a string", "/foo", true)

	testKeyMatch3Func(t, true, "", "/foo", "/foo")
	testKeyMatch3Func(t, true, "", "/foo", "/foo*")
	testKeyMatch3Func(t, false, "", "/foo", "/foo/*")
	testKeyMatch3Func(t, false, "", "/foo/bar", "/foo")
	testKeyMatch3Func(t, false, "", "/foo/bar", "/foo*")
	testKeyMatch3Func(t, true, "", "/foo/bar", "/foo/*")
	testKeyMatch3Func(t, false, "", "/foobar", "/foo")
	testKeyMatch3Func(t, false, "", "/foobar", "/foo*")
	testKeyMatch3Func(t, false, "", "/foobar", "/foo/*")

	testKeyMatch3Func(t, false, "", "/", "/{resource}")
	testKeyMatch3Func(t, true, "", "/resource1", "/{resource}")
	testKeyMatch3Func(t, false, "", "/myid", "/{id}/using/{resId}")
	testKeyMatch3Func(t, true, "", "/myid/using/myresid", "/{id}/using/{resId}")

	testKeyMatch3Func(t, false, "", "/proxy/myid", "/proxy/{id}/*")
	testKeyMatch3Func(t, true, "", "/proxy/myid/", "/proxy/{id}/*")
	testKeyMatch3Func(t, true, "", "/proxy/myid/res", "/proxy/{id}/*")
	testKeyMatch3Func(t, true, "", "/proxy/myid/res/res2", "/proxy/{id}/*")
	testKeyMatch3Func(t, true, "", "/proxy/myid/res/res2/res3", "/proxy/{id}/*")
	testKeyMatch3Func(t, false, "", "/proxy/", "/proxy/{id}/*")
}

func TestKeyGet3Func(t *testing.T) {
	testKeyGet3Func(t, false, "keyGet3: expected 3 arguments, but got 2", "/myid/using/myresid", "/{id}/using/{resId}")
	testKeyGet3Func(t, false, "keyGet3: expected 3 arguments, but got 4", "/myid/using/myresid", "/{id}/using/{resId}", "id", "resId")
	testKeyGet3Func(t, false, "keyGet3: argument must be a string", "/myid/using/myresid", "/{id}/using/{resId}", true)

	testKeyGet3Func(t, "myid", "", "/myid/using/myresid", "/{id}/using/{resId}", "id")
	testKeyGet3Func(t, "group_name", "", "/api/group1_group_name/project1_admin/info", "/api/{g}_{gn}/{proj}_admin/info", "gn")
	testKeyGet3Func(t, "", "", "/myid/using/myresid", "/{id}/using/{resId}", "missing")
}

func TestKeyMatch4Func(t *testing.T) {
	testKeyMatch4Func(t, false, "keyMatch4: expected 2 arguments, but got 1", "/parent/123/child/123")
	testKeyMatch4Func(t, false, "keyMatch4: expected 2 arguments, but got 3", "/parent/123/child/123", "/parent/{id}/child/{id}", true)
	testKeyMatch4Func(t, false, "keyMatch4: argument must be a string", "/parent/123/child/123", true)

	testKeyMatch4Func(t, true, "", "/parent/123/child/123", "/parent/{id}/child/{id}")
	testKeyMatch4Func(t, false, "", "/parent/123/child/456", "/parent/{id}/child/{id}")

	testKeyMatch4Func(t, true, "", "/parent/123/child/123", "/parent/{id}/child/{another_id}")
	testKeyMatch4Func(t, true, "", "/parent/123/child/456", "/parent/{id}/child/{another_id}")
}

func TestKeyMatch5Func(t *testing.T) {
	testKeyMatch5Func(t, false, "keyMatch5: expected 2 arguments, but got 1", "/foo")
	testKeyMatch5Func(t, false, "keyMatch5: expected 2 arguments, but got 3", "/foo/create/123", "/foo/*", "/foo/update/123")
	testKeyMatch5Func(t, false, "keyMatch5: argument must be a string", "/parent/123", true)

	testKeyMatch5Func(t, true, "", "/parent/child?status=1&type=2", "/parent/child")
	testKeyMatch5Func(t, false, "", "/parent?status=1&type=2", "/parent/child")

	testKeyMatch5Func(t, true, "", "/parent/child/?status=1&type=2", "/parent/child/")
	testKeyMatch5Func(t, false, "", "/parent/child/?status=1&type=2", "/parent/child")
	testKeyMatch5Func(t, false, "", "/parent/child?status=1&type=2", "/parent/child/")

	testKeyMatch5Func(t, true, "", "/foo", "/foo")
	testKeyMatch5Func(t, true, "", "/foo", "/foo*")
	testKeyMatch5Func(t, false, "", "/foo", "/foo/*")
	testKeyMatch5Func(t, false, "", "/foo/bar", "/foo")
	testKeyMatch5Func(t, false, "", "/foo/bar", "/foo*")
	testKeyMatch5Func(t, true, "", "/foo/bar", "/foo/*")
	testKeyMatch5Func(t, false, "", "/foobar", "/foo")
	testKeyMatch5Func(t, false, "", "/foobar", "/foo*")
	testKeyMatch5Func(t, false, "", "/foobar", "/foo/*")

	testKeyMatch5Func(t, false, "", "/", "/{resource}")
	testKeyMatch5Func(t, true, "", "/resource1", "/{resource}")
	testKeyMatch5Func(t, false, "", "/myid", "/{id}/using/{resId}")
	testKeyMatch5Func(t, true, "", "/myid/using/myresid", "/{id}/using/{resId}")

	testKeyMatch5Func(t, false, "", "/proxy/myid", "/proxy/{id}/*")
	testKeyMatch5Func(t, true, "", "/proxy/myid/", "/proxy/{id}/*")
	testKeyMatch5Func(t, true, "", "/proxy/myid/res", "/proxy/{id}/*")
	testKeyMatch5Func(t, true, "", "/proxy/myid/res/res2", "/proxy/{id}/*")
	testKeyMatch5Func(t, true, "", "/proxy/myid/res/res2/res3", "/proxy/{id}/*")
	testKeyMatch5Func(t, false, "", "/proxy/", "/proxy/{id}/*")

	testKeyMatch5Func(t, false, "", "/proxy/myid?status=1&type=2", "/proxy/{id}/*")
	testKeyMatch5Func(t, true, "", "/proxy/myid/", "/proxy/{id}/*")
	testKeyMatch5Func(t, true, "", "/proxy/myid/res?status=1&type=2", "/proxy/{id}/*")
	testKeyMatch5Func(t, true, "", "/proxy/myid/res/res2?status=1&type=2", "/proxy/{id}/*")
	testKeyMatch5Func(t, true, "", "/proxy/myid/res/res2/res3?status=1&type=2", "/proxy/{id}/*")
	testKeyMatch5Func(t, false, "", "/proxy/", "/proxy/{id}/*")
}

func TestIPMatchFunc(t *testing.T) {
	testIPMatchFunc(t, false, "ipMatch: expected 2 arguments, but got 1", "192.168.2.123")
	testIPMatchFunc(t, false, "ipMatch: argument must be a string", "192.168.2.123", 128)
	testIPMatchFunc(t, true, "", "192.168.2.123", "192.168.2.0/24")
}

func TestGlobMatch(t *testing.T) {
	testGlobMatch(t, "/foo", "/foo", true)
	testGlobMatch(t, "/foo", "/foo*", true)
	testGlobMatch(t, "/foo", "/foo/*", false)
	testGlobMatch(t, "/foo/bar", "/foo", false)
	testGlobMatch(t, "/foo/bar", "/foo*", false)
	testGlobMatch(t, "/foo/bar", "/foo/*", true)
	testGlobMatch(t, "/foobar", "/foo", false)
	testGlobMatch(t, "/foobar", "/foo*", true)
	testGlobMatch(t, "/foobar", "/foo/*", false)

	testGlobMatch(t, "/foo", "*/foo", true)
	testGlobMatch(t, "/foo", "*/foo*", true)
	testGlobMatch(t, "/foo", "*/foo/*", false)
	testGlobMatch(t, "/foo/bar", "*/foo", false)
	testGlobMatch(t, "/foo/bar", "*/foo*", false)
	testGlobMatch(t, "/foo/bar", "*/foo/*", true)
	testGlobMatch(t, "/foobar", "*/foo", false)
	testGlobMatch(t, "/foobar", "*/foo*", true)
	testGlobMatch(t, "/foobar", "*/foo/*", false)

	testGlobMatch(t, "/prefix/foo", "*/foo", false)
	testGlobMatch(t, "/prefix/foo", "*/foo*", false)
	testGlobMatch(t, "/prefix/foo", "*/foo/*", false)
	testGlobMatch(t, "/prefix/foo/bar", "*/foo", false)
	testGlobMatch(t, "/prefix/foo/bar", "*/foo*", false)
	testGlobMatch(t, "/prefix/foo/bar", "*/foo/*", false)
	testGlobMatch(t, "/prefix/foobar", "*/foo", false)
	testGlobMatch(t, "/prefix/foobar", "*/foo*", false)
	testGlobMatch(t, "/prefix/foobar", "*/foo/*", false)

	testGlobMatch(t, "/prefix/subprefix/foo", "*/foo", false)
	testGlobMatch(t, "/prefix/subprefix/foo", "*/foo*", false)
	testGlobMatch(t, "/prefix/subprefix/foo", "*/foo/*", false)
	testGlobMatch(t, "/prefix/subprefix/foo/bar", "*/foo", false)
	testGlobMatch(t, "/prefix/subprefix/foo/bar", "*/foo*", false)
	testGlobMatch(t, "/prefix/subprefix/foo/bar", "*/foo/*", false)
	testGlobMatch(t, "/prefix/subprefix/foobar", "*/foo", false)
	testGlobMatch(t, "/prefix/subprefix/foobar", "*/foo*", false)
	testGlobMatch(t, "/prefix/subprefix/foobar", "*/foo/*", false)

	testGlobMatch(t, "/foo", "**/foo", true)
	testGlobMatch(t, "/foo", "**/foo**", true)
	testGlobMatch(t, "/foo", "**/foo/**", true)
	testGlobMatch(t, "/foo/bar", "**/foo", false)
	testGlobMatch(t, "/foo/bar", "**/foo**", false)
	testGlobMatch(t, "/foo/bar", "**/foo/**", true)
	testGlobMatch(t, "/foobar", "**/foo", false)
	testGlobMatch(t, "/foobar", "**/foo**", true)
	testGlobMatch(t, "/foobar", "**/foo/**", false)

	testGlobMatch(t, "/prefix/foo", "**/foo", true)
	testGlobMatch(t, "/prefix/foo", "**/foo**", true)
	testGlobMatch(t, "/prefix/foo", "**/foo/**", true)
	testGlobMatch(t, "/prefix/foo/bar", "**/foo", false)
	testGlobMatch(t, "/prefix/foo/bar", "**/foo**", false)
	testGlobMatch(t, "/prefix/foo/bar", "**/foo/**", true)
	testGlobMatch(t, "/prefix/foobar", "**/foo", false)
	testGlobMatch(t, "/prefix/foobar", "**/foo**", true)
	testGlobMatch(t, "/prefix/foobar", "**/foo/**", false)

	testGlobMatch(t, "/prefix/subprefix/foo", "**/foo", true)
	testGlobMatch(t, "/prefix/subprefix/foo", "**/foo**", true)
	testGlobMatch(t, "/prefix/subprefix/foo", "**/foo/**", true)
	testGlobMatch(t, "/prefix/subprefix/foo/bar", "**/foo", false)
	testGlobMatch(t, "/prefix/subprefix/foo/bar", "**/foo**", false)
	testGlobMatch(t, "/prefix/subprefix/foo/bar", "**/foo/**", true)
	testGlobMatch(t, "/prefix/subprefix/foobar", "**/foo", false)
	testGlobMatch(t, "/prefix/subprefix/foobar", "**/foo**", true)
	testGlobMatch(t, "/prefix/subprefix/foobar", "**/foo/**", false)

	testGlobMatch(t, "/foo", "*/foo**", true)
	testGlobMatch(t, "/foo", "**/foo*", true)
	testGlobMatch(t, "/foo", "*/foo/**", true)
	testGlobMatch(t, "/foo", "**/foo/*", false)
	testGlobMatch(t, "/foo/bar", "*/foo**", false)
	testGlobMatch(t, "/foo/bar", "**/foo*", false)
	testGlobMatch(t, "/foo/bar", "*/foo/**", true)
	testGlobMatch(t, "/foo/bar", "**/foo/*", true)
	testGlobMatch(t, "/foobar", "*/foo**", true)
	testGlobMatch(t, "/foobar", "**/foo*", true)
	testGlobMatch(t, "/foobar", "*/foo/**", false)
	testGlobMatch(t, "/foobar", "**/foo/*", false)

	testGlobMatch(t, "/prefix/foo", "*/foo**", false)
	testGlobMatch(t, "/prefix/foo", "**/foo*", true)
	testGlobMatch(t, "/prefix/foo", "*/foo/**", false)
	testGlobMatch(t, "/prefix/foo", "**/foo/*", false)
	testGlobMatch(t, "/prefix/foo/bar", "*/foo**", false)
	testGlobMatch(t, "/prefix/foo/bar", "**/foo*", false)
	testGlobMatch(t, "/prefix/foo/bar", "*/foo/**", false)
	testGlobMatch(t, "/prefix/foo/bar", "**/foo/*", true)
	testGlobMatch(t, "/prefix/foobar", "*/foo**", false)
	testGlobMatch(t, "/prefix/foobar", "**/foo*", true)
	testGlobMatch(t, "/prefix/foobar", "*/foo/**", false)
	testGlobMatch(t, "/prefix/foobar", "**/foo/*", false)

	testGlobMatch(t, "/prefix/subprefix/foo", "*/foo**", false)
	testGlobMatch(t, "/prefix/subprefix/foo", "**/foo*", true)
	testGlobMatch(t, "/prefix/subprefix/foo", "*/foo/**", false)
	testGlobMatch(t, "/prefix/subprefix/foo", "**/foo/*", false)
	testGlobMatch(t, "/prefix/subprefix/foo/bar", "*/foo**", false)
	testGlobMatch(t, "/prefix/subprefix/foo/bar", "**/foo*", false)
	testGlobMatch(t, "/prefix/subprefix/foo/bar", "*/foo/**", false)
	testGlobMatch(t, "/prefix/subprefix/foo/bar", "**/foo/*", true)
	testGlobMatch(t, "/prefix/subprefix/foobar", "*/foo**", false)
	testGlobMatch(t, "/prefix/subprefix/foobar", "**/foo*", true)
	testGlobMatch(t, "/prefix/subprefix/foobar", "*/foo/**", false)
	testGlobMatch(t, "/prefix/subprefix/foobar", "**/foo/*", false)
}

func testTimeMatch(t *testing.T, startTime string, endTime string, res bool) {
	t.Helper()
	myRes, err := TimeMatch(startTime, endTime)
	if err != nil {
		panic(err)
	}
	t.Logf("%s < %s: %t", startTime, endTime, myRes)

	if myRes != res {
		t.Errorf("%s < %s: %t, supposed to be %t", startTime, endTime, !res, res)
	}
}

func TestTestMatch(t *testing.T) {
	testTimeMatch(t, "0000-01-01 00:00:00", "0000-01-02 00:00:00", false)
	testTimeMatch(t, "0000-01-01 00:00:00", "9999-12-30 00:00:00", true)
	testTimeMatch(t, "_", "_", true)
	testTimeMatch(t, "_", "9999-12-30 00:00:00", true)
	testTimeMatch(t, "_", "0000-01-02 00:00:00", false)
	testTimeMatch(t, "0000-01-01 00:00:00", "_", true)
	testTimeMatch(t, "9999-12-30 00:00:00", "_", false)
}
