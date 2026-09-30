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

package defaultrolemanager

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/casbin/casbin/v3/rbac"
	"github.com/casbin/casbin/v3/util"
)

func testRole(t *testing.T, rm rbac.RoleManager, name1 string, name2 string, res bool) {
	t.Helper()
	myRes, _ := rm.HasLink(name1, name2)
	t.Logf("%s, %s: %t", name1, name2, myRes)

	if myRes != res {
		t.Errorf("%s < %s: %t, supposed to be %t", name1, name2, !res, res)
	}
}

func testDomainRole(t *testing.T, rm rbac.RoleManager, name1 string, name2 string, domain string, res bool) {
	t.Helper()
	myRes, _ := rm.HasLink(name1, name2, domain)
	t.Logf("%s :: %s, %s: %t", domain, name1, name2, myRes)

	if myRes != res {
		t.Errorf("%s :: %s < %s: %t, supposed to be %t", domain, name1, name2, !res, res)
	}
}

func testPrintRoles(t *testing.T, rm rbac.RoleManager, name string, res []string) {
	t.Helper()
	myRes, _ := rm.GetRoles(name)
	t.Logf("%s: %s", name, myRes)

	if !util.SetEquals(myRes, res) {
		t.Errorf("%s: %s, supposed to be %s", name, myRes, res)
	}
}

func testPrintUsers(t *testing.T, rm rbac.RoleManager, name string, res []string) {
	t.Helper()
	myRes, _ := rm.GetUsers(name)
	t.Logf("%s: %s", name, myRes)

	if !util.SetEquals(myRes, res) {
		t.Errorf("%s: %s, supposed to be %s", name, myRes, res)
	}
}

func testPrintRolesWithDomain(t *testing.T, rm rbac.RoleManager, name string, domain string, res []string) {
	t.Helper()
	myRes, _ := rm.GetRoles(name, domain)

	if !util.SetEquals(myRes, res) {
		t.Errorf("%s: %s, supposed to be %s", name, myRes, res)
	}
}

func TestRole(t *testing.T) {
	rm := NewRoleManager(3)
	_ = rm.AddLink("u1", "g1")
	_ = rm.AddLink("u2", "g1")
	_ = rm.AddLink("u3", "g2")
	_ = rm.AddLink("u4", "g2")
	_ = rm.AddLink("u4", "g3")
	_ = rm.AddLink("g1", "g3")

	// Current role inheritance tree:
	//             g3    g2
	//            /  \  /  \
	//          g1    u4    u3
	//         /  \
	//       u1    u2

	testRole(t, rm, "u1", "g1", true)
	testRole(t, rm, "u1", "g2", false)
	testRole(t, rm, "u1", "g3", true)
	testRole(t, rm, "u2", "g1", true)
	testRole(t, rm, "u2", "g2", false)
	testRole(t, rm, "u2", "g3", true)
	testRole(t, rm, "u3", "g1", false)
	testRole(t, rm, "u3", "g2", true)
	testRole(t, rm, "u3", "g3", false)
	testRole(t, rm, "u4", "g1", false)
	testRole(t, rm, "u4", "g2", true)
	testRole(t, rm, "u4", "g3", true)

	testPrintRoles(t, rm, "u1", []string{"g1"})
	testPrintRoles(t, rm, "u2", []string{"g1"})
	testPrintRoles(t, rm, "u3", []string{"g2"})
	testPrintRoles(t, rm, "u4", []string{"g2", "g3"})
	testPrintRoles(t, rm, "g1", []string{"g3"})
	testPrintRoles(t, rm, "g2", []string{})
	testPrintRoles(t, rm, "g3", []string{})

	_ = rm.DeleteLink("g1", "g3")
	_ = rm.DeleteLink("u4", "g2")

	// Current role inheritance tree after deleting the links:
	//             g3    g2
	//               \     \
	//          g1    u4    u3
	//         /  \
	//       u1    u2

	testRole(t, rm, "u1", "g1", true)
	testRole(t, rm, "u1", "g2", false)
	testRole(t, rm, "u1", "g3", false)
	testRole(t, rm, "u2", "g1", true)
	testRole(t, rm, "u2", "g2", false)
	testRole(t, rm, "u2", "g3", false)
	testRole(t, rm, "u3", "g1", false)
	testRole(t, rm, "u3", "g2", true)
	testRole(t, rm, "u3", "g3", false)
	testRole(t, rm, "u4", "g1", false)
	testRole(t, rm, "u4", "g2", false)
	testRole(t, rm, "u4", "g3", true)

	testPrintRoles(t, rm, "u1", []string{"g1"})
	testPrintRoles(t, rm, "u2", []string{"g1"})
	testPrintRoles(t, rm, "u3", []string{"g2"})
	testPrintRoles(t, rm, "u4", []string{"g3"})
	testPrintRoles(t, rm, "g1", []string{})
	testPrintRoles(t, rm, "g2", []string{})
	testPrintRoles(t, rm, "g3", []string{})

	rm = NewRoleManager(3)
	rm.AddMatchingFunc("keyMatch", util.KeyMatch)

	_ = rm.AddLink("u1", "g1")
	_ = rm.AddLink("u1", "*")
	_ = rm.AddLink("u2", "g2")

	// Current role inheritance tree after deleting the links:
	//          g1   g2
	//            \ /  \
	//             *    u2
	//             |
	//             u1
	testRole(t, rm, "u1", "g1", true)
	testRole(t, rm, "u1", "g2", true)
	testRole(t, rm, "u2", "g2", true)
	testRole(t, rm, "u2", "g1", false)
	testPrintRoles(t, rm, "u1", []string{"*", "u1", "u2", "g1", "g2"})
	testPrintUsers(t, rm, "*", []string{"u1"})
}

func TestDomainRole(t *testing.T) {
	rm := NewRoleManager(3)
	_ = rm.AddLink("u1", "g1", "domain1")
	_ = rm.AddLink("u2", "g1", "domain1")
	_ = rm.AddLink("u3", "admin", "domain2")
	_ = rm.AddLink("u4", "admin", "domain2")
	_ = rm.AddLink("u4", "admin", "domain1")
	_ = rm.AddLink("g1", "admin", "domain1")

	// Current role inheritance tree:
	//       domain1:admin    domain2:admin
	//            /       \  /       \
	//      domain1:g1     u4         u3
	//         /  \
	//       u1    u2

	testDomainRole(t, rm, "u1", "g1", "domain1", true)
	testDomainRole(t, rm, "u1", "g1", "domain2", false)
	testDomainRole(t, rm, "u1", "admin", "domain1", true)
	testDomainRole(t, rm, "u1", "admin", "domain2", false)

	testDomainRole(t, rm, "u2", "g1", "domain1", true)
	testDomainRole(t, rm, "u2", "g1", "domain2", false)
	testDomainRole(t, rm, "u2", "admin", "domain1", true)
	testDomainRole(t, rm, "u2", "admin", "domain2", false)

	testDomainRole(t, rm, "u3", "g1", "domain1", false)
	testDomainRole(t, rm, "u3", "g1", "domain2", false)
	testDomainRole(t, rm, "u3", "admin", "domain1", false)
	testDomainRole(t, rm, "u3", "admin", "domain2", true)

	testDomainRole(t, rm, "u4", "g1", "domain1", false)
	testDomainRole(t, rm, "u4", "g1", "domain2", false)
	testDomainRole(t, rm, "u4", "admin", "domain1", true)
	testDomainRole(t, rm, "u4", "admin", "domain2", true)

	_ = rm.DeleteLink("g1", "admin", "domain1")
	_ = rm.DeleteLink("u4", "admin", "domain2")

	// Current role inheritance tree after deleting the links:
	//       domain1:admin    domain2:admin
	//                    \          \
	//      domain1:g1     u4         u3
	//         /  \
	//       u1    u2

	testDomainRole(t, rm, "u1", "g1", "domain1", true)
	testDomainRole(t, rm, "u1", "g1", "domain2", false)
	testDomainRole(t, rm, "u1", "admin", "domain1", false)
	testDomainRole(t, rm, "u1", "admin", "domain2", false)

	testDomainRole(t, rm, "u2", "g1", "domain1", true)
	testDomainRole(t, rm, "u2", "g1", "domain2", false)
	testDomainRole(t, rm, "u2", "admin", "domain1", false)
	testDomainRole(t, rm, "u2", "admin", "domain2", false)

	testDomainRole(t, rm, "u3", "g1", "domain1", false)
	testDomainRole(t, rm, "u3", "g1", "domain2", false)
	testDomainRole(t, rm, "u3", "admin", "domain1", false)
	testDomainRole(t, rm, "u3", "admin", "domain2", true)

	testDomainRole(t, rm, "u4", "g1", "domain1", false)
	testDomainRole(t, rm, "u4", "g1", "domain2", false)
	testDomainRole(t, rm, "u4", "admin", "domain1", true)
	testDomainRole(t, rm, "u4", "admin", "domain2", false)
}

func TestClear(t *testing.T) {
	rm := NewRoleManager(3)
	_ = rm.AddLink("u1", "g1")
	_ = rm.AddLink("u2", "g1")
	_ = rm.AddLink("u3", "g2")
	_ = rm.AddLink("u4", "g2")
	_ = rm.AddLink("u4", "g3")
	_ = rm.AddLink("g1", "g3")

	// Current role inheritance tree:
	//             g3    g2
	//            /  \  /  \
	//          g1    u4    u3
	//         /  \
	//       u1    u2

	_ = rm.Clear()

	// All data is cleared.
	// No role inheritance now.

	testRole(t, rm, "u1", "g1", false)
	testRole(t, rm, "u1", "g2", false)
	testRole(t, rm, "u1", "g3", false)
	testRole(t, rm, "u2", "g1", false)
	testRole(t, rm, "u2", "g2", false)
	testRole(t, rm, "u2", "g3", false)
	testRole(t, rm, "u3", "g1", false)
	testRole(t, rm, "u3", "g2", false)
	testRole(t, rm, "u3", "g3", false)
	testRole(t, rm, "u4", "g1", false)
	testRole(t, rm, "u4", "g2", false)
	testRole(t, rm, "u4", "g3", false)
}

func TestDomainPatternRole(t *testing.T) {
	rm := NewRoleManager(10)
	rm.AddDomainMatchingFunc("keyMatch2", util.KeyMatch2)

	_ = rm.AddLink("u1", "g1", "domain1")
	_ = rm.AddLink("u2", "g1", "domain2")
	_ = rm.AddLink("u3", "g1", "*")
	_ = rm.AddLink("u4", "g2", "domain3")
	// Current role inheritance tree after deleting the links:
	//       domain1:g1    domain2:g1			domain3:g2
	//		   /      \    /      \					|
	//	 domain1:u1    *:g1     domain2:u2		domain3:u4
	// 					|
	// 				   *:u3
	testDomainRole(t, rm, "u1", "g1", "domain1", true)
	testDomainRole(t, rm, "u2", "g1", "domain1", false)
	testDomainRole(t, rm, "u2", "g1", "domain2", true)
	testDomainRole(t, rm, "u3", "g1", "domain1", true)
	testDomainRole(t, rm, "u3", "g1", "domain2", true)
	testDomainRole(t, rm, "u1", "g2", "domain1", false)
	testDomainRole(t, rm, "u4", "g2", "domain3", true)
	testDomainRole(t, rm, "u3", "g2", "domain3", false)

	testPrintRolesWithDomain(t, rm, "u3", "domain1", []string{"g1"})
	testPrintRolesWithDomain(t, rm, "u1", "domain1", []string{"g1"})
	testPrintRolesWithDomain(t, rm, "u3", "domain2", []string{"g1"})
	testPrintRolesWithDomain(t, rm, "u1", "domain2", []string{})
	testPrintRolesWithDomain(t, rm, "u4", "domain3", []string{"g2"})
}

func TestAllMatchingFunc(t *testing.T) {
	rm := NewRoleManager(10)
	rm.AddMatchingFunc("keyMatch2", util.KeyMatch2)
	rm.AddDomainMatchingFunc("keyMatch2", util.KeyMatch2)

	_ = rm.AddLink("/book/:id", "book_group", "*")
	// Current role inheritance tree after deleting the links:
	//  		*:book_group
	//				|
	// 			*:/book/:id
	testDomainRole(t, rm, "/book/1", "book_group", "domain1", true)
	testDomainRole(t, rm, "/book/2", "book_group", "domain1", true)
}

func TestMatchingFuncOrder(t *testing.T) {
	rm := NewRoleManager(10)
	rm.AddMatchingFunc("regexMatch", util.RegexMatch)

	_ = rm.AddLink("g\\d+", "root")
	_ = rm.AddLink("u1", "g1")
	testRole(t, rm, "u1", "root", true)

	_ = rm.Clear()

	_ = rm.AddLink("u1", "g1")
	_ = rm.AddLink("g\\d+", "root")
	testRole(t, rm, "u1", "root", true)

	_ = rm.Clear()

	_ = rm.AddLink("u1", "g\\d+")
	testRole(t, rm, "u1", "g1", true)
	testRole(t, rm, "u1", "g2", true)
}

func TestDomainMatchingFuncWithDifferentDomain(t *testing.T) {
	rm := NewRoleManager(10)
	rm.AddDomainMatchingFunc("keyMatch", util.KeyMatch)

	_ = rm.AddLink("alice", "editor", "*")
	_ = rm.AddLink("editor", "admin", "domain1")

	testDomainRole(t, rm, "alice", "admin", "domain1", true)
	testDomainRole(t, rm, "alice", "admin", "domain2", false)
}

func TestDomainPatternDeleteLinkKeepsLinksStillGranted(t *testing.T) {
	rm := NewRoleManager(10)
	rm.AddDomainMatchingFunc("keyMatch", util.KeyMatch)

	// alice is admin in every domain and also in domain1 on its own.
	_ = rm.AddLink("alice", "admin", "*")
	_ = rm.AddLink("alice", "admin", "domain1")

	// Deleting the domain1 link must not drop what "*" still grants there.
	_ = rm.DeleteLink("alice", "admin", "domain1")
	testDomainRole(t, rm, "alice", "admin", "domain1", true)
	testDomainRole(t, rm, "alice", "admin", "domain2", true)

	// bob is admin in domain2 on his own and also through "*".
	_ = rm.AddLink("bob", "admin", "domain2")
	_ = rm.AddLink("bob", "admin", "*")

	// Deleting the "*" link must not drop bob's own domain2 link.
	_ = rm.DeleteLink("bob", "admin", "*")
	testDomainRole(t, rm, "bob", "admin", "domain2", true)
	testDomainRole(t, rm, "bob", "admin", "domain1", false)

	// Once no link grants it any more, the link is gone everywhere.
	_ = rm.DeleteLink("alice", "admin", "*")
	testDomainRole(t, rm, "alice", "admin", "domain1", false)
	testDomainRole(t, rm, "alice", "admin", "domain2", false)
	_ = rm.DeleteLink("bob", "admin", "domain2")
	testDomainRole(t, rm, "bob", "admin", "domain2", false)
}

func TestDomainPatternRebuildUsesAddedLinks(t *testing.T) {
	rm := NewRoleManager(10)
	rm.AddDomainMatchingFunc("keyMatch", util.KeyMatch)

	_ = rm.AddLink("carol", "admin", "domain1")
	_ = rm.AddLink("alice", "admin", "*")

	// Setting the matching function again rebuilds the role managers; the
	// "*" link copied into domain1 must not become a domain1 link of its own.
	rm.AddDomainMatchingFunc("keyMatch", util.KeyMatch)
	_ = rm.DeleteLink("alice", "admin", "*")
	testDomainRole(t, rm, "alice", "admin", "domain1", false)
	testDomainRole(t, rm, "carol", "admin", "domain1", true)
}

func TestTemporaryRoles(t *testing.T) {
	rm := NewRoleManager(10)
	rm.AddMatchingFunc("regexMatch", util.RegexMatch)

	_ = rm.AddLink("u\\d+", "user")

	for i := 0; i < 10; i++ {
		testRole(t, rm, fmt.Sprintf("u%d", i), "user", true)
	}

	testPrintUsers(t, rm, "user", []string{"u\\d+"})
	testPrintRoles(t, rm, "u1", []string{"user"})

	_ = rm.AddLink("u1", "manager")

	for i := 10; i < 20; i++ {
		testRole(t, rm, fmt.Sprintf("u%d", i), "user", true)
	}

	testPrintUsers(t, rm, "user", []string{"u\\d+", "u1"})
	testPrintRoles(t, rm, "u1", []string{"user", "manager"})
}

func TestMaxHierarchyLevel(t *testing.T) {
	rm := NewRoleManager(1)
	_ = rm.AddLink("level0", "level1")
	_ = rm.AddLink("level1", "level2")
	_ = rm.AddLink("level2", "level3")

	testRole(t, rm, "level0", "level0", true)
	testRole(t, rm, "level0", "level1", true)
	testRole(t, rm, "level0", "level2", false)
	testRole(t, rm, "level0", "level3", false)
	testRole(t, rm, "level1", "level2", true)
	testRole(t, rm, "level1", "level3", false)

	rm = NewRoleManager(2)
	_ = rm.AddLink("level0", "level1")
	_ = rm.AddLink("level1", "level2")
	_ = rm.AddLink("level2", "level3")

	testRole(t, rm, "level0", "level0", true)
	testRole(t, rm, "level0", "level1", true)
	testRole(t, rm, "level0", "level2", true)
	testRole(t, rm, "level0", "level3", false)
	testRole(t, rm, "level1", "level2", true)
	testRole(t, rm, "level1", "level3", true)
}

// TestConcurrentHasLink tests concurrent HasLink calls for race conditions.
// This test verifies that concurrent HasLink calls with matching functions
// don't produce inconsistent results due to temporary role creation/deletion races.
// Regression test for issue #1318.
func TestConcurrentHasLink(t *testing.T) {
	rm := NewRoleManager(10)
	rm.AddMatchingFunc("keyMatch2", util.KeyMatch2)

	_ = rm.AddLink("alice", "admin")
	_ = rm.AddLink("admin", "/data/*")

	expected, _ := rm.HasLink("alice", "/data/123")

	const numGoroutines = 20
	const numIterations = 100

	var inconsistencies int64
	var wg sync.WaitGroup

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < numIterations; j++ {
				result, err := rm.HasLink("alice", "/data/123")
				if err != nil {
					t.Errorf("HasLink failed: %v", err)
					return
				} else if result != expected {
					atomic.AddInt64(&inconsistencies, 1)
				}
			}
		}()
	}

	wg.Wait()

	if inconsistencies > 0 {
		t.Errorf("Found %d inconsistencies in %d total operations",
			inconsistencies, numGoroutines*numIterations)
	}
}
