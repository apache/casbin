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

package authztest_test

import (
	"fmt"

	"github.com/casbin/casbin/v3"
	"github.com/casbin/casbin/v3/authztest"
	"github.com/casbin/casbin/v3/model"
)

// The classic failure: a request is denied and you don't know which field
// to look at. Diagnose attributes the failure position by position,
// crediting role inheritance via g rules.
func ExampleDiagnose() {
	m, _ := model.NewModelFromString(`
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
`)
	e, _ := casbin.NewEnforcer(m)
	e.AddPolicy("admin", "data2", "write")
	e.AddGroupingPolicy("alice", "admin")

	fmt.Println(authztest.Diagnose(e, "alice", "data2", "read"))
	// Output:
	// no policy matched; closest candidates:
	//   p, admin, data2, write
	//     sub: ok ('alice' inherits 'admin' via g)
	//     obj: ok ('data2')
	//     act: 'read' does not match 'write' (not a wildcard)
}
