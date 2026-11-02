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

package config

import (
	"testing"
)

func TestGet(t *testing.T) {
	config, cerr := NewConfig("testdata/testini.ini")
	if cerr != nil {
		t.Errorf("Configuration file loading failed, err:%v", cerr.Error())
		t.Fatalf("err: %v", cerr)
	}

	// default::key test
	if v, err := config.Bool("debug"); err != nil || !v {
		t.Errorf("Get failure: expected different value for debug (expected: [%#v] got: [%#v])", true, v)
		t.Fatalf("err: %v", err)
	}
	if v := config.String("url"); v != "act.wiki" {
		t.Errorf("Get failure: expected different value for url (expected: [%#v] got: [%#v])", "act.wiki", v)
	}

	// redis::key test
	if v := config.Strings("redis::redis.key"); len(v) != 2 || v[0] != "push1" || v[1] != "push2" {
		t.Errorf("Get failure: expected different value for redis::redis.key (expected: [%#v] got: [%#v])", "[]string{push1,push2}", v)
	}
	if v := config.String("mysql::mysql.dev.host"); v != "127.0.0.1" {
		t.Errorf("Get failure: expected different value for mysql::mysql.dev.host (expected: [%#v] got: [%#v])", "127.0.0.1", v)
	}
	if v := config.String("mysql::mysql.master.host"); v != "10.0.0.1" {
		t.Errorf("Get failure: expected different value for mysql::mysql.master.host (expected: [%#v] got: [%#v])", "10.0.0.1", v)
	}
	if v := config.String("mysql::mysql.master.user"); v != "root" {
		t.Errorf("Get failure: expected different value for mysql::mysql.master.user (expected: [%#v] got: [%#v])", "root", v)
	}
	if v := config.String("mysql::mysql.master.note"); v != `"a#b;c" 'd#e'` {
		t.Errorf("Get failure: expected different value for mysql::mysql.master.note (expected: [%#v] got: [%#v])", `"a#b;c" 'd#e'`, v)
	}
	if v := config.String("mysql::mysql.master.pass"); v != "89dds)2$" {
		t.Errorf("Get failure: expected different value for mysql::mysql.master.pass (expected: [%#v] got: [%#v])", "89dds)2$", v)
	}
	// math::key test
	if v, err := config.Int64("math::math.i64"); err != nil || v != 64 {
		t.Errorf("Get failure: expected different value for math::math.i64 (expected: [%#v] got: [%#v])", 64, v)
		t.Fatalf("err: %v", err)
	}
	if v, err := config.Float64("math::math.f64"); err != nil || v != 64.1 {
		t.Errorf("Get failure: expected different value for math::math.f64 (expected: [%#v] got: [%#v])", 64.1, v)
		t.Fatalf("err: %v", err)
	}

	_ = config.Set("other::key1", "new test key")

	if v := config.String("other::key1"); v != "new test key" {
		t.Errorf("Get failure: expected different value for other::key1 (expected: [%#v] got: [%#v])", "new test key", v)
	}

	_ = config.Set("other::key1", "test key")

	if v := config.String("multi1::name"); v != "r.sub==p.sub && r.obj==p.obj" {
		t.Errorf("Get failure: expected different value for multi1::name (expected: [%#v] got: [%#v])", "r.sub==p.sub&&r.obj==p.obj", v)
	}

	if v := config.String("multi2::name"); v != "r.sub==p.sub && r.obj==p.obj" {
		t.Errorf("Get failure: expected different value for multi2::name (expected: [%#v] got: [%#v])", "r.sub==p.sub&&r.obj==p.obj", v)
	}

	if v := config.String("multi3::name"); v != "r.sub==p.sub && r.obj==p.obj" {
		t.Errorf("Get failure: expected different value for multi3::name (expected: [%#v] got: [%#v])", "r.sub==p.sub&&r.obj==p.obj", v)
	}

	if v := config.String("multi4::name"); v != "" {
		t.Errorf("Get failure: expected different value for multi4::name (expected: [%#v] got: [%#v])", "", v)
	}

	if v := config.String("multi5::name"); v != "r.sub==p.sub && r.obj==p.obj" {
		t.Errorf("Get failure: expected different value for multi5::name (expected: [%#v] got: [%#v])", "r.sub==p.sub&&r.obj==p.obj", v)
	}
}
