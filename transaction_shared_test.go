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

// Tests for the shared-transaction pattern described in
// https://github.com/apache/casbin/issues/1702.
//
// The core concern: when an application runs business-table writes and policy
// changes inside the same database transaction, both must be atomic.  If the
// business step fails after the policy write, the policy write must roll back
// too — not get silently persisted.
//
// The tests here use a mock adapter that models exactly that contract: writes
// are staged in an "inflight" buffer and only moved to the "persisted" store
// on Commit.  Rollback discards the buffer.  Business writes go through the
// same adapter so we can assert on both tables simultaneously.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist"
)

// atomicMockAdapter is a TransactionalAdapter that keeps a clear boundary
// between in-flight and committed writes.  It stands in for something like
// gorm-adapter where the database enforces that boundary for real.
type atomicMockAdapter struct {
	persisted    map[string]bool
	businessRows map[string]bool
}

type atomicMockTxState struct {
	parent           *atomicMockAdapter
	inflightPolicies []atomicTxOp
	inflightBusiness []atomicTxOp
	done             bool
}

type atomicTxOp struct {
	add bool
	key string
}

func newAtomicMockAdapter() *atomicMockAdapter {
	return &atomicMockAdapter{
		persisted:    make(map[string]bool),
		businessRows: make(map[string]bool),
	}
}

func (a *atomicMockAdapter) LoadPolicy(model.Model) error { return nil }
func (a *atomicMockAdapter) SavePolicy(model.Model) error { return nil }
func (a *atomicMockAdapter) AddPolicy(_ string, _ string, _ []string) error {
	return nil
}
func (a *atomicMockAdapter) RemovePolicy(_ string, _ string, _ []string) error {
	return nil
}
func (a *atomicMockAdapter) RemoveFilteredPolicy(_ string, _ string, _ int, _ ...string) error {
	return nil
}
func (a *atomicMockAdapter) BeginTransaction(_ context.Context) (persist.TransactionContext, error) {
	return &atomicMockTxState{parent: a}, nil
}

func (tx *atomicMockTxState) insertBusinessRow(key string) {
	tx.inflightBusiness = append(tx.inflightBusiness, atomicTxOp{add: true, key: key})
}

func (tx *atomicMockTxState) Commit() error {
	if tx.done {
		return errors.New("transaction already finished")
	}
	tx.done = true
	for _, op := range tx.inflightPolicies {
		if op.add {
			tx.parent.persisted[op.key] = true
		} else {
			delete(tx.parent.persisted, op.key)
		}
	}
	for _, op := range tx.inflightBusiness {
		if op.add {
			tx.parent.businessRows[op.key] = true
		} else {
			delete(tx.parent.businessRows, op.key)
		}
	}
	return nil
}

func (tx *atomicMockTxState) Rollback() error {
	if tx.done {
		return errors.New("transaction already finished")
	}
	tx.done = true
	return nil
}

func (tx *atomicMockTxState) GetAdapter() persist.Adapter {
	return &atomicMockTxAdapter{tx: tx}
}

// atomicMockTxAdapter routes policy writes through the open transaction so
// they share fate with any business writes staged via insertBusinessRow.
type atomicMockTxAdapter struct {
	tx *atomicMockTxState
}

func (a *atomicMockTxAdapter) LoadPolicy(model.Model) error { return nil }
func (a *atomicMockTxAdapter) SavePolicy(model.Model) error { return nil }
func (a *atomicMockTxAdapter) AddPolicy(_ string, _ string, rule []string) error {
	a.tx.inflightPolicies = append(a.tx.inflightPolicies, atomicTxOp{add: true, key: atomicRuleKey(rule)})
	return nil
}
func (a *atomicMockTxAdapter) RemovePolicy(_ string, _ string, rule []string) error {
	a.tx.inflightPolicies = append(a.tx.inflightPolicies, atomicTxOp{add: false, key: atomicRuleKey(rule)})
	return nil
}
func (a *atomicMockTxAdapter) RemoveFilteredPolicy(_ string, _ string, _ int, _ ...string) error {
	return nil
}

func atomicRuleKey(rule []string) string {
	return strings.Join(rule, ",")
}

// TestSharedTransactionRollback shows that when business logic fails after a
// policy change, neither the policy write nor the business write survives.
//
// This is the failure mode reported in issue #1702: without a shared
// transaction the policy row gets committed even though the rest of the
// operation rolls back.
func TestSharedTransactionRollback(t *testing.T) {
	a := newAtomicMockAdapter()
	e, err := NewTransactionalEnforcer("examples/rbac_model.conf", a)
	if err != nil {
		t.Fatalf("enforcer: %v", err)
	}

	bizErr := errors.New("payment gateway timeout")

	err = e.WithTransaction(context.Background(), func(tx *Transaction) error {
		if _, addErr := tx.AddGroupingPolicy("alice", "admin"); addErr != nil {
			return addErr
		}

		// Caller writes to their own table via the transaction-scoped adapter.
		if sharedTx, ok := tx.txContext.(*atomicMockTxState); ok {
			sharedTx.insertBusinessRow("order:42")
		}

		return bizErr
	})

	if !errors.Is(err, bizErr) {
		t.Fatalf("expected bizErr, got %v", err)
	}

	// The in-memory model must not reflect the rolled-back policy.
	if ok, _ := e.HasGroupingPolicy("alice", "admin"); ok {
		t.Fatal("policy must be rolled back together with the transaction")
	}
	if a.persisted["alice,admin"] {
		t.Fatal("policy row must not reach the persisted store after rollback")
	}
	if a.businessRows["order:42"] {
		t.Fatal("business row must not reach the persisted store after rollback")
	}
}

// TestSharedTransactionCommit is the happy path: both the policy change and
// the business write land atomically when there is no error.
func TestSharedTransactionCommit(t *testing.T) {
	a := newAtomicMockAdapter()
	e, err := NewTransactionalEnforcer("examples/rbac_model.conf", a)
	if err != nil {
		t.Fatalf("enforcer: %v", err)
	}

	err = e.WithTransaction(context.Background(), func(tx *Transaction) error {
		if _, addErr := tx.AddGroupingPolicy("alice", "admin"); addErr != nil {
			return addErr
		}
		if _, addErr := tx.AddPolicy("admin", "data1", "read"); addErr != nil {
			return addErr
		}
		if sharedTx, ok := tx.txContext.(*atomicMockTxState); ok {
			sharedTx.insertBusinessRow("order:99")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("transaction: %v", err)
	}

	if ok, _ := e.HasGroupingPolicy("alice", "admin"); !ok {
		t.Fatal("grouping policy should be visible after commit")
	}
	if ok, _ := e.HasPolicy("admin", "data1", "read"); !ok {
		t.Fatal("policy should be visible after commit")
	}
	if !a.persisted["alice,admin"] {
		t.Fatal("grouping policy row should be in persisted store after commit")
	}
	if !a.persisted["admin,data1,read"] {
		t.Fatal("policy row should be in persisted store after commit")
	}
	if !a.businessRows["order:99"] {
		t.Fatal("business row should be in persisted store after commit")
	}

	// Role links must have been rebuilt: alice inherits admin's permission.
	if ok, enforceErr := e.Enforce("alice", "data1", "read"); enforceErr != nil || !ok {
		t.Fatalf("alice should inherit admin's read, got %v (err %v)", ok, enforceErr)
	}
}
