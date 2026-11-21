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
	"context"
	"errors"
	"testing"

	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist"
)

// MockTransactionalAdapter implements TransactionalAdapter interface for testing.
type MockTransactionalAdapter struct {
	Enforcer *Enforcer
}

// MockTransactionContext implements TransactionContext interface for testing.
type MockTransactionContext struct {
	adapter    *MockTransactionalAdapter
	committed  bool
	rolledBack bool
}

// NewMockTransactionalAdapter creates a new mock adapter.
func NewMockTransactionalAdapter() *MockTransactionalAdapter {
	return &MockTransactionalAdapter{}
}

// LoadPolicy implements Adapter interface.
func (a *MockTransactionalAdapter) LoadPolicy(model model.Model) error {
	return nil
}

// SavePolicy implements Adapter interface.
func (a *MockTransactionalAdapter) SavePolicy(model model.Model) error {
	return nil
}

// AddPolicy implements Adapter interface.
func (a *MockTransactionalAdapter) AddPolicy(sec string, ptype string, rule []string) error {
	return nil
}

// RemovePolicy implements Adapter interface.
func (a *MockTransactionalAdapter) RemovePolicy(sec string, ptype string, rule []string) error {
	return nil
}

// RemoveFilteredPolicy implements Adapter interface.
func (a *MockTransactionalAdapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	return nil
}

// BeginTransaction implements TransactionalAdapter interface.
func (a *MockTransactionalAdapter) BeginTransaction(ctx context.Context) (persist.TransactionContext, error) {
	return &MockTransactionContext{adapter: a}, nil
}

// Commit implements TransactionContext interface.
func (tx *MockTransactionContext) Commit() error {
	if tx.committed || tx.rolledBack {
		return errors.New("transaction already finished")
	}
	tx.committed = true
	return nil
}

// Rollback implements TransactionContext interface.
func (tx *MockTransactionContext) Rollback() error {
	if tx.committed || tx.rolledBack {
		return errors.New("transaction already finished")
	}
	tx.rolledBack = true
	return nil
}

// GetAdapter implements TransactionContext interface.
func (tx *MockTransactionContext) GetAdapter() persist.Adapter {
	return tx.adapter
}

// Test basic transaction functionality.
func TestTransactionBasicOperations(t *testing.T) {
	adapter := NewMockTransactionalAdapter()
	e, err := NewTransactionalEnforcer("examples/rbac_model.conf", adapter)
	if err != nil {
		t.Fatalf("Failed to create transactional enforcer: %v", err)
	}
	adapter.Enforcer = e.Enforcer

	ctx := context.Background()

	// Begin transaction.
	tx, err := e.BeginTransaction(ctx)
	if err != nil {
		t.Fatalf("Failed to begin transaction: %v", err)
	}

	// Add policies in transaction.
	ok, err := tx.AddPolicy("alice", "data1", "read")
	if !ok || err != nil {
		t.Fatalf("Failed to add policy in transaction: %v", err)
	}

	ok, err = tx.AddPolicy("bob", "data2", "write")
	if !ok || err != nil {
		t.Fatalf("Failed to add policy in transaction: %v", err)
	}

	// Commit transaction.
	if err := tx.Commit(); err != nil {
		t.Fatalf("Failed to commit transaction: %v", err)
	}

	// Verify transaction was committed.
	if !tx.IsCommitted() {
		t.Error("Transaction should be committed")
	}
}

// Test transaction rollback.
func TestTransactionRollback(t *testing.T) {
	adapter := NewMockTransactionalAdapter()
	e, err := NewTransactionalEnforcer("examples/rbac_model.conf", adapter)
	if err != nil {
		t.Fatalf("Failed to create transactional enforcer: %v", err)
	}
	adapter.Enforcer = e.Enforcer

	ctx := context.Background()

	// Begin transaction.
	tx, err := e.BeginTransaction(ctx)
	if err != nil {
		t.Fatalf("Failed to begin transaction: %v", err)
	}

	// Add policy in transaction.
	ok, err := tx.AddPolicy("alice", "data1", "read")
	if !ok || err != nil {
		t.Fatalf("Failed to add policy in transaction: %v", err)
	}

	// Rollback transaction.
	if err := tx.Rollback(); err != nil {
		t.Fatalf("Failed to rollback transaction: %v", err)
	}

	// Verify transaction was rolled back.
	if !tx.IsRolledBack() {
		t.Error("Transaction should be rolled back")
	}
}

// Test concurrent transactions.
func TestConcurrentTransactions(t *testing.T) {
	adapter := NewMockTransactionalAdapter()
	e, err := NewTransactionalEnforcer("examples/rbac_model.conf", adapter)
	if err != nil {
		t.Fatalf("Failed to create transactional enforcer: %v", err)
	}
	adapter.Enforcer = e.Enforcer

	ctx := context.Background()

	// Start first transaction
	tx1, err := e.BeginTransaction(ctx)
	if err != nil {
		t.Fatalf("Failed to begin transaction 1: %v", err)
	}

	// Add policy in first transaction
	ok, err := tx1.AddPolicy("alice", "data1", "read")
	if !ok || err != nil {
		t.Fatalf("Failed to add policy in transaction 1: %v", err)
	}

	// Start second transaction
	tx2, err := e.BeginTransaction(ctx)
	if err != nil {
		t.Fatalf("Failed to begin transaction 2: %v", err)
	}

	// Add different policy in second transaction
	ok, err = tx2.AddPolicy("bob", "data2", "write")
	if !ok || err != nil {
		t.Fatalf("Failed to add policy in transaction 2: %v", err)
	}

	// Commit first transaction
	if err := tx1.Commit(); err != nil {
		t.Fatalf("Failed to commit transaction 1: %v", err)
	}

	// Commit second transaction
	if err := tx2.Commit(); err != nil {
		t.Fatalf("Failed to commit transaction 2: %v", err)
	}

	// Verify transactions were committed
	if !tx1.IsCommitted() {
		t.Error("Transaction 1 should be committed")
	}
	if !tx2.IsCommitted() {
		t.Error("Transaction 2 should be committed")
	}
}

// Two transactions that touch different rules should both survive the commit of
// the other one. The second committer used to replace the model with its own
// start snapshot, which silently dropped whatever the first one had committed.
func TestConcurrentTransactionsKeepEachOthersCommits(t *testing.T) {
	adapter := NewMockTransactionalAdapter()
	e, err := NewTransactionalEnforcer("examples/rbac_model.conf", adapter)
	if err != nil {
		t.Fatalf("Failed to create transactional enforcer: %v", err)
	}
	adapter.Enforcer = e.Enforcer

	if _, err = e.AddPolicy("alice", "data2", "write"); err != nil {
		t.Fatalf("Failed to seed policy: %v", err)
	}

	ctx := context.Background()

	tx1, err := e.BeginTransaction(ctx)
	if err != nil {
		t.Fatalf("Failed to begin transaction 1: %v", err)
	}
	tx2, err := e.BeginTransaction(ctx)
	if err != nil {
		t.Fatalf("Failed to begin transaction 2: %v", err)
	}

	// tx1 revokes a permission, tx2 grants an unrelated one.
	if ok, err := tx1.RemovePolicy("alice", "data2", "write"); !ok || err != nil {
		t.Fatalf("Failed to remove policy in transaction 1: %v", err)
	}
	if ok, err := tx2.AddPolicy("bob", "data3", "read"); !ok || err != nil {
		t.Fatalf("Failed to add policy in transaction 2: %v", err)
	}

	if err = tx1.Commit(); err != nil {
		t.Fatalf("Failed to commit transaction 1: %v", err)
	}
	if err = tx2.Commit(); err != nil {
		t.Fatalf("Failed to commit transaction 2: %v", err)
	}

	allowed, err := e.Enforce("alice", "data2", "write")
	if err != nil {
		t.Fatalf("Enforce failed: %v", err)
	}
	if allowed {
		t.Error("alice should no longer have data2 write after transaction 1 revoked it")
	}

	allowed, err = e.Enforce("bob", "data3", "read")
	if err != nil {
		t.Fatalf("Enforce failed: %v", err)
	}
	if !allowed {
		t.Error("bob should have data3 read after transaction 2 granted it")
	}
}

// Test transaction conflicts.
func TestTransactionConflicts(t *testing.T) {
	adapter := NewMockTransactionalAdapter()
	e, err := NewTransactionalEnforcer("examples/rbac_model.conf", adapter)
	if err != nil {
		t.Fatalf("Failed to create transactional enforcer: %v", err)
	}
	adapter.Enforcer = e.Enforcer

	ctx := context.Background()

	// Test Case 1: Two transactions commit
	t.Run("TwoTransactionsCommit", func(t *testing.T) {
		tx1, _ := e.BeginTransaction(ctx)
		tx2, _ := e.BeginTransaction(ctx)

		// Commit both transactions
		if err := tx1.Commit(); err != nil {
			t.Fatalf("Failed to commit tx1: %v", err)
		}
		if err := tx2.Commit(); err != nil {
			t.Fatalf("Failed to commit tx2: %v", err)
		}

		// Verify both transactions were committed
		if !tx1.IsCommitted() {
			t.Error("Transaction 1 should be committed")
		}
		if !tx2.IsCommitted() {
			t.Error("Transaction 2 should be committed")
		}
	})

	// Test Case 2: Transaction rollback
	t.Run("TransactionRollback", func(t *testing.T) {
		tx, _ := e.BeginTransaction(ctx)

		// Rollback transaction
		if err := tx.Rollback(); err != nil {
			t.Fatalf("Failed to rollback transaction: %v", err)
		}

		// Verify transaction was rolled back
		if !tx.IsRolledBack() {
			t.Error("Transaction should be rolled back")
		}
	})

	// Test Case 3: Cannot commit after rollback
	t.Run("NoCommitAfterRollback", func(t *testing.T) {
		tx, _ := e.BeginTransaction(ctx)

		// Rollback transaction
		if err := tx.Rollback(); err != nil {
			t.Fatalf("Failed to rollback transaction: %v", err)
		}

		// Try to commit
		if err := tx.Commit(); err == nil {
			t.Error("Should not be able to commit after rollback")
		}
	})
}

// Test transaction buffer operations.
func TestTransactionBuffer(t *testing.T) {
	adapter := NewMockTransactionalAdapter()
	e, err := NewTransactionalEnforcer("examples/rbac_model.conf", adapter)
	if err != nil {
		t.Fatalf("Failed to create transactional enforcer: %v", err)
	}
	adapter.Enforcer = e.Enforcer

	ctx := context.Background()

	tx, err := e.BeginTransaction(ctx)
	if err != nil {
		t.Fatalf("Failed to begin transaction: %v", err)
	}

	// Initially no operations.
	if tx.HasOperations() {
		t.Fatal("Transaction should have no operations initially")
	}

	if tx.OperationCount() != 0 {
		t.Fatal("Operation count should be 0 initially")
	}

	// Add some operations.
	tx.AddPolicy("alice", "data1", "read")
	tx.AddPolicy("bob", "data2", "write")

	if !tx.HasOperations() {
		t.Fatal("Transaction should have operations")
	}

	if tx.OperationCount() != 2 {
		t.Fatalf("Expected 2 operations, got %d", tx.OperationCount())
	}

	// Get buffered model.
	bufferedModel, err := tx.GetBufferedModel()
	if err != nil {
		t.Fatalf("Failed to get buffered model: %v", err)
	}

	// Check that buffered model contains the policies.
	hasPolicy, _ := bufferedModel.HasPolicy("p", "p", []string{"alice", "data1", "read"})
	if !hasPolicy {
		t.Fatal("Buffered model should contain the added policy")
	}

	tx.Rollback()
}

// newTestTransactionalEnforcer creates a transactional enforcer backed by the mock adapter.
func newTestTransactionalEnforcer(t *testing.T) *TransactionalEnforcer {
	t.Helper()

	adapter := NewMockTransactionalAdapter()
	e, err := NewTransactionalEnforcer("examples/rbac_model.conf", adapter)
	if err != nil {
		t.Fatalf("Failed to create transactional enforcer: %v", err)
	}
	adapter.Enforcer = e.Enforcer

	return e
}

// hasPolicy reports whether the enforcer model holds the given policy rule.
func hasPolicy(t *testing.T, e *TransactionalEnforcer, params ...interface{}) bool {
	t.Helper()

	ok, err := e.HasPolicy(params...)
	if err != nil {
		t.Fatalf("Failed to check policy %v: %v", params, err)
	}
	return ok
}

// hasGroupingPolicy reports whether the enforcer model holds the given grouping policy rule.
func hasGroupingPolicy(t *testing.T, e *TransactionalEnforcer, params ...interface{}) bool {
	t.Helper()

	ok, err := e.HasGroupingPolicy(params...)
	if err != nil {
		t.Fatalf("Failed to check grouping policy %v: %v", params, err)
	}
	return ok
}

// Test batch grouping policy operations within a transaction.
func TestTransactionGroupingPolicies(t *testing.T) {
	e := newTestTransactionalEnforcer(t)
	ctx := context.Background()

	err := e.WithTransaction(ctx, func(tx *Transaction) error {
		if ok, err := tx.AddPolicy("admin", "data1", "read"); !ok || err != nil {
			t.Fatalf("Failed to add policy in transaction: %v", err)
		}
		if ok, err := tx.AddGroupingPolicies([][]string{{"alice", "admin"}, {"bob", "admin"}}); !ok || err != nil {
			t.Fatalf("Failed to add grouping policies in transaction: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Failed to commit transaction: %v", err)
	}

	if !hasGroupingPolicy(t, e, "alice", "admin") || !hasGroupingPolicy(t, e, "bob", "admin") {
		t.Fatal("Both grouping policies should have been added")
	}

	// Role links must have been rebuilt for the committed grouping policies.
	if allowed, enforceErr := e.Enforce("alice", "data1", "read"); enforceErr != nil || !allowed {
		t.Fatalf("alice should inherit the admin permission, got %v (err %v)", allowed, enforceErr)
	}

	// Removing them again must take effect too.
	err = e.WithTransaction(ctx, func(tx *Transaction) error {
		removed, removeErr := tx.RemoveGroupingPolicies([][]string{{"alice", "admin"}, {"bob", "admin"}})
		if !removed || removeErr != nil {
			t.Fatalf("Failed to remove grouping policies in transaction: %v", removeErr)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Failed to commit transaction: %v", err)
	}

	if hasGroupingPolicy(t, e, "alice", "admin") || hasGroupingPolicy(t, e, "bob", "admin") {
		t.Fatal("Both grouping policies should have been removed")
	}
	if ok, _ := e.Enforce("alice", "data1", "read"); ok {
		t.Fatal("alice should no longer inherit the admin permission")
	}
}

// Test updating a grouping policy within a transaction.
func TestTransactionUpdateGroupingPolicy(t *testing.T) {
	e := newTestTransactionalEnforcer(t)
	ctx := context.Background()

	if err := e.WithTransaction(ctx, func(tx *Transaction) error {
		_, err := tx.AddGroupingPolicy("alice", "admin")
		return err
	}); err != nil {
		t.Fatalf("Failed to commit transaction: %v", err)
	}

	// Updating a rule that does not exist changes nothing.
	if err := e.WithTransaction(ctx, func(tx *Transaction) error {
		ok, err := tx.UpdateGroupingPolicy([]string{"carol", "admin"}, []string{"carol", "user"})
		if err != nil {
			return err
		}
		if ok {
			t.Fatal("Updating a missing grouping policy should return false")
		}
		return nil
	}); err != nil {
		t.Fatalf("Failed to commit transaction: %v", err)
	}

	// Mismatched batch lengths are rejected.
	if err := e.WithTransaction(ctx, func(tx *Transaction) error {
		if _, err := tx.UpdateGroupingPolicies([][]string{{"alice", "admin"}}, [][]string{}); err == nil {
			t.Fatal("Mismatched old/new rule counts should return an error")
		}
		return nil
	}); err != nil {
		t.Fatalf("Failed to commit transaction: %v", err)
	}

	if err := e.WithTransaction(ctx, func(tx *Transaction) error {
		ok, err := tx.UpdateGroupingPolicy([]string{"alice", "admin"}, []string{"alice", "user"})
		if !ok || err != nil {
			t.Fatalf("Failed to update grouping policy in transaction: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatalf("Failed to commit transaction: %v", err)
	}

	if hasGroupingPolicy(t, e, "alice", "admin") {
		t.Fatal("The old grouping policy should have been removed")
	}
	if !hasGroupingPolicy(t, e, "alice", "user") {
		t.Fatal("The new grouping policy should have been added")
	}
}

// Test filtered removal within a transaction.
func TestTransactionRemoveFilteredPolicy(t *testing.T) {
	e := newTestTransactionalEnforcer(t)
	ctx := context.Background()

	if err := e.WithTransaction(ctx, func(tx *Transaction) error {
		if _, err := tx.AddPolicies([][]string{
			{"alice", "data1", "read"},
			{"alice", "data2", "write"},
			{"bob", "data2", "write"},
		}); err != nil {
			return err
		}
		_, err := tx.AddGroupingPolicies([][]string{{"alice", "admin"}, {"bob", "admin"}})
		return err
	}); err != nil {
		t.Fatalf("Failed to commit transaction: %v", err)
	}

	// A filter that matches nothing is a no-op.
	if err := e.WithTransaction(ctx, func(tx *Transaction) error {
		ok, err := tx.RemoveFilteredPolicy(0, "carol")
		if err != nil {
			return err
		}
		if ok || tx.HasOperations() {
			t.Fatal("A filter matching no rule should buffer nothing")
		}
		return nil
	}); err != nil {
		t.Fatalf("Failed to commit transaction: %v", err)
	}

	if err := e.WithTransaction(ctx, func(tx *Transaction) error {
		ok, err := tx.RemoveFilteredPolicy(0, "alice")
		if !ok || err != nil {
			t.Fatalf("Failed to remove filtered policy in transaction: %v", err)
		}

		// The removal is visible inside the transaction before committing.
		bufferedModel, err := tx.GetBufferedModel()
		if err != nil {
			return err
		}
		if has, _ := bufferedModel.HasPolicy("p", "p", []string{"alice", "data1", "read"}); has {
			t.Fatal("The buffered model should no longer contain alice's policy")
		}

		// But not outside of it.
		if !hasPolicy(t, e, "alice", "data1", "read") {
			t.Fatal("The enforcer model should still contain alice's policy before commit")
		}

		ok, err = tx.RemoveFilteredGroupingPolicy(1, "admin")
		if !ok || err != nil {
			t.Fatalf("Failed to remove filtered grouping policy in transaction: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatalf("Failed to commit transaction: %v", err)
	}

	if hasPolicy(t, e, "alice", "data1", "read") || hasPolicy(t, e, "alice", "data2", "write") {
		t.Fatal("All of alice's policies should have been removed")
	}
	if !hasPolicy(t, e, "bob", "data2", "write") {
		t.Fatal("bob's policy should have been kept")
	}
	if hasGroupingPolicy(t, e, "alice", "admin") || hasGroupingPolicy(t, e, "bob", "admin") {
		t.Fatal("All grouping policies for admin should have been removed")
	}
}

// Test that a rolled back filtered removal leaves the model untouched.
func TestTransactionRemoveFilteredPolicyRollback(t *testing.T) {
	e := newTestTransactionalEnforcer(t)
	ctx := context.Background()

	if err := e.WithTransaction(ctx, func(tx *Transaction) error {
		_, err := tx.AddPolicy("alice", "data1", "read")
		return err
	}); err != nil {
		t.Fatalf("Failed to commit transaction: %v", err)
	}

	wantErr := errors.New("business operation failed")
	err := e.WithTransaction(ctx, func(tx *Transaction) error {
		if _, err := tx.RemoveFilteredPolicy(0, "alice"); err != nil {
			return err
		}
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("Expected the business error to be returned, got %v", err)
	}

	if !hasPolicy(t, e, "alice", "data1", "read") {
		t.Fatal("The policy should still exist after a rollback")
	}
}

func TestTransactionCommitNotifiesWatcher(t *testing.T) {
	adapter := NewMockTransactionalAdapter()
	e, err := NewTransactionalEnforcer("examples/rbac_model.conf", adapter)
	if err != nil {
		t.Fatalf("Failed to create transactional enforcer: %v", err)
	}
	adapter.Enforcer = e.Enforcer

	updates := 0
	watcher := &SampleWatcher{}
	if err = e.SetWatcher(watcher); err != nil {
		t.Fatalf("Failed to set watcher: %v", err)
	}
	watcher.callback = func(string) { updates++ }

	tx, err := e.BeginTransaction(context.Background())
	if err != nil {
		t.Fatalf("Failed to begin transaction: %v", err)
	}
	if _, err = tx.AddPolicy("alice", "data1", "read"); err != nil {
		t.Fatalf("Failed to add policy in transaction: %v", err)
	}
	if updates != 0 {
		t.Fatalf("Watcher should not be notified before commit, got %d updates", updates)
	}
	if err = tx.Commit(); err != nil {
		t.Fatalf("Failed to commit transaction: %v", err)
	}
	if updates != 1 {
		t.Fatalf("Watcher should be notified once after commit, got %d updates", updates)
	}

	tx, err = e.BeginTransaction(context.Background())
	if err != nil {
		t.Fatalf("Failed to begin transaction: %v", err)
	}
	if _, err := tx.RemovePolicy("alice", "data1", "read"); err != nil {
		t.Fatalf("Failed to remove policy in transaction: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("Failed to roll back transaction: %v", err)
	}
	if updates != 1 {
		t.Fatalf("Watcher should not be notified after rollback, got %d updates", updates)
	}
}
