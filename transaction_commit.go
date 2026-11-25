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
	"sync/atomic"

	"github.com/casbin/casbin/v3/persist"
)

// Commit commits the transaction using a two-phase commit protocol.
// Phase 1: Apply all operations to the database
// Phase 2: Apply changes to the in-memory model and rebuild role links.
func (tx *Transaction) Commit() error {
	// Try to acquire the commit lock with timeout.
	if !tryLockWithTimeout(&tx.enforcer.commitLock, tx.startTime, defaultLockTimeout) {
		_ = tx.txContext.Rollback()
		tx.enforcer.activeTransactions.Delete(tx.id)
		return errors.New("transaction timeout: failed to acquire lock")
	}
	defer tx.enforcer.commitLock.Unlock()

	tx.mutex.Lock()
	defer tx.mutex.Unlock()

	if tx.committed {
		return errors.New("transaction already committed")
	}
	if tx.rolledBack {
		return errors.New("transaction already rolled back")
	}

	// First check if model version has changed.
	currentVersion := atomic.LoadInt64(&tx.enforcer.modelVersion)
	if currentVersion != tx.baseVersion {
		// Model has been modified, need to check for conflicts.
		detector := NewConflictDetector(
			tx.buffer.GetModelSnapshot(),
			tx.enforcer.model,
			tx.buffer.GetOperations(),
		)
		if err := detector.DetectConflicts(); err != nil {
			_ = tx.txContext.Rollback()
			tx.enforcer.activeTransactions.Delete(tx.id)
			return err
		}
	}

	// If no operations, just commit the database transaction and clear state.
	if !tx.buffer.HasOperations() {
		if err := tx.txContext.Commit(); err != nil {
			return err
		}
		tx.committed = true
		tx.enforcer.activeTransactions.Delete(tx.id)
		return nil
	}

	// Phase 1: Apply all buffered operations to the database
	if err := tx.applyOperationsToDatabase(); err != nil {
		// Rollback database transaction on failure.
		_ = tx.txContext.Rollback()
		tx.enforcer.activeTransactions.Delete(tx.id)
		return err
	}

	// Commit database transaction.
	if err := tx.txContext.Commit(); err != nil {
		tx.enforcer.activeTransactions.Delete(tx.id)
		return err
	}

	// Phase 2: Apply changes to the in-memory model
	if err := tx.applyOperationsToModel(); err != nil {
		// At this point, database is committed but model update failed.
		// This is a critical error that should not happen in normal circumstances.
		tx.enforcer.activeTransactions.Delete(tx.id)
		return errors.New("critical error: database committed but model update failed: " + err.Error())
	}

	// Increment model version number.
	atomic.AddInt64(&tx.enforcer.modelVersion, 1)

	tx.committed = true
	tx.enforcer.activeTransactions.Delete(tx.id)

	return tx.notifyWatcher()
}

// notifyWatcher tells other instances about the committed operations,
// mirroring what the non-transactional management API does.
func (tx *Transaction) notifyWatcher() error {
	e := tx.enforcer
	if !e.shouldNotify() {
		return nil
	}

	watcherEx, isWatcherEx := e.watcher.(persist.WatcherEx)
	updatableWatcher, isUpdatableWatcher := e.watcher.(persist.UpdatableWatcher)
	if !isWatcherEx && !isUpdatableWatcher {
		return e.watcher.Update()
	}

	for _, op := range tx.buffer.GetOperations() {
		var err error
		switch {
		case op.Type == persist.OperationAdd && isWatcherEx:
			err = watcherEx.UpdateForAddPolicies(op.Section, op.PolicyType, op.Rules...)
		case op.Type == persist.OperationRemove && isWatcherEx:
			err = watcherEx.UpdateForRemovePolicies(op.Section, op.PolicyType, op.Rules...)
		case op.Type == persist.OperationUpdate && isUpdatableWatcher:
			err = updatableWatcher.UpdateForUpdatePolicies(op.Section, op.PolicyType, op.OldRules, op.Rules)
		default:
			err = e.watcher.Update()
		}
		if err != nil {
			return err
		}
	}

	return nil
}

// Rollback rolls back the transaction.
// This will rollback the database transaction and clear the transaction state.
func (tx *Transaction) Rollback() error {
	// Try to acquire the commit lock with timeout.
	if !tryLockWithTimeout(&tx.enforcer.commitLock, tx.startTime, defaultLockTimeout) {
		tx.enforcer.activeTransactions.Delete(tx.id)
		return errors.New("transaction timeout: failed to acquire lock for rollback")
	}
	defer tx.enforcer.commitLock.Unlock()

	tx.mutex.Lock()
	defer tx.mutex.Unlock()

	if tx.committed {
		return errors.New("transaction already committed")
	}
	if tx.rolledBack {
		return errors.New("transaction already rolled back")
	}

	// Rollback database transaction.
	if err := tx.txContext.Rollback(); err != nil {
		return err
	}

	tx.rolledBack = true
	tx.enforcer.activeTransactions.Delete(tx.id)

	return nil
}

// applyOperationsToDatabase applies all buffered operations to the database.
func (tx *Transaction) applyOperationsToDatabase() error {
	operations := tx.buffer.GetOperations()
	txAdapter := tx.txContext.GetAdapter()

	for _, op := range operations {
		switch op.Type {
		case persist.OperationAdd:
			if err := tx.applyAddOperationToDatabase(txAdapter, op); err != nil {
				return err
			}
		case persist.OperationRemove:
			if err := tx.applyRemoveOperationToDatabase(txAdapter, op); err != nil {
				return err
			}
		case persist.OperationUpdate:
			if err := tx.applyUpdateOperationToDatabase(txAdapter, op); err != nil {
				return err
			}
		}
	}

	return nil
}

// applyAddOperationToDatabase applies an add operation to the database.
func (tx *Transaction) applyAddOperationToDatabase(adapter persist.Adapter, op persist.PolicyOperation) error {
	if batchAdapter, ok := adapter.(persist.BatchAdapter); ok {
		// Use batch operation if available.
		return batchAdapter.AddPolicies(op.Section, op.PolicyType, op.Rules)
	} else {
		// Fall back to individual operations.
		for _, rule := range op.Rules {
			if err := adapter.AddPolicy(op.Section, op.PolicyType, rule); err != nil {
				return err
			}
		}
	}
	return nil
}

// applyRemoveOperationToDatabase applies a remove operation to the database.
func (tx *Transaction) applyRemoveOperationToDatabase(adapter persist.Adapter, op persist.PolicyOperation) error {
	if batchAdapter, ok := adapter.(persist.BatchAdapter); ok {
		// Use batch operation if available.
		return batchAdapter.RemovePolicies(op.Section, op.PolicyType, op.Rules)
	} else {
		// Fall back to individual operations.
		for _, rule := range op.Rules {
			if err := adapter.RemovePolicy(op.Section, op.PolicyType, rule); err != nil {
				return err
			}
		}
	}
	return nil
}

// applyUpdateOperationToDatabase applies an update operation to the database.
func (tx *Transaction) applyUpdateOperationToDatabase(adapter persist.Adapter, op persist.PolicyOperation) error {
	if updateAdapter, ok := adapter.(persist.UpdatableAdapter); ok {
		// Use update operation if available.
		return updateAdapter.UpdatePolicies(op.Section, op.PolicyType, op.OldRules, op.Rules)
	}

	// Fall back to remove + add.
	for i, oldRule := range op.OldRules {
		if err := adapter.RemovePolicy(op.Section, op.PolicyType, oldRule); err != nil {
			return err
		}
		if err := adapter.AddPolicy(op.Section, op.PolicyType, op.Rules[i]); err != nil {
			return err
		}
	}
	return nil
}

// applyOperationsToModel applies all buffered operations to the in-memory model.
func (tx *Transaction) applyOperationsToModel() error {
	// Build on the current model so that changes committed after this
	// transaction began are kept.
	newModel, err := tx.buffer.ApplyOperationsToModel(tx.enforcer.model)
	if err != nil {
		return err
	}

	// Replace the enforcer's model.
	tx.enforcer.model = newModel
	tx.enforcer.invalidateMatcherMap()

	// Rebuild role links if necessary.
	if tx.enforcer.autoBuildRoleLinks {
		// Check if any operations involved grouping policies.
		operations := tx.buffer.GetOperations()
		needRoleRebuild := false

		for _, op := range operations {
			if op.Section == "g" {
				needRoleRebuild = true
				break
			}
		}

		if needRoleRebuild {
			if err := tx.enforcer.BuildRoleLinks(); err != nil {
				return err
			}
		}
	}

	return nil
}

// IsCommitted returns true if the transaction has been committed.
func (tx *Transaction) IsCommitted() bool {
	tx.mutex.RLock()
	defer tx.mutex.RUnlock()
	return tx.committed
}

// IsRolledBack returns true if the transaction has been rolled back.
func (tx *Transaction) IsRolledBack() bool {
	tx.mutex.RLock()
	defer tx.mutex.RUnlock()
	return tx.rolledBack
}

// IsActive returns true if the transaction is still active (not committed or rolled back).
func (tx *Transaction) IsActive() bool {
	tx.mutex.RLock()
	defer tx.mutex.RUnlock()
	return !tx.committed && !tx.rolledBack
}
