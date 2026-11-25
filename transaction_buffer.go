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
	"sync"

	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist"
)

// TransactionBuffer holds all policy changes made within a transaction.
// It maintains a list of operations and a snapshot of the model state
// at the beginning of the transaction.
type TransactionBuffer struct {
	operations    []persist.PolicyOperation // Buffered operations
	modelSnapshot model.Model               // Model state at transaction start
	mutex         sync.RWMutex              // Protects concurrent access
}

// NewTransactionBuffer creates a new transaction buffer with a model snapshot.
// The snapshot represents the state of the model at the beginning of the transaction.
func NewTransactionBuffer(baseModel model.Model) *TransactionBuffer {
	return &TransactionBuffer{
		operations:    make([]persist.PolicyOperation, 0),
		modelSnapshot: baseModel.Copy(),
	}
}

// AddOperation adds a policy operation to the buffer.
// This operation will be applied when the transaction is committed.
func (tb *TransactionBuffer) AddOperation(op persist.PolicyOperation) {
	tb.mutex.Lock()
	defer tb.mutex.Unlock()
	tb.operations = append(tb.operations, op)
}

// GetOperations returns all buffered operations.
// Returns a copy to prevent external modifications.
func (tb *TransactionBuffer) GetOperations() []persist.PolicyOperation {
	tb.mutex.RLock()
	defer tb.mutex.RUnlock()

	// Return a copy to prevent external modifications.
	result := make([]persist.PolicyOperation, len(tb.operations))
	copy(result, tb.operations)
	return result
}

// Clear removes all buffered operations.
// This is typically called after a successful commit or rollback.
func (tb *TransactionBuffer) Clear() {
	tb.mutex.Lock()
	defer tb.mutex.Unlock()
	tb.operations = tb.operations[:0]
}

// GetModelSnapshot returns the model snapshot taken at transaction start.
// This represents the original state before any transaction operations.
func (tb *TransactionBuffer) GetModelSnapshot() model.Model {
	tb.mutex.RLock()
	defer tb.mutex.RUnlock()
	return tb.modelSnapshot.Copy()
}

// ApplyOperationsToModel applies all buffered operations to a model and returns the result.
// This simulates what the model would look like after all operations are applied.
// It's used for validation and preview purposes within the transaction.
func (tb *TransactionBuffer) ApplyOperationsToModel(baseModel model.Model) (model.Model, error) {
	tb.mutex.RLock()
	defer tb.mutex.RUnlock()

	resultModel := baseModel.Copy()

	for _, op := range tb.operations {
		switch op.Type {
		case persist.OperationAdd:
			for _, rule := range op.Rules {
				if err := addPolicyIfAbsent(resultModel, op.Section, op.PolicyType, rule); err != nil {
					return nil, err
				}
			}
		case persist.OperationRemove:
			for _, rule := range op.Rules {
				if _, err := resultModel.RemovePolicy(op.Section, op.PolicyType, rule); err != nil {
					return nil, err
				}
			}
		case persist.OperationUpdate:
			// For update operations, remove old rules and add new ones.
			for i, oldRule := range op.OldRules {
				if i < len(op.Rules) {
					if _, err := resultModel.RemovePolicy(op.Section, op.PolicyType, oldRule); err != nil {
						return nil, err
					}
					if err := addPolicyIfAbsent(resultModel, op.Section, op.PolicyType, op.Rules[i]); err != nil {
						return nil, err
					}
				}
			}
		}
	}

	return resultModel, nil
}

// addPolicyIfAbsent adds a rule unless the model already has it, since
// Model.AddPolicy does not check and a duplicate would survive a later removal.
func addPolicyIfAbsent(m model.Model, sec string, ptype string, rule []string) error {
	ok, err := m.HasPolicy(sec, ptype, rule)
	if err != nil || ok {
		return err
	}
	return m.AddPolicy(sec, ptype, rule)
}

// HasOperations returns true if there are any buffered operations.
func (tb *TransactionBuffer) HasOperations() bool {
	tb.mutex.RLock()
	defer tb.mutex.RUnlock()
	return len(tb.operations) > 0
}

// OperationCount returns the number of buffered operations.
func (tb *TransactionBuffer) OperationCount() int {
	tb.mutex.RLock()
	defer tb.mutex.RUnlock()
	return len(tb.operations)
}
