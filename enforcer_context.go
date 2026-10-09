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
	"fmt"

	Err "github.com/casbin/casbin/v3/errors"
	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist"
)

// ContextEnforcer wraps Enforcer and provides context-aware operations.
type ContextEnforcer struct {
	*Enforcer
	adapterCtx persist.ContextAdapter
}

// NewContextEnforcer creates a context-aware enforcer via file or DB.
func NewContextEnforcer(params ...interface{}) (IEnforcerContext, error) {
	e := &ContextEnforcer{}
	var err error
	e.Enforcer, err = NewEnforcer(params...)
	if err != nil {
		return nil, err
	}

	if e.adapter != nil {
		if contextAdapter, ok := e.adapter.(persist.ContextAdapter); ok {
			e.adapterCtx = contextAdapter
		} else {
			return nil, errors.New("adapter does not support context operations, ContextAdapter interface not implemented")
		}
	} else {
		return nil, errors.New("no adapter provided, ContextEnforcer requires a ContextAdapter")
	}

	return e, nil
}

// LoadPolicyCtx loads all policy rules from the storage with context.
func (e *ContextEnforcer) LoadPolicyCtx(ctx context.Context) error {
	newModel, err := e.loadPolicyFromAdapterCtx(ctx, e.model)
	if err != nil {
		return err
	}
	err = e.applyModifiedModel(newModel)
	if err != nil {
		return err
	}
	return nil
}

func (e *ContextEnforcer) loadPolicyFromAdapterCtx(ctx context.Context, baseModel model.Model) (model.Model, error) {
	newModel := baseModel.Copy()
	newModel.ClearPolicy()

	if err := e.adapterCtx.LoadPolicyCtx(ctx, newModel); err != nil && err.Error() != "invalid file path, file path cannot be empty" {
		return nil, err
	}

	if err := newModel.SortPoliciesBySubjectHierarchy(); err != nil {
		return nil, err
	}

	if err := newModel.SortPoliciesByPriority(); err != nil {
		return nil, err
	}

	return newModel, nil
}

// LoadFilteredPolicyCtx loads all policy rules from the storage with context and filter.
func (e *Enforcer) LoadFilteredPolicyCtx(ctx context.Context, filter interface{}) error {
	e.model.ClearPolicy()
	return e.loadFilteredPolicyCtx(ctx, filter)
}

// LoadIncrementalFilteredPolicyCtx append a filtered policy from file/database with context.
func (e *Enforcer) LoadIncrementalFilteredPolicyCtx(ctx context.Context, filter interface{}) error {
	return e.loadFilteredPolicyCtx(ctx, filter)
}

func (e *Enforcer) loadFilteredPolicyCtx(ctx context.Context, filter interface{}) error {
	e.invalidateMatcherMap()

	var filteredAdapter persist.ContextFilteredAdapter

	// Attempt to cast the Adapter as a FilteredAdapter
	switch adapter := e.adapter.(type) {
	case persist.ContextFilteredAdapter:
		filteredAdapter = adapter
	default:
		return errors.New("filtered policies are not supported by this adapter")
	}
	if err := filteredAdapter.LoadFilteredPolicyCtx(ctx, e.model, filter); err != nil && err.Error() != "invalid file path, file path cannot be empty" {
		return err
	}

	if err := e.model.SortPoliciesBySubjectHierarchy(); err != nil {
		return err
	}

	if err := e.model.SortPoliciesByPriority(); err != nil {
		return err
	}

	e.initRmMap()
	e.model.PrintPolicy()
	if e.autoBuildRoleLinks {
		err := e.BuildRoleLinks()
		if err != nil {
			return err
		}
	}
	return nil
}

// IsFilteredCtx returns true if the loaded policy has been filtered with context.
func (e *ContextEnforcer) IsFilteredCtx(ctx context.Context) bool {
	if adapter, ok := e.adapter.(persist.ContextFilteredAdapter); ok {
		return adapter.IsFilteredCtx(ctx)
	} else {
		return false
	}
}

func (e *ContextEnforcer) SavePolicyCtx(ctx context.Context) error {
	if e.IsFiltered() {
		return errors.New("cannot save a filtered policy")
	}
	if err := e.adapterCtx.SavePolicyCtx(ctx, e.model); err != nil {
		return err
	}
	if e.watcher != nil {
		var err error
		if watcher, ok := e.watcher.(persist.WatcherEx); ok {
			err = watcher.UpdateForSavePolicy(e.model)
		} else {
			err = e.watcher.Update()
		}
		return err
	}
	return nil
}

// AddPolicyCtx adds a policy rule to the storage with context.
func (e *ContextEnforcer) AddPolicyCtx(ctx context.Context, params ...interface{}) (bool, error) {
	return e.AddNamedPolicyCtx(ctx, "p", params...)
}

// AddPoliciesCtx adds policy rules to the storage with context.
func (e *ContextEnforcer) AddPoliciesCtx(ctx context.Context, rules [][]string) (bool, error) {
	return e.AddNamedPoliciesCtx(ctx, "p", rules)
}

// AddNamedPolicyCtx adds a named policy rule to the storage with context.
func (e *ContextEnforcer) AddNamedPolicyCtx(ctx context.Context, ptype string, params ...interface{}) (bool, error) {
	if strSlice, ok := params[0].([]string); len(params) == 1 && ok {
		strSlice = append(make([]string, 0, len(strSlice)), strSlice...)
		return e.addPolicyCtx(ctx, "p", ptype, strSlice)
	}
	policy := make([]string, 0)
	for _, param := range params {
		policy = append(policy, param.(string))
	}

	return e.addPolicyCtx(ctx, "p", ptype, policy)
}

// AddNamedPoliciesCtx adds named policy rules to the storage with context.
func (e *ContextEnforcer) AddNamedPoliciesCtx(ctx context.Context, ptype string, rules [][]string) (bool, error) {
	return e.addPoliciesCtx(ctx, "p", ptype, rules, false)
}

func (e *ContextEnforcer) AddPoliciesExCtx(ctx context.Context, rules [][]string) (bool, error) {
	return e.AddNamedPoliciesExCtx(ctx, "p", rules)
}

func (e *ContextEnforcer) AddNamedPoliciesExCtx(ctx context.Context, ptype string, rules [][]string) (bool, error) {
	return e.addPoliciesCtx(ctx, "p", ptype, rules, true)
}

// RemovePolicyCtx removes a policy rule from the storage with context.
func (e *ContextEnforcer) RemovePolicyCtx(ctx context.Context, params ...interface{}) (bool, error) {
	return e.RemoveNamedPolicyCtx(ctx, "p", params...)
}

// RemoveNamedPolicyCtx removes a named policy rule from the storage with context.
func (e *ContextEnforcer) RemoveNamedPolicyCtx(ctx context.Context, ptype string, params ...interface{}) (bool, error) {
	if strSlice, ok := params[0].([]string); len(params) == 1 && ok {
		return e.removePolicyCtx(ctx, "p", ptype, strSlice)
	}
	policy := make([]string, 0)
	for _, param := range params {
		policy = append(policy, param.(string))
	}

	return e.removePolicyCtx(ctx, "p", ptype, policy)
}

// RemovePoliciesCtx removes policy rules from the storage with context.
func (e *ContextEnforcer) RemovePoliciesCtx(ctx context.Context, rules [][]string) (bool, error) {
	return e.RemoveNamedPoliciesCtx(ctx, "p", rules)
}

// RemoveNamedPoliciesCtx removes named policy rules from the storage with context.
func (e *ContextEnforcer) RemoveNamedPoliciesCtx(ctx context.Context, ptype string, rules [][]string) (bool, error) {
	return e.removePoliciesCtx(ctx, "p", ptype, rules)
}

// RemoveFilteredPolicyCtx removes policy rules that match the filter from the storage with context.
func (e *ContextEnforcer) RemoveFilteredPolicyCtx(ctx context.Context, fieldIndex int, fieldValues ...string) (bool, error) {
	return e.RemoveFilteredNamedPolicyCtx(ctx, "p", fieldIndex, fieldValues...)
}

// RemoveFilteredNamedPolicyCtx removes named policy rules that match the filter from the storage with context.
func (e *ContextEnforcer) RemoveFilteredNamedPolicyCtx(ctx context.Context, ptype string, fieldIndex int, fieldValues ...string) (bool, error) {
	return e.removeFilteredPolicyCtx(ctx, "p", ptype, fieldIndex, fieldValues)
}

// UpdatePolicyCtx updates a policy rule in the storage with context.
func (e *ContextEnforcer) UpdatePolicyCtx(ctx context.Context, oldPolicy []string, newPolicy []string) (bool, error) {
	return e.UpdateNamedPolicyCtx(ctx, "p", oldPolicy, newPolicy)
}

// UpdateNamedPolicyCtx updates a named policy rule in the storage with context.
func (e *ContextEnforcer) UpdateNamedPolicyCtx(ctx context.Context, ptype string, p1 []string, p2 []string) (bool, error) {
	return e.updatePolicyCtx(ctx, "p", ptype, p1, p2)
}

// UpdatePoliciesCtx updates policy rules in the storage with context.
func (e *ContextEnforcer) UpdatePoliciesCtx(ctx context.Context, oldPolicies [][]string, newPolicies [][]string) (bool, error) {
	return e.UpdateNamedPoliciesCtx(ctx, "p", oldPolicies, newPolicies)
}

// UpdateNamedPoliciesCtx updates named policy rules in the storage with context.
func (e *ContextEnforcer) UpdateNamedPoliciesCtx(ctx context.Context, ptype string, p1 [][]string, p2 [][]string) (bool, error) {
	return e.updatePoliciesCtx(ctx, "p", ptype, p1, p2)
}

// UpdateFilteredPoliciesCtx updates policy rules that match the filter in the storage with context.
func (e *ContextEnforcer) UpdateFilteredPoliciesCtx(ctx context.Context, newPolicies [][]string, fieldIndex int, fieldValues ...string) (bool, error) {
	return e.UpdateFilteredNamedPoliciesCtx(ctx, "p", newPolicies, fieldIndex, fieldValues...)
}

// UpdateFilteredNamedPoliciesCtx updates named policy rules that match the filter in the storage with context.
func (e *ContextEnforcer) UpdateFilteredNamedPoliciesCtx(ctx context.Context, ptype string, newPolicies [][]string, fieldIndex int, fieldValues ...string) (bool, error) {
	return e.updateFilteredPoliciesCtx(ctx, "p", ptype, newPolicies, fieldIndex, fieldValues...)
}

// Grouping Policy Context Methods

// AddGroupingPolicyCtx adds a grouping policy rule to the storage with context.
func (e *ContextEnforcer) AddGroupingPolicyCtx(ctx context.Context, params ...interface{}) (bool, error) {
	return e.AddNamedGroupingPolicyCtx(ctx, "g", params...)
}

// AddGroupingPoliciesCtx adds grouping policy rules to the storage with context.
func (e *ContextEnforcer) AddGroupingPoliciesCtx(ctx context.Context, rules [][]string) (bool, error) {
	return e.AddNamedGroupingPoliciesCtx(ctx, "g", rules)
}

func (e *ContextEnforcer) AddGroupingPoliciesExCtx(ctx context.Context, rules [][]string) (bool, error) {
	return e.AddNamedGroupingPoliciesExCtx(ctx, "g", rules)
}

// AddNamedGroupingPolicyCtx adds a named grouping policy rule to the storage with context.
func (e *ContextEnforcer) AddNamedGroupingPolicyCtx(ctx context.Context, ptype string, params ...interface{}) (bool, error) {
	var ruleAdded bool
	var err error
	if strSlice, ok := params[0].([]string); len(params) == 1 && ok {
		ruleAdded, err = e.addPolicyCtx(ctx, "g", ptype, strSlice)
	} else {
		policy := make([]string, 0)
		for _, param := range params {
			policy = append(policy, param.(string))
		}
		ruleAdded, err = e.addPolicyCtx(ctx, "g", ptype, policy)
	}

	return ruleAdded, err
}

// AddNamedGroupingPoliciesCtx adds named grouping policy rules to the storage with context.
func (e *ContextEnforcer) AddNamedGroupingPoliciesCtx(ctx context.Context, ptype string, rules [][]string) (bool, error) {
	return e.addPoliciesCtx(ctx, "g", ptype, rules, false)
}

func (e *ContextEnforcer) AddNamedGroupingPoliciesExCtx(ctx context.Context, ptype string, rules [][]string) (bool, error) {
	return e.addPoliciesCtx(ctx, "g", ptype, rules, true)
}

// RemoveGroupingPolicyCtx removes a grouping policy rule from the storage with context.
func (e *ContextEnforcer) RemoveGroupingPolicyCtx(ctx context.Context, params ...interface{}) (bool, error) {
	return e.RemoveNamedGroupingPolicyCtx(ctx, "g", params...)
}

// RemoveNamedGroupingPolicyCtx removes a named grouping policy rule from the storage with context.
func (e *ContextEnforcer) RemoveNamedGroupingPolicyCtx(ctx context.Context, ptype string, params ...interface{}) (bool, error) {
	var ruleRemoved bool
	var err error
	if strSlice, ok := params[0].([]string); len(params) == 1 && ok {
		ruleRemoved, err = e.removePolicyCtx(ctx, "g", ptype, strSlice)
	} else {
		policy := make([]string, 0)
		for _, param := range params {
			policy = append(policy, param.(string))
		}

		ruleRemoved, err = e.removePolicyCtx(ctx, "g", ptype, policy)
	}

	return ruleRemoved, err
}

// RemoveGroupingPoliciesCtx removes grouping policy rules from the storage with context.
func (e *ContextEnforcer) RemoveGroupingPoliciesCtx(ctx context.Context, rules [][]string) (bool, error) {
	return e.RemoveNamedGroupingPoliciesCtx(ctx, "g", rules)
}

// RemoveNamedGroupingPoliciesCtx removes named grouping policy rules from the storage with context.
func (e *ContextEnforcer) RemoveNamedGroupingPoliciesCtx(ctx context.Context, ptype string, rules [][]string) (bool, error) {
	return e.removePoliciesCtx(ctx, "g", ptype, rules)
}

// RemoveFilteredGroupingPolicyCtx removes grouping policy rules that match the filter from the storage with context.
func (e *ContextEnforcer) RemoveFilteredGroupingPolicyCtx(ctx context.Context, fieldIndex int, fieldValues ...string) (bool, error) {
	return e.RemoveFilteredNamedGroupingPolicyCtx(ctx, "g", fieldIndex, fieldValues...)
}

// RemoveFilteredNamedGroupingPolicyCtx removes named grouping policy rules that match the filter from the storage with context.
func (e *ContextEnforcer) RemoveFilteredNamedGroupingPolicyCtx(ctx context.Context, ptype string, fieldIndex int, fieldValues ...string) (bool, error) {
	return e.removeFilteredPolicyCtx(ctx, "g", ptype, fieldIndex, fieldValues)
}

// UpdateGroupingPolicyCtx updates a grouping policy rule in the storage with context.
func (e *ContextEnforcer) UpdateGroupingPolicyCtx(ctx context.Context, oldRule []string, newRule []string) (bool, error) {
	return e.UpdateNamedGroupingPolicyCtx(ctx, "g", oldRule, newRule)
}

// UpdateNamedGroupingPolicyCtx updates a named grouping policy rule in the storage with context.
func (e *ContextEnforcer) UpdateNamedGroupingPolicyCtx(ctx context.Context, ptype string, oldRule []string, newRule []string) (bool, error) {
	return e.updatePolicyCtx(ctx, "g", ptype, oldRule, newRule)
}

// UpdateGroupingPoliciesCtx updates grouping policy rules in the storage with context.
func (e *ContextEnforcer) UpdateGroupingPoliciesCtx(ctx context.Context, oldRules [][]string, newRules [][]string) (bool, error) {
	return e.UpdateNamedGroupingPoliciesCtx(ctx, "g", oldRules, newRules)
}

// UpdateNamedGroupingPoliciesCtx updates named grouping policy rules in the storage with context.
func (e *ContextEnforcer) UpdateNamedGroupingPoliciesCtx(ctx context.Context, ptype string, oldRules [][]string, newRules [][]string) (bool, error) {
	return e.updatePoliciesCtx(ctx, "g", ptype, oldRules, newRules)
}

// Self Context Methods (bypass watcher notifications)

// SelfAddPolicyCtx adds a policy rule to the current policy with context.
func (e *ContextEnforcer) SelfAddPolicyCtx(ctx context.Context, sec string, ptype string, rule []string) (bool, error) {
	return e.addPolicyWithoutNotifyCtx(ctx, sec, ptype, rule)
}

// SelfAddPoliciesCtx adds policy rules to the current policy with context.
func (e *ContextEnforcer) SelfAddPoliciesCtx(ctx context.Context, sec string, ptype string, rules [][]string) (bool, error) {
	return e.addPoliciesWithoutNotifyCtx(ctx, sec, ptype, rules, false)
}

func (e *ContextEnforcer) SelfAddPoliciesExCtx(ctx context.Context, sec string, ptype string, rules [][]string) (bool, error) {
	return e.addPoliciesWithoutNotifyCtx(ctx, sec, ptype, rules, true)
}

// SelfRemovePolicyCtx removes a policy rule from the current policy with context.
func (e *ContextEnforcer) SelfRemovePolicyCtx(ctx context.Context, sec string, ptype string, rule []string) (bool, error) {
	return e.removePolicyWithoutNotifyCtx(ctx, sec, ptype, rule)
}

// SelfRemovePoliciesCtx removes policy rules from the current policy with context.
func (e *ContextEnforcer) SelfRemovePoliciesCtx(ctx context.Context, sec string, ptype string, rules [][]string) (bool, error) {
	return e.removePoliciesWithoutNotifyCtx(ctx, sec, ptype, rules)
}

// SelfRemoveFilteredPolicyCtx removes policy rules that match the filter from the current policy with context.
func (e *ContextEnforcer) SelfRemoveFilteredPolicyCtx(ctx context.Context, sec string, ptype string, fieldIndex int, fieldValues ...string) (bool, error) {
	return e.removeFilteredPolicyWithoutNotifyCtx(ctx, sec, ptype, fieldIndex, fieldValues)
}

// SelfUpdatePolicyCtx updates a policy rule in the current policy with context.
func (e *ContextEnforcer) SelfUpdatePolicyCtx(ctx context.Context, sec string, ptype string, oldRule, newRule []string) (bool, error) {
	return e.updatePolicyWithoutNotifyCtx(ctx, sec, ptype, oldRule, newRule)
}

// SelfUpdatePoliciesCtx updates policy rules in the current policy with context.
func (e *ContextEnforcer) SelfUpdatePoliciesCtx(ctx context.Context, sec string, ptype string, oldRules, newRules [][]string) (bool, error) {
	return e.updatePoliciesWithoutNotifyCtx(ctx, sec, ptype, oldRules, newRules)
}

// Internal API methods with context support

// addPolicyWithoutNotifyCtx adds a rule to the current policy with context.
func (e *ContextEnforcer) addPolicyWithoutNotifyCtx(ctx context.Context, sec string, ptype string, rule []string) (bool, error) {
	defer e.bumpPolicyVersion()

	if e.dispatcher != nil && e.autoNotifyDispatcher {
		return true, e.dispatcher.AddPolicies(sec, ptype, [][]string{rule})
	}

	hasPolicy, err := e.model.HasPolicy(sec, ptype, rule)
	if hasPolicy || err != nil {
		return false, err
	}

	if e.shouldPersist() {
		if err = e.adapterCtx.AddPolicyCtx(ctx, sec, ptype, rule); err != nil {
			if err.Error() != notImplemented {
				return false, err
			}
		}
	}

	err = e.model.AddPolicy(sec, ptype, rule)
	if err != nil {
		return false, err
	}

	if sec == "g" {
		err := e.BuildIncrementalRoleLinks(model.PolicyAdd, ptype, [][]string{rule})
		if err != nil {
			return true, err
		}
	}

	return true, nil
}

// addPoliciesWithoutNotifyCtx adds rules to the current policy with context.
func (e *ContextEnforcer) addPoliciesWithoutNotifyCtx(ctx context.Context, sec string, ptype string, rules [][]string, autoRemoveRepeat bool) (bool, error) {
	defer e.bumpPolicyVersion()

	if e.dispatcher != nil && e.autoNotifyDispatcher {
		return true, e.dispatcher.AddPolicies(sec, ptype, rules)
	}

	if !autoRemoveRepeat {
		hasPolicies, err := e.model.HasPolicies(sec, ptype, rules)
		if hasPolicies || err != nil {
			return false, err
		}
	}

	if e.shouldPersist() {
		if err := e.adapterCtx.(persist.ContextBatchAdapter).AddPoliciesCtx(ctx, sec, ptype, rules); err != nil {
			if err.Error() != notImplemented {
				return false, err
			}
		}
	}

	err := e.model.AddPolicies(sec, ptype, rules)
	if err != nil {
		return false, err
	}

	if sec == "g" {
		err := e.BuildIncrementalRoleLinks(model.PolicyAdd, ptype, rules)
		if err != nil {
			return true, err
		}

		err = e.BuildIncrementalConditionalRoleLinks(model.PolicyAdd, ptype, rules)
		if err != nil {
			return true, err
		}
	}

	return true, nil
}

// removePolicyWithoutNotifyCtx removes a rule from the current policy with context.
func (e *ContextEnforcer) removePolicyWithoutNotifyCtx(ctx context.Context, sec string, ptype string, rule []string) (bool, error) {
	defer e.bumpPolicyVersion()

	if e.dispatcher != nil && e.autoNotifyDispatcher {
		return true, e.dispatcher.RemovePolicies(sec, ptype, [][]string{rule})
	}

	if e.shouldPersist() {
		if err := e.adapterCtx.RemovePolicyCtx(ctx, sec, ptype, rule); err != nil {
			if err.Error() != notImplemented {
				return false, err
			}
		}
	}

	ruleRemoved, err := e.model.RemovePolicy(sec, ptype, rule)
	if !ruleRemoved || err != nil {
		return ruleRemoved, err
	}

	if sec == "g" {
		err := e.BuildIncrementalRoleLinks(model.PolicyRemove, ptype, [][]string{rule})
		if err != nil {
			return ruleRemoved, err
		}
	}

	return ruleRemoved, nil
}

// removePoliciesWithoutNotifyCtx removes rules from the current policy with context.
func (e *ContextEnforcer) removePoliciesWithoutNotifyCtx(ctx context.Context, sec string, ptype string, rules [][]string) (bool, error) {
	defer e.bumpPolicyVersion()

	if hasPolicies, err := e.model.HasPolicies(sec, ptype, rules); !hasPolicies || err != nil {
		return hasPolicies, err
	}

	if e.dispatcher != nil && e.autoNotifyDispatcher {
		return true, e.dispatcher.RemovePolicies(sec, ptype, rules)
	}

	if e.shouldPersist() {
		if err := e.adapterCtx.(persist.ContextBatchAdapter).RemovePoliciesCtx(ctx, sec, ptype, rules); err != nil {
			if err.Error() != notImplemented {
				return false, err
			}
		}
	}

	rulesRemoved, err := e.model.RemovePolicies(sec, ptype, rules)
	if !rulesRemoved || err != nil {
		return rulesRemoved, err
	}

	if sec == "g" {
		err := e.BuildIncrementalRoleLinks(model.PolicyRemove, ptype, rules)
		if err != nil {
			return rulesRemoved, err
		}
	}
	return rulesRemoved, nil
}

// removeFilteredPolicyWithoutNotifyCtx removes policy rules that match the filter from the current policy with context.
func (e *ContextEnforcer) removeFilteredPolicyWithoutNotifyCtx(ctx context.Context, sec string, ptype string, fieldIndex int, fieldValues []string) (bool, error) {
	defer e.bumpPolicyVersion()

	if len(fieldValues) == 0 {
		return false, Err.ErrInvalidFieldValuesParameter
	}

	if e.dispatcher != nil && e.autoNotifyDispatcher {
		return true, e.dispatcher.RemoveFilteredPolicy(sec, ptype, fieldIndex, fieldValues...)
	}

	if e.shouldPersist() {
		if err := e.adapterCtx.RemoveFilteredPolicyCtx(ctx, sec, ptype, fieldIndex, fieldValues...); err != nil {
			if err.Error() != notImplemented {
				return false, err
			}
		}
	}

	ruleRemoved, effects, err := e.model.RemoveFilteredPolicy(sec, ptype, fieldIndex, fieldValues...)
	if !ruleRemoved || err != nil {
		return ruleRemoved, err
	}

	if sec == "g" {
		err := e.BuildIncrementalRoleLinks(model.PolicyRemove, ptype, effects)
		if err != nil {
			return ruleRemoved, err
		}
	}

	return ruleRemoved, nil
}

// updatePolicyWithoutNotifyCtx updates a policy rule in the current policy with context.
func (e *ContextEnforcer) updatePolicyWithoutNotifyCtx(ctx context.Context, sec string, ptype string, oldRule, newRule []string) (bool, error) {
	defer e.bumpPolicyVersion()

	if e.dispatcher != nil && e.autoNotifyDispatcher {
		return true, e.dispatcher.UpdatePolicy(sec, ptype, oldRule, newRule)
	}

	if e.shouldPersist() {
		if err := e.adapterCtx.(persist.ContextUpdatableAdapter).UpdatePolicyCtx(ctx, sec, ptype, oldRule, newRule); err != nil {
			if err.Error() != notImplemented {
				return false, err
			}
		}
	}
	ruleUpdated, err := e.model.UpdatePolicy(sec, ptype, oldRule, newRule)
	if !ruleUpdated || err != nil {
		return ruleUpdated, err
	}

	if sec == "g" {
		err := e.BuildIncrementalRoleLinks(model.PolicyRemove, ptype, [][]string{oldRule}) // remove the old rule
		if err != nil {
			return ruleUpdated, err
		}
		err = e.BuildIncrementalRoleLinks(model.PolicyAdd, ptype, [][]string{newRule}) // add the new rule
		if err != nil {
			return ruleUpdated, err
		}
	}

	return ruleUpdated, nil
}

func (e *ContextEnforcer) updatePoliciesWithoutNotifyCtx(ctx context.Context, sec string, ptype string, oldRules [][]string, newRules [][]string) (bool, error) {
	defer e.bumpPolicyVersion()

	if len(newRules) != len(oldRules) {
		return false, fmt.Errorf("the length of oldRules should be equal to the length of newRules, but got the length of oldRules is %d, the length of newRules is %d", len(oldRules), len(newRules))
	}

	if e.dispatcher != nil && e.autoNotifyDispatcher {
		return true, e.dispatcher.UpdatePolicies(sec, ptype, oldRules, newRules)
	}

	if e.shouldPersist() {
		if err := e.adapterCtx.(persist.ContextUpdatableAdapter).UpdatePoliciesCtx(ctx, sec, ptype, oldRules, newRules); err != nil {
			if err.Error() != notImplemented {
				return false, err
			}
		}
	}

	ruleUpdated, err := e.model.UpdatePolicies(sec, ptype, oldRules, newRules)
	if !ruleUpdated || err != nil {
		return ruleUpdated, err
	}

	if sec == "g" {
		err := e.BuildIncrementalRoleLinks(model.PolicyRemove, ptype, oldRules) // remove the old rules
		if err != nil {
			return ruleUpdated, err
		}
		err = e.BuildIncrementalRoleLinks(model.PolicyAdd, ptype, newRules) // add the new rules
		if err != nil {
			return ruleUpdated, err
		}
	}

	return ruleUpdated, nil
}

func (e *ContextEnforcer) addPolicyCtx(ctx context.Context, sec string, ptype string, rule []string) (bool, error) {
	ok, err := e.addPolicyWithoutNotifyCtx(ctx, sec, ptype, rule)
	if !ok || err != nil {
		return ok, err
	}

	if e.shouldNotify() {
		var err error
		if watcher, ok := e.watcher.(persist.WatcherEx); ok {
			err = watcher.UpdateForAddPolicy(sec, ptype, rule...)
		} else {
			err = e.watcher.Update()
		}
		return true, err
	}

	return true, nil
}

func (e *ContextEnforcer) addPoliciesCtx(ctx context.Context, sec string, ptype string, rules [][]string, autoRemoveRepeat bool) (bool, error) {
	ok, err := e.addPoliciesWithoutNotifyCtx(ctx, sec, ptype, rules, autoRemoveRepeat)
	if !ok || err != nil {
		return ok, err
	}

	if e.shouldNotify() {
		var err error
		if watcher, ok := e.watcher.(persist.WatcherEx); ok {
			err = watcher.UpdateForAddPolicies(sec, ptype, rules...)
		} else {
			err = e.watcher.Update()
		}
		return true, err
	}

	return true, nil
}

func (e *ContextEnforcer) updatePolicyCtx(ctx context.Context, sec string, ptype string, oldRule []string, newRule []string) (bool, error) {
	ok, err := e.updatePolicyWithoutNotifyCtx(ctx, sec, ptype, oldRule, newRule)
	if !ok || err != nil {
		return ok, err
	}

	if e.shouldNotify() {
		var err error
		if watcher, ok := e.watcher.(persist.UpdatableWatcher); ok {
			err = watcher.UpdateForUpdatePolicy(sec, ptype, oldRule, newRule)
		} else {
			err = e.watcher.Update()
		}
		return true, err
	}

	return true, nil
}

func (e *ContextEnforcer) updatePoliciesCtx(ctx context.Context, sec string, ptype string, oldRules [][]string, newRules [][]string) (bool, error) {
	ok, err := e.updatePoliciesWithoutNotifyCtx(ctx, sec, ptype, oldRules, newRules)
	if !ok || err != nil {
		return ok, err
	}

	if e.shouldNotify() {
		var err error
		if watcher, ok := e.watcher.(persist.UpdatableWatcher); ok {
			err = watcher.UpdateForUpdatePolicies(sec, ptype, oldRules, newRules)
		} else {
			err = e.watcher.Update()
		}
		return true, err
	}

	return true, nil
}

func (e *ContextEnforcer) removePolicyCtx(ctx context.Context, sec string, ptype string, rule []string) (bool, error) {
	ok, err := e.removePolicyWithoutNotifyCtx(ctx, sec, ptype, rule)
	if !ok || err != nil {
		return ok, err
	}

	if e.shouldNotify() {
		var err error
		if watcher, ok := e.watcher.(persist.WatcherEx); ok {
			err = watcher.UpdateForRemovePolicy(sec, ptype, rule...)
		} else {
			err = e.watcher.Update()
		}
		return true, err
	}

	return true, nil
}

func (e *ContextEnforcer) removePoliciesCtx(ctx context.Context, sec string, ptype string, rules [][]string) (bool, error) {
	ok, err := e.removePoliciesWithoutNotifyCtx(ctx, sec, ptype, rules)
	if !ok || err != nil {
		return ok, err
	}

	if e.shouldNotify() {
		var err error
		if watcher, ok := e.watcher.(persist.WatcherEx); ok {
			err = watcher.UpdateForRemovePolicies(sec, ptype, rules...)
		} else {
			err = e.watcher.Update()
		}
		return true, err
	}

	return true, nil
}

// removeFilteredPolicy removes rules based on field filters from the current policy.
func (e *ContextEnforcer) removeFilteredPolicyCtx(ctx context.Context, sec string, ptype string, fieldIndex int, fieldValues []string) (bool, error) {
	ok, err := e.removeFilteredPolicyWithoutNotifyCtx(ctx, sec, ptype, fieldIndex, fieldValues)
	if !ok || err != nil {
		return ok, err
	}

	if e.shouldNotify() {
		var err error
		if watcher, ok := e.watcher.(persist.WatcherEx); ok {
			err = watcher.UpdateForRemoveFilteredPolicy(sec, ptype, fieldIndex, fieldValues...)
		} else {
			err = e.watcher.Update()
		}
		return true, err
	}

	return true, nil
}

func (e *ContextEnforcer) updateFilteredPoliciesCtx(ctx context.Context, sec string, ptype string, newRules [][]string, fieldIndex int, fieldValues ...string) (bool, error) {
	oldRules, err := e.updateFilteredPoliciesWithoutNotifyCtx(ctx, sec, ptype, newRules, fieldIndex, fieldValues...)
	ok := len(oldRules) != 0
	if !ok || err != nil {
		return ok, err
	}

	if e.shouldNotify() {
		var err error
		if watcher, ok := e.watcher.(persist.UpdatableWatcher); ok {
			err = watcher.UpdateForUpdatePolicies(sec, ptype, oldRules, newRules)
		} else {
			err = e.watcher.Update()
		}
		return true, err
	}

	return true, nil
}

func (e *ContextEnforcer) updateFilteredPoliciesWithoutNotifyCtx(ctx context.Context, sec string, ptype string, newRules [][]string, fieldIndex int, fieldValues ...string) ([][]string, error) {
	defer e.bumpPolicyVersion()

	var (
		oldRules [][]string
		err      error
	)

	if _, err = e.model.GetAssertion(sec, ptype); err != nil {
		return oldRules, err
	}

	if e.shouldPersist() {
		if oldRules, err = e.adapter.(persist.ContextUpdatableAdapter).UpdateFilteredPoliciesCtx(ctx, sec, ptype, newRules, fieldIndex, fieldValues...); err != nil {
			if err.Error() != notImplemented {
				return nil, err
			}
		}
		// For compatibility, because some adapters return oldRules containing ptype, see https://github.com/casbin/xorm-adapter/issues/49
		for i, oldRule := range oldRules {
			if len(oldRules[i]) == len(e.model[sec][ptype].Tokens)+1 {
				oldRules[i] = oldRule[1:]
			}
		}
	}

	if e.dispatcher != nil && e.autoNotifyDispatcher {
		return oldRules, e.dispatcher.UpdateFilteredPolicies(sec, ptype, oldRules, newRules)
	}

	ruleChanged, err := e.model.RemovePolicies(sec, ptype, oldRules)
	if err != nil {
		return oldRules, err
	}
	err = e.model.AddPolicies(sec, ptype, newRules)
	if err != nil {
		return oldRules, err
	}
	ruleChanged = ruleChanged && len(newRules) != 0
	if !ruleChanged {
		return make([][]string, 0), nil
	}

	if sec == "g" {
		err := e.BuildIncrementalRoleLinks(model.PolicyRemove, ptype, oldRules) // remove the old rules
		if err != nil {
			return oldRules, err
		}
		err = e.BuildIncrementalRoleLinks(model.PolicyAdd, ptype, newRules) // add the new rules
		if err != nil {
			return oldRules, err
		}
	}

	return oldRules, nil
}
