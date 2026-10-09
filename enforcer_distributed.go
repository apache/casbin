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
	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist"
)

// DistributedEnforcer wraps SyncedEnforcer for dispatcher.
type DistributedEnforcer struct {
	*SyncedEnforcer
}

func NewDistributedEnforcer(params ...interface{}) (*DistributedEnforcer, error) {
	e := &DistributedEnforcer{}
	var err error
	e.SyncedEnforcer, err = NewSyncedEnforcer(params...)
	if err != nil {
		return nil, err
	}

	return e, nil
}

// SetDispatcher sets the current dispatcher.
func (d *DistributedEnforcer) SetDispatcher(dispatcher persist.Dispatcher) {
	d.dispatcher = dispatcher
}

// AddPoliciesSelf provides a method for dispatcher to add authorization rules to the current policy.
// The function returns the rules affected and error.
func (d *DistributedEnforcer) AddPoliciesSelf(shouldPersist func() bool, sec string, ptype string, rules [][]string) (affected [][]string, err error) {
	defer d.bumpPolicyVersion()

	d.m.Lock()
	defer d.m.Unlock()
	if shouldPersist != nil && shouldPersist() {
		var noExistsPolicy [][]string
		for _, rule := range rules {
			var hasPolicy bool
			hasPolicy, err = d.model.HasPolicy(sec, ptype, rule)
			if err != nil {
				return nil, err
			}
			if !hasPolicy {
				noExistsPolicy = append(noExistsPolicy, rule)
			}
		}

		if err = d.adapter.(persist.BatchAdapter).AddPolicies(sec, ptype, noExistsPolicy); err != nil && err.Error() != notImplemented {
			return nil, err
		}
	}

	affected, err = d.model.AddPoliciesWithAffected(sec, ptype, rules)
	if err != nil {
		return affected, err
	}

	if sec == "g" {
		err := d.BuildIncrementalRoleLinks(model.PolicyAdd, ptype, affected)
		if err != nil {
			return affected, err
		}
	}

	return affected, nil
}

// RemovePoliciesSelf provides a method for dispatcher to remove a set of rules from current policy.
// The function returns the rules affected and error.
func (d *DistributedEnforcer) RemovePoliciesSelf(shouldPersist func() bool, sec string, ptype string, rules [][]string) (affected [][]string, err error) {
	defer d.bumpPolicyVersion()

	d.m.Lock()
	defer d.m.Unlock()
	if shouldPersist != nil && shouldPersist() {
		if err = d.adapter.(persist.BatchAdapter).RemovePolicies(sec, ptype, rules); err != nil {
			if err.Error() != notImplemented {
				return nil, err
			}
		}
	}

	affected, err = d.model.RemovePoliciesWithAffected(sec, ptype, rules)
	if err != nil {
		return affected, err
	}

	if sec == "g" {
		err = d.BuildIncrementalRoleLinks(model.PolicyRemove, ptype, affected)
		if err != nil {
			return affected, err
		}
	}

	return affected, err
}

// RemoveFilteredPolicySelf provides a method for dispatcher to remove an authorization rule from the current policy, field filters can be specified.
// The function returns the rules affected and error.
func (d *DistributedEnforcer) RemoveFilteredPolicySelf(shouldPersist func() bool, sec string, ptype string, fieldIndex int, fieldValues ...string) (affected [][]string, err error) {
	defer d.bumpPolicyVersion()

	d.m.Lock()
	defer d.m.Unlock()
	if shouldPersist != nil && shouldPersist() {
		if err = d.adapter.RemoveFilteredPolicy(sec, ptype, fieldIndex, fieldValues...); err != nil {
			if err.Error() != notImplemented {
				return nil, err
			}
		}
	}

	_, affected, err = d.model.RemoveFilteredPolicy(sec, ptype, fieldIndex, fieldValues...)
	if err != nil {
		return affected, err
	}

	if sec == "g" {
		err := d.BuildIncrementalRoleLinks(model.PolicyRemove, ptype, affected)
		if err != nil {
			return affected, err
		}
	}

	return affected, nil
}

// ClearPolicySelf provides a method for dispatcher to clear all rules from the current policy.
func (d *DistributedEnforcer) ClearPolicySelf(shouldPersist func() bool) error {
	defer d.bumpPolicyVersion()

	d.m.Lock()
	defer d.m.Unlock()
	if shouldPersist != nil && shouldPersist() {
		err := d.adapter.SavePolicy(nil)
		if err != nil {
			return err
		}
	}

	d.model.ClearPolicy()

	return nil
}

// UpdatePolicySelf provides a method for dispatcher to update an authorization rule from the current policy.
func (d *DistributedEnforcer) UpdatePolicySelf(shouldPersist func() bool, sec string, ptype string, oldRule, newRule []string) (affected bool, err error) {
	defer d.bumpPolicyVersion()

	d.m.Lock()
	defer d.m.Unlock()
	if shouldPersist != nil && shouldPersist() {
		err = d.adapter.(persist.UpdatableAdapter).UpdatePolicy(sec, ptype, oldRule, newRule)
		if err != nil {
			return false, err
		}
	}

	ruleUpdated, err := d.model.UpdatePolicy(sec, ptype, oldRule, newRule)
	if !ruleUpdated || err != nil {
		return ruleUpdated, err
	}

	if sec == "g" {
		err := d.BuildIncrementalRoleLinks(model.PolicyRemove, ptype, [][]string{oldRule}) // remove the old rule
		if err != nil {
			return ruleUpdated, err
		}
		err = d.BuildIncrementalRoleLinks(model.PolicyAdd, ptype, [][]string{newRule}) // add the new rule
		if err != nil {
			return ruleUpdated, err
		}
	}

	return ruleUpdated, nil
}

// UpdatePoliciesSelf provides a method for dispatcher to update a set of authorization rules from the current policy.
func (d *DistributedEnforcer) UpdatePoliciesSelf(shouldPersist func() bool, sec string, ptype string, oldRules, newRules [][]string) (affected bool, err error) {
	defer d.bumpPolicyVersion()

	d.m.Lock()
	defer d.m.Unlock()
	if shouldPersist != nil && shouldPersist() {
		err = d.adapter.(persist.UpdatableAdapter).UpdatePolicies(sec, ptype, oldRules, newRules)
		if err != nil {
			return false, err
		}
	}

	ruleUpdated, err := d.model.UpdatePolicies(sec, ptype, oldRules, newRules)
	if !ruleUpdated || err != nil {
		return ruleUpdated, err
	}

	if sec == "g" {
		err := d.BuildIncrementalRoleLinks(model.PolicyRemove, ptype, oldRules) // remove the old rule
		if err != nil {
			return ruleUpdated, err
		}
		err = d.BuildIncrementalRoleLinks(model.PolicyAdd, ptype, newRules) // add the new rule
		if err != nil {
			return ruleUpdated, err
		}
	}

	return ruleUpdated, nil
}

// UpdateFilteredPoliciesSelf provides a method for dispatcher to update a set of authorization rules from the current policy.
func (d *DistributedEnforcer) UpdateFilteredPoliciesSelf(shouldPersist func() bool, sec string, ptype string, newRules [][]string, fieldIndex int, fieldValues ...string) (bool, error) {
	defer d.bumpPolicyVersion()

	d.m.Lock()
	defer d.m.Unlock()
	var (
		oldRules [][]string
		err      error
	)
	if shouldPersist != nil && shouldPersist() {
		oldRules, err = d.adapter.(persist.UpdatableAdapter).UpdateFilteredPolicies(sec, ptype, newRules, fieldIndex, fieldValues...)
		if err != nil {
			return false, err
		}
	}

	ruleChanged, err := d.model.RemovePolicies(sec, ptype, oldRules)
	if err != nil {
		return ruleChanged, err
	}
	err = d.model.AddPolicies(sec, ptype, newRules)
	if err != nil {
		return ruleChanged, err
	}
	ruleChanged = ruleChanged && len(newRules) != 0
	if !ruleChanged {
		return ruleChanged, nil
	}

	if sec == "g" {
		err := d.BuildIncrementalRoleLinks(model.PolicyRemove, ptype, oldRules) // remove the old rule
		if err != nil {
			return ruleChanged, err
		}
		err = d.BuildIncrementalRoleLinks(model.PolicyAdd, ptype, newRules) // add the new rule
		if err != nil {
			return ruleChanged, err
		}
	}

	return true, nil
}
