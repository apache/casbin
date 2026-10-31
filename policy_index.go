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
	"fmt"
	"sync"

	"github.com/casbin/casbin/v3/model"
)

const (
	wildcardPolicyBucket uint32 = ^uint32(0)
	missingPolicyBucket  uint32 = ^uint32(1)
)

// PolicyIndex partitions the policy rules of one policy type so that Enforce
// only evaluates the rules in the request's partition.
//
// RequestKey receives the request values, with an optional EnforceContext
// removed, and returns the partition key for the request. Returning false
// disables the index for that request, so every rule is evaluated.
//
// PolicyKey returns the partition key for one policy rule. The key "*" puts
// the rule in every partition.
//
// Enforce skips the matcher of a rule whose key differs from the request key.
// The caller must guarantee that such a rule can never match the request;
// otherwise the decision changes. This includes matchers that evaluate policy
// fields with eval(). Rules are still merged by the configured effector, so
// deny rules must be reachable through the request key or "*".
type PolicyIndex struct {
	RequestKey func(rvals []interface{}) (string, bool)
	PolicyKey  func(rule []string) string
}

// SetPolicyIndex installs a policy partition for ptype. It replaces an
// existing index for the same policy type. The index is rebuilt automatically
// when the policy changes.
func (e *Enforcer) SetPolicyIndex(ptype string, index PolicyIndex) error {
	if index.RequestKey == nil || index.PolicyKey == nil {
		return errors.New("policy index functions cannot be nil")
	}
	if _, ok := e.model["p"][ptype]; !ok {
		return fmt.Errorf("policy type %q does not exist", ptype)
	}

	e.policyIndexes.Store(ptype, &policyIndex{
		requestKey: index.RequestKey,
		policyKey:  index.PolicyKey,
	})
	return nil
}

// SetPolicyIndexByToken installs a policy partition that uses the string value
// of requestToken as the request key and the string value of policyToken as
// the rule key. It uses the default request type "r"; use SetPolicyIndex with
// a custom function when enforcing through an EnforceContext.
func (e *Enforcer) SetPolicyIndexByToken(ptype string, requestToken string, policyToken string) error {
	rAssertion, ok := e.model["r"]["r"]
	if !ok {
		return errors.New("request type \"r\" does not exist")
	}
	requestIndex := -1
	for i, token := range rAssertion.Tokens {
		if token == requestToken {
			requestIndex = i
			break
		}
	}
	if requestIndex == -1 {
		return fmt.Errorf("request token %q does not exist", requestToken)
	}

	pAssertion, ok := e.model["p"][ptype]
	if !ok {
		return fmt.Errorf("policy type %q does not exist", ptype)
	}
	policyIndex := -1
	for i, token := range pAssertion.Tokens {
		if token == policyToken {
			policyIndex = i
			break
		}
	}
	if policyIndex == -1 {
		return fmt.Errorf("policy token %q does not exist", policyToken)
	}

	return e.SetPolicyIndex(ptype, PolicyIndex{
		RequestKey: func(rvals []interface{}) (string, bool) {
			if requestIndex >= len(rvals) {
				return "", false
			}
			key, ok := rvals[requestIndex].(string)
			return key, ok
		},
		PolicyKey: func(rule []string) string {
			if policyIndex >= len(rule) {
				return ""
			}
			return rule[policyIndex]
		},
	})
}

// RemovePolicyIndex removes the policy partition for ptype.
func (e *Enforcer) RemovePolicyIndex(ptype string) {
	e.policyIndexes.Delete(ptype)
}

func (e *Enforcer) getPolicyIndex(ptype string) *policyIndex {
	if value, ok := e.policyIndexes.Load(ptype); ok {
		return value.(*policyIndex)
	}
	return nil
}

type policyIndex struct {
	requestKey func(rvals []interface{}) (string, bool)
	policyKey  func(rule []string) string

	mu        sync.Mutex
	built     bool
	version   uint64
	bucketIDs []uint32
	names     map[string]uint32
}

func (idx *policyIndex) ensureBuilt(ast *model.Assertion) []uint32 {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	if idx.built && idx.version == ast.PolicyVersion && len(idx.bucketIDs) == len(ast.Policy) {
		return idx.bucketIDs
	}

	names := make(map[string]uint32)
	bucketIDs := make([]uint32, len(ast.Policy))
	var next uint32
	for i, rule := range ast.Policy {
		key := idx.policyKey(rule)
		if key == "*" {
			bucketIDs[i] = wildcardPolicyBucket
			continue
		}

		id, ok := names[key]
		if !ok {
			id = next
			names[key] = id
			next++
		}
		bucketIDs[i] = id
	}

	idx.version = ast.PolicyVersion
	idx.bucketIDs = bucketIDs
	idx.names = names
	idx.built = true
	return bucketIDs
}

func (idx *policyIndex) reset() {
	idx.mu.Lock()
	idx.built = false
	idx.bucketIDs = nil
	idx.names = nil
	idx.mu.Unlock()
}

func (idx *policyIndex) requestBucket(rvals []interface{}) (uint32, bool) {
	key, ok := idx.requestKey(rvals)
	if !ok {
		return 0, false
	}

	idx.mu.Lock()
	id, found := idx.names[key]
	idx.mu.Unlock()
	if !found {
		return missingPolicyBucket, true
	}
	return id, true
}

func policyMatchesBucket(bucketIDs []uint32, policyIndex int, bucket uint32) bool {
	if policyIndex < 0 || policyIndex >= len(bucketIDs) {
		return true
	}
	id := bucketIDs[policyIndex]
	return id == wildcardPolicyBucket || id == bucket
}
