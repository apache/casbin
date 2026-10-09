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
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/casbin/casbin/v3/detector"
	"github.com/casbin/casbin/v3/effector"
	"github.com/casbin/casbin/v3/log"
	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist"
	fileadapter "github.com/casbin/casbin/v3/persist/file-adapter"
	"github.com/casbin/casbin/v3/rbac"
	defaultrolemanager "github.com/casbin/casbin/v3/rbac/default-role-manager"
	"github.com/casbin/casbin/v3/util"

	"github.com/casbin/govaluate"
)

// Enforcer is the main interface for authorization enforcement and policy management.
type Enforcer struct {
	policyVersion uint64

	modelPath string
	model     model.Model
	fm        model.FunctionMap
	eft       effector.Effector

	adapter    persist.Adapter
	watcher    persist.Watcher
	dispatcher persist.Dispatcher
	rmMap      map[string]rbac.RoleManager
	condRmMap  map[string]rbac.ConditionalRoleManager
	matcherMap sync.Map
	logger     log.Logger
	detectors  []detector.Detector

	enabled              bool
	autoSave             bool
	autoBuildRoleLinks   bool
	autoNotifyWatcher    bool
	autoNotifyDispatcher bool
	acceptJsonRequest    bool
	gFunctionCache       bool

	aiConfig AIConfig
}

// EnforceContext is used as the first element of the parameter "rvals" in method "enforce".
type EnforceContext struct {
	RType string
	PType string
	EType string
	MType string
}

func (e EnforceContext) GetCacheKey() string {
	return "EnforceContext{" + e.RType + "-" + e.PType + "-" + e.EType + "-" + e.MType + "}"
}

// NewEnforcer creates an enforcer via file or DB.
//
// File:
//
//	e := casbin.NewEnforcer("path/to/basic_model.conf", "path/to/basic_policy.csv")
//
// MySQL DB:
//
//	a := mysqladapter.NewDBAdapter("mysql", "mysql_username:mysql_password@tcp(127.0.0.1:3306)/")
//	e := casbin.NewEnforcer("path/to/basic_model.conf", a)
func NewEnforcer(params ...interface{}) (*Enforcer, error) {
	e := &Enforcer{}

	// Bind the parameters up front so the accesses below are provably in range.
	var param0, param1 interface{}
	if len(params) > 0 {
		param0 = params[0]
	}
	if len(params) > 1 {
		param1 = params[1]
	}

	switch len(params) {
	case 2:
		switch p0 := param0.(type) {
		case string:
			switch p1 := param1.(type) {
			case string:
				err := e.InitWithFile(p0, p1)
				if err != nil {
					return nil, err
				}
			default:
				err := e.InitWithAdapter(p0, p1.(persist.Adapter))
				if err != nil {
					return nil, err
				}
			}
		default:
			switch param1.(type) {
			case string:
				return nil, errors.New("invalid parameters for enforcer")
			default:
				err := e.InitWithModelAndAdapter(p0.(model.Model), param1.(persist.Adapter))
				if err != nil {
					return nil, err
				}
			}
		}
	case 1:
		switch p0 := param0.(type) {
		case string:
			err := e.InitWithFile(p0, "")
			if err != nil {
				return nil, err
			}
		default:
			err := e.InitWithModelAndAdapter(p0.(model.Model), nil)
			if err != nil {
				return nil, err
			}
		}
	case 0:
		return e, nil
	default:
		return nil, errors.New("invalid parameters for enforcer")
	}

	return e, nil
}

// InitWithFile initializes an enforcer with a model file and a policy file.
func (e *Enforcer) InitWithFile(modelPath string, policyPath string) error {
	a := fileadapter.NewAdapter(policyPath)
	return e.InitWithAdapter(modelPath, a)
}

// InitWithAdapter initializes an enforcer with a database adapter.
func (e *Enforcer) InitWithAdapter(modelPath string, adapter persist.Adapter) error {
	m, err := model.NewModelFromFile(modelPath)
	if err != nil {
		return err
	}

	err = e.InitWithModelAndAdapter(m, adapter)
	if err != nil {
		return err
	}

	e.modelPath = modelPath
	return nil
}

// InitWithModelAndAdapter initializes an enforcer with a model and a database adapter.
func (e *Enforcer) InitWithModelAndAdapter(m model.Model, adapter persist.Adapter) error {
	e.adapter = adapter

	e.model = m
	e.model.PrintModel()
	e.fm = model.LoadFunctionMap()

	e.initialize()

	// Do not initialize the full policy when using a filtered adapter
	fa, ok := e.adapter.(persist.FilteredAdapter)
	if e.adapter != nil && (!ok || ok && !fa.IsFiltered()) {
		err := e.LoadPolicy()
		if err != nil {
			return err
		}
	}

	return nil
}

func (e *Enforcer) initialize() {
	e.rmMap = map[string]rbac.RoleManager{}
	e.condRmMap = map[string]rbac.ConditionalRoleManager{}
	e.eft = effector.NewDefaultEffector()
	e.watcher = nil
	e.matcherMap = sync.Map{}
	e.bumpPolicyVersion()

	e.enabled = true
	e.autoSave = true
	e.autoBuildRoleLinks = true
	e.autoNotifyWatcher = true
	e.autoNotifyDispatcher = true
	e.gFunctionCache = true
	e.initRmMap()

	// Initialize detectors with default detector if not already set
	if e.detectors == nil {
		e.detectors = []detector.Detector{detector.NewDefaultDetector()}
	}
}

// LoadModel reloads the model from the model CONF file.
// Because the policy is attached to a model, so the policy is invalidated and needs to be reloaded by calling LoadPolicy().
func (e *Enforcer) LoadModel() error {
	var err error
	e.model, err = model.NewModelFromFile(e.modelPath)
	if err != nil {
		return err
	}

	e.model.PrintModel()
	e.fm = model.LoadFunctionMap()

	e.initialize()

	return nil
}

// GetModel gets the current model.
func (e *Enforcer) GetModel() model.Model {
	return e.model
}

// SetModel sets the current model.
func (e *Enforcer) SetModel(m model.Model) {
	e.model = m
	e.fm = model.LoadFunctionMap()

	e.initialize()
}

// GetAdapter gets the current adapter.
func (e *Enforcer) GetAdapter() persist.Adapter {
	return e.adapter
}

// SetAdapter sets the current adapter.
func (e *Enforcer) SetAdapter(adapter persist.Adapter) {
	e.adapter = adapter
}

// SetWatcher sets the current watcher.
func (e *Enforcer) SetWatcher(watcher persist.Watcher) error {
	e.watcher = watcher
	if _, ok := e.watcher.(persist.WatcherEx); ok {
		// The callback of WatcherEx has no generic implementation.
		return nil
	} else {
		// In case the Watcher wants to use a customized callback function, call `SetUpdateCallback` after `SetWatcher`.
		return watcher.SetUpdateCallback(func(string) { _ = e.LoadPolicy() })
	}
}

// GetRoleManager gets the current role manager.
func (e *Enforcer) GetRoleManager() rbac.RoleManager {
	if e.rmMap != nil && e.rmMap["g"] != nil {
		return e.rmMap["g"]
	} else if e.condRmMap != nil && e.condRmMap["g"] != nil {
		return e.condRmMap["g"]
	} else {
		return nil
	}
}

// GetNamedRoleManager gets the role manager for the named policy.
func (e *Enforcer) GetNamedRoleManager(ptype string) rbac.RoleManager {
	if e.rmMap != nil && e.rmMap[ptype] != nil {
		return e.rmMap[ptype]
	} else if e.condRmMap != nil && e.condRmMap[ptype] != nil {
		return e.condRmMap[ptype]
	} else {
		return nil
	}
}

// SetRoleManager sets the current role manager.
func (e *Enforcer) SetRoleManager(rm rbac.RoleManager) {
	e.invalidateMatcherMap()
	e.rmMap["g"] = rm
}

// SetNamedRoleManager sets the role manager for the named policy.
func (e *Enforcer) SetNamedRoleManager(ptype string, rm rbac.RoleManager) {
	e.invalidateMatcherMap()
	e.rmMap[ptype] = rm
}

// SetEffector sets the current effector.
func (e *Enforcer) SetEffector(eft effector.Effector) {
	e.eft = eft
}

// SetLogger sets the logger for the enforcer.
func (e *Enforcer) SetLogger(logger log.Logger) {
	e.logger = logger
}

// SetDetector sets a single detector for the enforcer.
func (e *Enforcer) SetDetector(d detector.Detector) {
	e.detectors = []detector.Detector{d}
}

// SetDetectors sets multiple detectors for the enforcer.
func (e *Enforcer) SetDetectors(detectors []detector.Detector) {
	e.detectors = detectors
}

// RunDetections runs all detectors on all role managers.
// Returns the first error encountered, or nil if all checks pass.
// Silently skips role managers that don't support the required iteration methods.
func (e *Enforcer) RunDetections() error {
	if len(e.detectors) == 0 {
		return nil
	}

	// Run detectors on all role managers
	for _, rm := range e.rmMap {
		for _, d := range e.detectors {
			err := d.Check(rm)
			// Skip if the role manager doesn't support the required iteration or is not initialized
			if err != nil && (strings.Contains(err.Error(), "does not support Range iteration") ||
				strings.Contains(err.Error(), "not properly initialized")) {
				continue
			}
			if err != nil {
				return err
			}
		}
	}

	// Run detectors on all conditional role managers
	for _, crm := range e.condRmMap {
		for _, d := range e.detectors {
			err := d.Check(crm)
			// Skip if the role manager doesn't support the required iteration or is not initialized
			if err != nil && (strings.Contains(err.Error(), "does not support Range iteration") ||
				strings.Contains(err.Error(), "not properly initialized")) {
				continue
			}
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// ClearPolicy clears all policy.
func (e *Enforcer) ClearPolicy() {
	e.invalidateMatcherMap()

	if e.dispatcher != nil && e.autoNotifyDispatcher {
		_ = e.dispatcher.ClearPolicy()
		return
	}
	e.model.ClearPolicy()
}

// LoadPolicy reloads the policy from file/database.
func (e *Enforcer) LoadPolicy() error {
	logEntry := e.onLogBeforeEventInLoadPolicy()

	newModel, err := e.loadPolicyFromAdapter(e.model)
	if err != nil {
		e.onLogAfterEventWithError(logEntry, err)
		return err
	}
	err = e.applyModifiedModel(newModel)
	if err != nil {
		e.onLogAfterEventWithError(logEntry, err)
		return err
	}

	e.onLogAfterEventInLoadPolicy(logEntry, newModel)

	// Run detectors after all policy rules are loaded
	err = e.RunDetections()
	if err != nil {
		return err
	}

	return nil
}

func (e *Enforcer) loadPolicyFromAdapter(baseModel model.Model) (model.Model, error) {
	newModel := baseModel.Copy()
	newModel.ClearPolicy()

	if err := e.adapter.LoadPolicy(newModel); err != nil && err.Error() != "invalid file path, file path cannot be empty" {
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

func (e *Enforcer) applyModifiedModel(newModel model.Model) error {
	var err error
	needToRebuild := false
	defer func() {
		if err != nil {
			if e.autoBuildRoleLinks && needToRebuild {
				_ = e.BuildRoleLinks()
			}
		}
	}()

	if e.autoBuildRoleLinks {
		needToRebuild = true

		if err := e.rebuildRoleLinks(newModel); err != nil {
			return err
		}

		if err := e.rebuildConditionalRoleLinks(newModel); err != nil {
			return err
		}
	}

	e.model = newModel
	e.invalidateMatcherMap()
	return nil
}

func (e *Enforcer) rebuildRoleLinks(newModel model.Model) error {
	if len(e.rmMap) != 0 {
		for _, rm := range e.rmMap {
			err := rm.Clear()
			if err != nil {
				return err
			}
		}

		err := newModel.BuildRoleLinks(e.rmMap)
		if err != nil {
			return err
		}
	}

	return nil
}

func (e *Enforcer) rebuildConditionalRoleLinks(newModel model.Model) error {
	if len(e.condRmMap) != 0 {
		for _, crm := range e.condRmMap {
			err := crm.Clear()
			if err != nil {
				return err
			}
		}

		err := newModel.BuildConditionalRoleLinks(e.condRmMap)
		if err != nil {
			return err
		}
	}
	return nil
}

func (e *Enforcer) loadFilteredPolicy(filter interface{}) error {
	e.invalidateMatcherMap()

	var filteredAdapter persist.FilteredAdapter

	// Attempt to cast the Adapter as a FilteredAdapter
	switch adapter := e.adapter.(type) {
	case persist.FilteredAdapter:
		filteredAdapter = adapter
	default:
		return errors.New("filtered policies are not supported by this adapter")
	}
	if err := filteredAdapter.LoadFilteredPolicy(e.model, filter); err != nil && err.Error() != "invalid file path, file path cannot be empty" {
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

// LoadFilteredPolicy reloads a filtered policy from file/database.
func (e *Enforcer) LoadFilteredPolicy(filter interface{}) error {
	e.model.ClearPolicy()

	return e.loadFilteredPolicy(filter)
}

// LoadIncrementalFilteredPolicy append a filtered policy from file/database.
func (e *Enforcer) LoadIncrementalFilteredPolicy(filter interface{}) error {
	return e.loadFilteredPolicy(filter)
}

// IsFiltered returns true if the loaded policy has been filtered.
func (e *Enforcer) IsFiltered() bool {
	filteredAdapter, ok := e.adapter.(persist.FilteredAdapter)
	if !ok {
		return false
	}
	return filteredAdapter.IsFiltered()
}

// SavePolicy saves the current policy (usually after changed with Casbin API) back to file/database.
func (e *Enforcer) SavePolicy() error {
	logEntry := e.onLogBeforeEventInSavePolicy()

	if e.IsFiltered() {
		err := errors.New("cannot save a filtered policy")
		e.onLogAfterEventWithError(logEntry, err)
		return err
	}
	if err := e.adapter.SavePolicy(e.model); err != nil {
		e.onLogAfterEventWithError(logEntry, err)
		return err
	}

	e.onLogAfterEventInSavePolicy(logEntry)

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

// getDomainTokens extracts domain token names from request and policy definitions.
// Returns empty strings if tokens cannot be found.
func (e *Enforcer) getDomainTokens() (rDomainToken, pDomainToken string) {
	if rAssertion, ok := e.model["r"]["r"]; ok && len(rAssertion.Tokens) > 1 {
		rDomainToken = rAssertion.Tokens[1]
	}
	if pAssertion, ok := e.model["p"]["p"]; ok && len(pAssertion.Tokens) > 1 {
		pDomainToken = pAssertion.Tokens[1]
	}
	return rDomainToken, pDomainToken
}

// registerDomainMatchingFunc registers domain matching function if the matcher uses keyMatch for domains.
func (e *Enforcer) registerDomainMatchingFunc(ptype string) {
	// Dynamically detect the domain token name from the model definition.
	// In RBAC with domains, the domain is typically the second parameter (index 1)
	// in both request and policy definitions (e.g., r = sub, dom, obj, act).
	// We extract the actual token names to support arbitrary domain parameter names.
	rDomainToken, pDomainToken := e.getDomainTokens()
	if rDomainToken == "" || pDomainToken == "" {
		return
	}

	matchFun := fmt.Sprintf("keyMatch(%s, %s)", rDomainToken, pDomainToken)
	if strings.Contains(e.model["m"]["m"].Value, matchFun) {
		e.AddNamedDomainMatchingFunc(ptype, "g", util.KeyMatch)
	}
}

func (e *Enforcer) initRmMap() {
	for ptype, assertion := range e.model["g"] {
		if rm, ok := e.rmMap[ptype]; ok {
			_ = rm.Clear()
			continue
		}
		if len(assertion.Tokens) <= 2 && len(assertion.ParamsTokens) == 0 {
			assertion.RM = defaultrolemanager.NewRoleManagerImpl(10)
			e.rmMap[ptype] = assertion.RM
		}
		if len(assertion.Tokens) <= 2 && len(assertion.ParamsTokens) != 0 {
			assertion.CondRM = defaultrolemanager.NewConditionalRoleManager(10)
			e.condRmMap[ptype] = assertion.CondRM
		}
		if len(assertion.Tokens) > 2 {
			if len(assertion.ParamsTokens) == 0 {
				assertion.RM = defaultrolemanager.NewRoleManager(10)
				e.rmMap[ptype] = assertion.RM
			} else {
				assertion.CondRM = defaultrolemanager.NewConditionalDomainManager(10)
				e.condRmMap[ptype] = assertion.CondRM
			}
			e.registerDomainMatchingFunc(ptype)
		}
	}
}

// EnableEnforce changes the enforcing state of Casbin, when Casbin is disabled, all access will be allowed by the Enforce() function.
func (e *Enforcer) EnableEnforce(enable bool) {
	e.enabled = enable
}

// EnableAutoNotifyWatcher controls whether to save a policy rule automatically notify the Watcher when it is added or removed.
func (e *Enforcer) EnableAutoNotifyWatcher(enable bool) {
	e.autoNotifyWatcher = enable
}

// EnableAutoNotifyDispatcher controls whether to save a policy rule automatically notify the Dispatcher when it is added or removed.
func (e *Enforcer) EnableAutoNotifyDispatcher(enable bool) {
	e.autoNotifyDispatcher = enable
}

// EnableAutoSave controls whether to save a policy rule automatically to the adapter when it is added or removed.
func (e *Enforcer) EnableAutoSave(autoSave bool) {
	e.autoSave = autoSave
}

// EnableAutoBuildRoleLinks controls whether to rebuild the role inheritance relations when a role is added or deleted.
func (e *Enforcer) EnableAutoBuildRoleLinks(autoBuildRoleLinks bool) {
	e.autoBuildRoleLinks = autoBuildRoleLinks
}

// EnableAcceptJsonRequest controls whether to accept json as a request parameter.
func (e *Enforcer) EnableAcceptJsonRequest(acceptJsonRequest bool) {
	e.acceptJsonRequest = acceptJsonRequest
}

// EnableGFunctionCache controls whether to cache g() function results.
// Disable this when inputs are high-cardinality (e.g. UUIDs or dynamic paths)
// to prevent unbounded memory growth.
func (e *Enforcer) EnableGFunctionCache(enabled bool) {
	e.gFunctionCache = enabled
	e.invalidateMatcherMap()
}

// BuildRoleLinks manually rebuild the role inheritance relations.
func (e *Enforcer) BuildRoleLinks() error {
	e.invalidateMatcherMap()
	if e.rmMap == nil {
		return errors.New("rmMap is nil")
	}
	for _, rm := range e.rmMap {
		err := rm.Clear()
		if err != nil {
			return err
		}
	}

	return e.model.BuildRoleLinks(e.rmMap)
}

// BuildIncrementalRoleLinks provides incremental build the role inheritance relations.
func (e *Enforcer) BuildIncrementalRoleLinks(op model.PolicyOp, ptype string, rules [][]string) error {
	e.invalidateMatcherMap()
	return e.model.BuildIncrementalRoleLinks(e.rmMap, op, "g", ptype, rules)
}

// BuildIncrementalConditionalRoleLinks provides incremental build the role inheritance relations with conditions.
func (e *Enforcer) BuildIncrementalConditionalRoleLinks(op model.PolicyOp, ptype string, rules [][]string) error {
	e.invalidateMatcherMap()
	return e.model.BuildIncrementalConditionalRoleLinks(e.condRmMap, op, "g", ptype, rules)
}

// NewEnforceContext Create a default structure based on the suffix.
func NewEnforceContext(suffix string) EnforceContext {
	return EnforceContext{
		RType: "r" + suffix,
		PType: "p" + suffix,
		EType: "e" + suffix,
		MType: "m" + suffix,
	}
}

func (e *Enforcer) invalidateMatcherMap() {
	e.matcherMap = sync.Map{}
	e.bumpPolicyVersion()
}

func (e *Enforcer) getPolicyVersion() uint64 {
	return atomic.LoadUint64(&e.policyVersion)
}

func (e *Enforcer) bumpPolicyVersion() {
	atomic.AddUint64(&e.policyVersion, 1)
}

// enforce use a custom matcher to decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (matcher, sub, obj, act), use model matcher by default when matcher is "".
func (e *Enforcer) enforce(matcher string, explains *[]string, rvals ...interface{}) (ok bool, err error) { //nolint:funlen,cyclop,gocyclo // TODO: reduce function complexity
	logEntry := e.onLogBeforeEventInEnforce(rvals)

	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v\n%s", r, debug.Stack())
			if e.logger != nil && logEntry != nil {
				logEntry.Error = err
			}
		}
		e.onLogAfterEventInEnforce(logEntry, ok)
	}()

	if !e.enabled {
		return true, nil
	}

	functions := e.fm.GetFunctions()
	if _, ok := e.model["g"]; ok {
		for key, ast := range e.model["g"] {
			// g must be a normal role definition (ast.RM != nil)
			//   or a conditional role definition (ast.CondRM != nil)
			// ast.RM and ast.CondRM shouldn't be nil at the same time
			if ast.RM != nil {
				functions[key] = util.GenerateGFunction(ast.RM, e.gFunctionCache)
			}
			if ast.CondRM != nil {
				functions[key] = util.GenerateConditionalGFunction(ast.CondRM)
			}
		}
	}

	var (
		rType = "r"
		pType = "p"
		eType = "e"
		mType = "m"
	)
	if len(rvals) != 0 {
		switch rvals[0].(type) {
		case EnforceContext:
			enforceContext := rvals[0].(EnforceContext)
			rType = enforceContext.RType
			pType = enforceContext.PType
			eType = enforceContext.EType
			mType = enforceContext.MType
			rvals = rvals[1:]
		default:
			break
		}
	}

	var expString string
	if matcher == "" {
		expString = e.model["m"][mType].Value
	} else {
		// For custom matchers provided at runtime, escape backslashes in string literals
		expString = util.EscapeStringLiterals(util.RemoveComments(util.EscapeAssertion(matcher)))
	}

	rTokens := make(map[string]int, len(e.model["r"][rType].Tokens))
	for i, token := range e.model["r"][rType].Tokens {
		rTokens[token] = i
	}
	pTokens := make(map[string]int, len(e.model["p"][pType].Tokens))
	for i, token := range e.model["p"][pType].Tokens {
		pTokens[token] = i
	}

	if e.acceptJsonRequest {
		// try to parse all request values from json to map[string]interface{}
		for i, rval := range rvals {
			switch rval := rval.(type) {
			case string:
				// Only attempt JSON parsing for strings that look like JSON objects or arrays
				if len(rval) > 0 && (rval[0] == '{' || rval[0] == '[') {
					var mapValue map[string]interface{}
					mapValue, err = util.JsonToMap(rval)
					if err != nil {
						// Return a clear error when JSON-like string fails to parse
						return false, fmt.Errorf("failed to parse JSON parameter at index %d: %w", i, err)
					}
					rvals[i] = mapValue
				}
			}
		}
	}

	parameters := enforceParameters{
		rTokens: rTokens,
		rVals:   rvals,

		pTokens: pTokens,
	}

	hasEval := util.HasEval(expString)
	if hasEval {
		functions["eval"] = generateEvalFunction(functions, &parameters)
	}
	var expression *govaluate.EvaluableExpression
	expression, err = e.getAndStoreMatcherExpression(hasEval, expString, functions)
	if err != nil {
		return false, err
	}

	if len(e.model["r"][rType].Tokens) != len(rvals) {
		return false, fmt.Errorf(
			"invalid request size: expected %d, got %d, rvals: %v",
			len(e.model["r"][rType].Tokens),
			len(rvals),
			rvals)
	}

	var policyEffects []effector.Effect
	var matcherResults []float64

	var effect effector.Effect
	var explainIndex int

	if policyLen := len(e.model["p"][pType].Policy); policyLen != 0 && strings.Contains(expString, pType+"_") { //nolint:nestif // TODO: reduce function complexity
		policyEffects = make([]effector.Effect, policyLen)
		matcherResults = make([]float64, policyLen)

		for policyIndex, pvals := range e.model["p"][pType].Policy {
			// log.LogPrint("Policy Rule: ", pvals)
			if len(e.model["p"][pType].Tokens) != len(pvals) {
				return false, fmt.Errorf(
					"invalid policy size: expected %d, got %d, pvals: %v",
					len(e.model["p"][pType].Tokens),
					len(pvals),
					pvals)
			}

			parameters.pVals = pvals

			result, err := expression.Eval(parameters)
			// log.LogPrint("Result: ", result)
			if err != nil {
				return false, err
			}

			// set to no-match at first
			matcherResults[policyIndex] = 0
			switch result := result.(type) {
			case bool:
				if result {
					matcherResults[policyIndex] = 1
				}
			case float64:
				if result != 0 {
					matcherResults[policyIndex] = 1
				}
			default:
				return false, errors.New("matcher result should be bool, int or float")
			}

			if j, ok := parameters.pTokens[pType+"_eft"]; ok {
				eft := parameters.pVals[j]
				switch eft {
				case "allow":
					policyEffects[policyIndex] = effector.Allow
				case "deny":
					policyEffects[policyIndex] = effector.Deny
				default:
					policyEffects[policyIndex] = effector.Indeterminate
				}
			} else {
				policyEffects[policyIndex] = effector.Allow
			}

			// if e.model["e"]["e"].Value == "priority(p_eft) || deny" {
			//	break
			// }

			effect, explainIndex, err = e.eft.MergeEffects(e.model["e"][eType].Value, policyEffects, matcherResults, policyIndex, policyLen)
			if err != nil {
				return false, err
			}
			if effect != effector.Indeterminate {
				break
			}
		}
	} else {
		if hasEval && len(e.model["p"][pType].Policy) == 0 {
			return false, errors.New("please make sure rule exists in policy when using eval() in matcher")
		}

		policyEffects = make([]effector.Effect, 1)
		matcherResults = make([]float64, 1)
		matcherResults[0] = 1

		parameters.pVals = make([]string, len(parameters.pTokens))

		result, err := expression.Eval(parameters)
		if err != nil {
			return false, err
		}

		if result.(bool) {
			policyEffects[0] = effector.Allow
		} else {
			policyEffects[0] = effector.Indeterminate
		}

		effect, explainIndex, err = e.eft.MergeEffects(e.model["e"][eType].Value, policyEffects, matcherResults, 0, 1)
		if err != nil {
			return false, err
		}
	}

	if explains != nil {
		if explainIndex != -1 && len(e.model["p"][pType].Policy) > explainIndex {
			*explains = e.model["p"][pType].Policy[explainIndex]
		}
	}

	// effect -> result
	result := effect == effector.Allow

	return result, nil
}

func (e *Enforcer) getAndStoreMatcherExpression(hasEval bool, expString string, functions map[string]govaluate.ExpressionFunction) (*govaluate.EvaluableExpression, error) {
	var expression *govaluate.EvaluableExpression
	var err error
	cachedExpression, isPresent := e.matcherMap.Load(expString)

	if !hasEval && isPresent {
		expression = cachedExpression.(*govaluate.EvaluableExpression)
	} else {
		expression, err = govaluate.NewEvaluableExpressionWithFunctions(expString, functions)
		if err != nil {
			return nil, err
		}
		e.matcherMap.Store(expString, expression)
	}
	return expression, nil
}

// Enforce decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (sub, obj, act).
func (e *Enforcer) Enforce(rvals ...interface{}) (bool, error) {
	return e.enforce("", nil, rvals...)
}

// EnforceWithMatcher use a custom matcher to decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (matcher, sub, obj, act), use model matcher by default when matcher is "".
func (e *Enforcer) EnforceWithMatcher(matcher string, rvals ...interface{}) (bool, error) {
	return e.enforce(matcher, nil, rvals...)
}

// EnforceEx explain enforcement by informing matched rules.
func (e *Enforcer) EnforceEx(rvals ...interface{}) (bool, []string, error) {
	explain := []string{}
	result, err := e.enforce("", &explain, rvals...)
	return result, explain, err
}

// EnforceExWithMatcher use a custom matcher and explain enforcement by informing matched rules.
func (e *Enforcer) EnforceExWithMatcher(matcher string, rvals ...interface{}) (bool, []string, error) {
	explain := []string{}
	result, err := e.enforce(matcher, &explain, rvals...)
	return result, explain, err
}

// BatchEnforce enforce in batches.
func (e *Enforcer) BatchEnforce(requests [][]interface{}) ([]bool, error) {
	var results []bool
	for _, request := range requests {
		result, err := e.enforce("", nil, request...)
		if err != nil {
			return results, err
		}
		results = append(results, result)
	}
	return results, nil
}

// BatchEnforceWithMatcher enforce with matcher in batches.
func (e *Enforcer) BatchEnforceWithMatcher(matcher string, requests [][]interface{}) ([]bool, error) {
	var results []bool
	for _, request := range requests {
		result, err := e.enforce(matcher, nil, request...)
		if err != nil {
			return results, err
		}
		results = append(results, result)
	}
	return results, nil
}

// AddNamedMatchingFunc add MatchingFunc by ptype RoleManager.
func (e *Enforcer) AddNamedMatchingFunc(ptype, name string, fn rbac.MatchingFunc) bool {
	if rm, ok := e.rmMap[ptype]; ok {
		rm.AddMatchingFunc(name, fn)
		return true
	}
	return false
}

// AddNamedDomainMatchingFunc add MatchingFunc by ptype to RoleManager.
func (e *Enforcer) AddNamedDomainMatchingFunc(ptype, name string, fn rbac.MatchingFunc) bool {
	if rm, ok := e.rmMap[ptype]; ok {
		rm.AddDomainMatchingFunc(name, fn)
		return true
	}
	if condRm, ok := e.condRmMap[ptype]; ok {
		condRm.AddDomainMatchingFunc(name, fn)
		return true
	}
	return false
}

// AddNamedLinkConditionFunc Add condition function fn for Link userName->roleName,
// when fn returns true, Link is valid, otherwise invalid.
func (e *Enforcer) AddNamedLinkConditionFunc(ptype, user, role string, fn rbac.LinkConditionFunc) bool {
	if rm, ok := e.condRmMap[ptype]; ok {
		rm.AddLinkConditionFunc(user, role, fn)
		return true
	}
	return false
}

// AddNamedDomainLinkConditionFunc Add condition function fn for Link userName-> {roleName, domain},
// when fn returns true, Link is valid, otherwise invalid.
func (e *Enforcer) AddNamedDomainLinkConditionFunc(ptype, user, role string, domain string, fn rbac.LinkConditionFunc) bool {
	if rm, ok := e.condRmMap[ptype]; ok {
		rm.AddDomainLinkConditionFunc(user, role, domain, fn)
		return true
	}
	return false
}

// SetNamedLinkConditionFuncParams Sets the parameters of the condition function fn for Link userName->roleName.
func (e *Enforcer) SetNamedLinkConditionFuncParams(ptype, user, role string, params ...string) bool {
	if rm, ok := e.condRmMap[ptype]; ok {
		rm.SetLinkConditionFuncParams(user, role, params...)
		return true
	}
	return false
}

// SetNamedDomainLinkConditionFuncParams Sets the parameters of the condition function fn
// for Link userName->{roleName, domain}.
func (e *Enforcer) SetNamedDomainLinkConditionFuncParams(ptype, user, role, domain string, params ...string) bool {
	if rm, ok := e.condRmMap[ptype]; ok {
		rm.SetDomainLinkConditionFuncParams(user, role, domain, params...)
		return true
	}
	return false
}

// assumes bounds have already been checked.
type enforceParameters struct {
	rTokens map[string]int
	rVals   []interface{}

	pTokens map[string]int
	pVals   []string
}

// implements govaluate.Parameters.
func (p enforceParameters) Get(name string) (interface{}, error) {
	if name == "" {
		return nil, nil
	}

	switch name[0] {
	case 'p':
		i, ok := p.pTokens[name]
		if !ok {
			return nil, errors.New("No parameter '" + name + "' found.")
		}
		return p.pVals[i], nil
	case 'r':
		i, ok := p.rTokens[name]
		if !ok {
			return nil, errors.New("No parameter '" + name + "' found.")
		}
		return p.rVals[i], nil
	default:
		return nil, errors.New("No parameter '" + name + "' found.")
	}
}

func generateEvalFunction(functions map[string]govaluate.ExpressionFunction, parameters *enforceParameters) govaluate.ExpressionFunction {
	return func(args ...interface{}) (interface{}, error) {
		if len(args) != 1 {
			return nil, fmt.Errorf("function eval(subrule string) expected %d arguments, but got %d", 1, len(args))
		}

		expression, ok := args[0].(string)
		if !ok {
			return nil, errors.New("argument of eval(subrule string) must be a string")
		}
		expression = util.EscapeAssertion(expression)
		expr, err := govaluate.NewEvaluableExpressionWithFunctions(expression, functions)
		if err != nil {
			return nil, fmt.Errorf("error while parsing eval parameter: %s, %s", expression, err.Error())
		}
		return expr.Eval(parameters)
	}
}
