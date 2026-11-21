<!--
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements. See the NOTICE file
distributed with this work for additional information
regarding copyright ownership. The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License. You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied. See the License for the
specific language governing permissions and limitations
under the License.
-->

# Casbin conformance cases

Shared test cases that every Casbin implementation should pass. They are generated from the Go implementation, which is the reference: each test records what Go's `EnforceEx()` returns for one request.

## Layout

- `data/`: model (`.conf`) and policy (`.csv`) files, copied from `examples/`.
- `cases/*.json`: one file per model and policy pair:

```json
{
  "model": "rbac_model.conf",
  "policy": "rbac_policy.csv",
  "tests": [
    {"request": ["alice", "data1", "read"], "allow": true, "explain": ["alice", "data1", "read"]},
    {"request": ["bob", "data1", "read"], "allow": false, "explain": []}
  ]
}
```

`model` and `policy` are file names in `data/`. Every request value is a string. `explain` is the policy rule returned by `EnforceEx()`, or `[]` when no rule decided the result.

## Running the cases

Load the enforcer from the two files with the default file adapter, call the implementation's `enforceEx` for every request, and compare both `allow` and `explain`. The Go test is [`conformance_test.go`](../conformance_test.go).

Other implementations read the cases from the directory in the `CASBIN_CONFORMANCE_DIR` environment variable and skip the test when it is not set. In CI, check out this directory from `apache/casbin`:

```yaml
- uses: actions/checkout@v4
  with:
    repository: apache/casbin
    path: casbin-conformance
    sparse-checkout: conformance
- run: <test command>
  env:
    CASBIN_CONFORMANCE_DIR: ${{ github.workspace }}/casbin-conformance/conformance
```

## Typed names

`typed_names.json` checks `TypedName` and `ParseTypedName`. For every entry in `valid`, `TypedName(type, parts...)` must return `name`, and `ParseTypedName(name)` must return `type` and `parts`. Every string in `invalid` must be rejected by `ParseTypedName`.

The encoding escapes `%`, `:` and `/` in the type and in each part as `%25`, `%3A` and `%2F`, then joins the type and the first part with `:` and the parts with `/`. The Go implementation is [`typed_name.go`](../typed_name.go).

## Regenerating

Add a model and policy pair to `conformanceSources` in `conformance_test.go`, then run:

```shell
go test -run '^TestConformance$' -update-conformance .
```

Requests are generated from the values in the policy, and at most 300 are kept per case, half of them allowed where possible.
