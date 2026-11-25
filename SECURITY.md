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

# Security policy

## Reporting a vulnerability

Report vulnerabilities privately to security@apache.org, as described at https://www.apache.org/security/. Please do not open public issues or pull requests for them.

## Security model

Casbin is an authorization library. An application loads a model and a policy, and asks the enforcer whether a request is allowed. This section applies to apache/casbin, apache/casbin-pycasbin and apache/casbin-jcasbin.

### What we treat as trusted

- The model, including the matcher.
- The policy, including `eval()` rules, wherever it is stored. It is written by the application's policy administrator.

### What we treat as untrusted

- The request passed to the enforcer. A request should never get a decision other than the one the model and policy define for it.

### What we do not consider a vulnerability

- A finding that requires writing to the model or the policy. Policy text, including `eval()` rules, does not cross a trust boundary.
- An application that lets less trusted users write policy. That application must validate the input itself.
- Limits on which `eval()` expressions are accepted, where they exist, are portability controls, not security boundaries.

### What we would want to hear about

- A way for a less trusted party to place content into a policy the enforcer loads, or to reach `eval()` or the matcher, without already being able to edit the policy.
