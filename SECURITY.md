# Security Policy

## Reporting a Vulnerability

Apache Casbin follows the [Apache Software Foundation security process](https://www.apache.org/security/). Please report security issues privately to security@apache.org. Do not open public GitHub issues, pull requests or discussions for security issues.

This policy applies to Apache Casbin and to its implementations in other languages.

## Security Model

Casbin is an authorization library embedded in an application. It decides whether a request is allowed according to a model and a policy provided by the application.

The following are trusted:

- The authors of the model, the policy and the matchers (policy administrators), and anyone who can call the management APIs.
- The application code that creates and calls the enforcer.
- The storage behind an adapter.
- The message channel used by a watcher or dispatcher to synchronize policy between instances.
- Clients of a Casbin service that exposes the enforcer and management APIs to other internal components (for example, over gRPC).

The following are untrusted:

- The values of an enforcement request: the subject, object, action and other request fields, including the attributes of objects passed for ABAC.

## What Is Not a Vulnerability

The following are not treated as vulnerabilities. Some of them may still be fixed as ordinary bugs or hardening.

1. Issues that require the ability to write or modify the model, the policy or the matchers, including expressions, regular expressions, IP ranges and functions placed in them, or that are caused by invalid or unsafe values written there by a policy administrator.
2. Unexpected results caused by how a matcher expression is written or evaluated, such as operator precedence, the parsing of literals, or the handling of mixed operators, where the matcher itself is controlled by a policy administrator.
3. Issues that require control of the storage behind an adapter or of the message channel used by a watcher or dispatcher.
4. Issues that require acting as a trusted client of a Casbin service, such as passing crafted arguments to its management or enforcement APIs.
5. Issues caused by how the application uses the API, such as disabling enforcement, clearing and rebuilding policy on a live enforcer, or using an enforcer that is not documented as thread-safe from multiple goroutines or threads.
6. Short windows in which cached or synchronized decisions do not yet reflect a policy change, including races between policy updates and concurrent enforcement. Caches and watchers do not guarantee strong consistency.
7. Missing authentication in front of an authorization middleware or plugin. Casbin only performs authorization; authenticating the user is the responsibility of the application or of the middleware placed before it.
8. Differences in behavior or results between implementations of Casbin in different languages for the same model and policy. The implementations are not guaranteed to behave identically.
9. Denial of service, including panics, crashes, hangs and excessive CPU or memory consumption, even when triggered by the values of an enforcement request. Such issues are fixed as ordinary bugs.

## Severity

Reported severity scores are reassessed against this security model. An issue whose preconditions include any of the trusted parties above is rated accordingly.
