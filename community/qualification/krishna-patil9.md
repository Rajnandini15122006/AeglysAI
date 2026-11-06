# AeglysAI qualification technical evidence

- Public fork URL: https://github.com/krishna-patil9/AeglysAI
- Qualification branch URL: https://github.com/krishna-patil9/AeglysAI/tree/qualification/krishna-patil9
- Exact base commit: `48047e46aee115181dc0fd67a45105a0b7a45a45`

---

## 1. Architecture: Domain, Application, Infrastructure, and API boundaries

AeglysAI is architected according to Clean Architecture and SOLID design principles targeting .NET 8. Inward-pointing dependency rules guarantee that core business policies remain decoupled from transport mechanisms, external SDKs, and data stores:

- **AeglysAI.Domain**:
  The innermost dependency-free foundation declaring domain concepts, immutable value records, and identity contracts:
  - Subject identity (`Subject` holding subject identifier and issuer string)
  - Target permissions (`Resource`, `Action`, and composite `Permission`)
  - Role definition (`Role` containing assigned permissions)
  - Attribute-based access structures (`AbacRule`, `AttributeCondition`, `AttributeSet`, `AttributeScope`)
  - Risk models (`RiskContext`, `RiskSignal`)
  - Authorization outcomes (`AuthorizationOutcome`: ALLOW, DENY, STEP_UP, LIMIT).

- **AeglysAI.Application**:
  Houses the operational policy pipelines and evaluation engines, referencing only `AeglysAI.Domain`:
  - Identity extraction abstractions (`ICurrentIdentity`, `AuthenticatedIdentity`)
  - Evaluation engines: `RbacAuthorizationEngine` (Model A), `ModelBAuthorizationEngine` (Model B: RBAC + ABAC), and `ModelCAuthorizationEngine` (Model C: Contextual Risk Engine)
  - Contract interfaces (`IAuthorizationEngine`, `IAbacEvaluator`, `IRbacPolicyProvider`, `IContextualRiskEngine`, `IRiskContextProvider`)
  - Audit event schema (`AuthorizationAuditEvent`).

- **AeglysAI.Infrastructure**:
  Provides concrete data snapshot and policy providers, referencing `Application` and `Domain`:
  - `InMemoryRbacPolicyProvider`
  - `InMemoryAbacContextProvider`
  - `InMemoryRiskContextProvider`.

- **AeglysAI.Api**:
  Composition root and HTTP hosting layer, referencing `Application` and `Infrastructure`:
  - Minimal API endpoint mapping (`/health`, `/identity`, `/authorization/evaluate`, `/authorization/evaluate/model-b`, `/authorization/evaluate/model-c`)
  - JWT Bearer authentication and single-identity extraction (`HttpCurrentIdentity`)
  - Strict input sanitization (`EvaluationInput` with disallowed unmapped JSON properties)
  - Structured telemetry, trace propagation, and decision audit pipeline (`AuthorizationObservation`, `LoggingAuthorizationAuditSink`).

### Request and Decision Flow
1. **Client Ingestion**: An HTTP POST request arrives with a signed JWT Bearer header and a JSON payload specifying `resource` and `action`.
2. **Authentication Enforcement**: ASP.NET Core validates the JWT. `HttpCurrentIdentity` verifies that exactly one authenticated identity is present and extracts exactly one `sub` and one `iss` claim, returning an immutable `Subject(sub, iss)`. If missing, malformed, or ambiguous, access is refused with HTTP 401 Unauthorized.
3. **Payload Inspection**: `EvaluationInput` enforces non-empty strings under 256 characters and rejects unmapped JSON fields to avoid parameter injection.
4. **Model A (RBAC)**: Checks if the subject has assigned roles matching the required permission. If no roles or permissions match, it terminates with `DENY` (`NoAssignedRoles` / `NoMatchingPermission`).
5. **Model B (RBAC + ABAC)**: Evaluates Model A first. If permitted, evaluates applicable ABAC rules across Subject, Resource, Environment, and Action scopes. If any required attribute is missing from the snapshot, evaluation terminates with `DENY` (`MissingAttribute`). If conditions fail, it returns `DENY` (`ConditionNotSatisfied`).
6. **Model C (Contextual Risk)**: Evaluates Model B first. If permitted, queries `IRiskContextProvider` for the request's `RiskContext`. `ContextualRiskEngine` calculates a normalized weighted risk score (0.00 to 1.00) across 5 risk signals. Missing signals default to conservative maximum risk (1.0 weight) and level `Unknown`, terminating with `DENY` (`MissingRiskContext`). Otherwise:
   - Score < 0.25: `ALLOW` (`LowContextualRisk`)
   - 0.25 <= Score < 0.50: `STEP_UP` (`AdditionalAssuranceRequired` with step-up verification obligation)
   - 0.50 <= Score < 0.75: `LIMIT` (`RateRestrictionRequired` with 10 req/min rate limit obligation)
   - Score >= 0.75: `DENY` (`HighContextualRisk`).
7. **Telemetry & Decision Audit**: `AuthorizationObservation` records OpenTelemetry trace activities and logs a structured JSON audit event containing a newly generated correlation ID, pseudonymized subject/resource/action identifiers, model identifier, processing duration, and reasons without mutating the decision outcome.

---

## 2. A/B/C baseline understanding

- **Model A (RBAC Baseline)**:
  Evaluates subject roles against static permission grants. Fails closed with `DENY` if the subject has no assigned roles or lacks matching permissions.
- **Model B (RBAC + ABAC)**:
  Requires an explicit Model A grant before evaluating contextual attributes (Subject, Resource, Environment, Action). Missing attributes or unmatched conditions result in strict denial (`MissingAttribute` takes precedence over condition failure).
- **Model C (Contextual Risk Assessment)**:
  Introduces a deterministic weighted risk score across 5 indicators (AuthenticationWeakness: 0.25, ResourceSensitivity: 0.25, OperationSensitivity: 0.20, NetworkExposure: 0.15, DeviceExposure: 0.15). Evaluated only after Model B succeeds. Returns non-binary decisions: `STEP_UP` (assurance challenge obligation), `LIMIT` (rate restriction obligation), or `DENY`.

---

## 3. Setup and .NET 8 prerequisites

- OS: Windows 11 (build 10.0.26200, 64-bit)
- .NET SDK & Runtimes:
  - Microsoft .NET SDK 8.0.427
  - Microsoft .NET Core Runtime 8.0.33
  - Microsoft ASP.NET Core Runtime 8.0.33
  - Microsoft Windows Desktop Runtime 8.0.33
- Prerequisites verification:
  - Verified with `dotnet --info`.
  - Executed clean `dotnet restore`, `dotnet build AeglysAI.sln -c Release --no-restore`, and `dotnet test AeglysAI.sln -c Release --no-build`.

---

## 4. One technical observation

### Observation: Correlation Isolation & Pseudonymization in the Audit Pipeline
Examining `AuthorizationObservation.cs` and `AuthorizationAuditTests.cs` reveals two notable security mechanisms alongside an architectural limitation:
1. **Correlation Spoofing Defense**: `AuthorizationObservation` explicitly ignores any client-supplied `X-Correlation-ID` or tracking headers, generating a fresh `Guid.NewGuid().ToString("N")` per evaluation. This prevents malicious clients or compromised upstream proxies from injecting correlation canary tokens, spoofing trace identifiers, or polluting structured audit logs.
2. **Data Minimization via SHA-256 Pseudonymization**: Subject, resource, and action names are transformed using length-prefixed canonicalization (`$"{part.Length}:{part}"`) and hashed via `SHA256.HashData`. Raw identities and actions are never persisted in the audit event.
3. **Limitation (Unsalted Low-Entropy Pseudonyms & Ephemeral Sink)**:
   - Because `Pseudonym` uses bare unsalted SHA-256, low-entropy identifiers (such as common resource names like `"reports"`, `"identity"`, or actions like `"read"`, `"write"`) can be trivially reversed using offline dictionary attacks or precomputed rainbow tables.
   - Audit event emission is strictly best-effort: sink exceptions are caught and swallowed (incrementing `Failures` metric) to prevent audit failures from blocking authorization decisions. The baseline sink (`LoggingAuthorizationAuditSink`) writes to `ILogger` without a durable write-ahead log, queue, or transactional outbox.

### How Tested
- Tested via `AuthorizationAuditTests.Exactly_one_safe_event_matches_the_selected_model`, which sends canary header `X-Correlation-ID: credential-canary-do-not-log` and verifies that the canary is suppressed and replaced by a server-generated GUID.
- Verified that `audit.SubjectId`, `audit.ResourceId`, and `audit.ActionId` match `AuthorizationObservation.Pseudonym(...)` SHA-256 strings rather than raw values.
- Verified full test suite execution (168 tests passed, 0 failures).

### Limitations
- The in-memory audit sink does not survive process termination or container restarts.
- Pseudonymization protects high-entropy identifiers well, but provides weak confidentiality for low-cardinality dictionary terms without a keyed HMAC or rotating secret.

---

## 5. One proposed improvement

### Proposed Improvement: Keyed HMAC Pseudonymization and Asynchronous Resilient Audit Outbox
1. **Keyed Pseudonymization (HMAC-SHA256)**: Replace unsalted `SHA256` in `AuthorizationObservation.Pseudonym` with `HMACSHA256` using an application-managed rotating salt or secret key (injected via `IOptions<AuditSecurityOptions>`).
2. **Resilient Asynchronous Audit Outbox**: Implement an in-memory bounded channel / queue with an asynchronous background worker (`IHostedService`) that buffers audit events for `IAuthorizationAuditSink`. If downstream logging or storage experiences transient failures, events are buffered with configurable backpressure and dead-letter queue (DLQ) support rather than dropped.

### Engineering Value
1. **Dictionary Attack Defense**: Prevents adversaries from de-anonymizing low-entropy resource and action names from exported audit logs via rainbow tables.
2. **Audit Durability & High Availability**: Ensures decision evaluation remains high-throughput and non-blocking (< 1 ms latency) while protecting audit event integrity against transient logging sink disruptions.
3. **Clean Architecture Compliance**: Keeps cryptographic abstractions within Application/Infrastructure while injecting configuration options through the API layer.

### Validation Approach
1. **Unit Testing**:
   - Verify HMAC pseudonym generation matches expected outputs given a fixed test secret key.
   - Verify rainbow table resistance: identical resource names hashed with different keys yield distinct pseudonyms.
   - Verify channel capacity, backpressure handling, and graceful queue flushing upon host shutdown.
2. **Integration Testing**:
   - Introduce a simulated failing sink in `AuthorizationAuditTests` and assert that audit events are retained in the dead-letter buffer while the HTTP response continues to return HTTP 200 with the correct decision outcome.

---

## 6. Validation results: exact commands, environment, actual outcomes and limitations

### Exact Commands Run
```powershell
dotnet --info
dotnet restore AeglysAI.sln
dotnet build AeglysAI.sln -c Release --no-restore
dotnet test AeglysAI.sln -c Release --no-build
```

### Environment
- OS: Windows 11 (build 10.0.26200, 64-bit)
- .NET SDK: 8.0.427
- .NET Core Runtime: 8.0.33
- ASP.NET Core Runtime: 8.0.33
- Configuration: Release

### Actual Outcomes
- **Restore**: Completed successfully with all package assets verified.
- **Build**: Built successfully across all 11 solution projects with `0 Warning(s)`, `0 Error(s)`.
- **Test Execution**: All **168** tests passed (0 failed, 0 skipped):
  - `AeglysAI.Application.Tests`: 53 passed, 0 failed (duration: 145 ms)
  - `AeglysAI.IntegrationTests`: 93 passed, 0 failed (duration: 21 s)
  - `AeglysAI.Domain.Tests`: 14 passed, 0 failed (duration: 128 ms)
  - `AeglysAI.ArchitectureTests`: 4 passed, 0 failed (duration: 15 ms)
  - `AeglysAI.Experiments.Tests`: 4 passed, 0 failed (duration: 344 ms)
  - **Total**: 168 passed, 0 failed, 0 skipped.

### Limitations
- In-memory mock providers and Development trust fixtures were used for evaluation; live OIDC and database providers remain planned.
- Tests do not cover distributed durable logging exporters.

---

## 7. Sanitized build/run/test evidence location

- Local qualification log: `community/qualification/build-test-evidence.txt`
- Repository file URL: https://github.com/krishna-patil9/AeglysAI/blob/qualification/krishna-patil9/community/qualification/build-test-evidence.txt
- Raw sanitized log URL: https://raw.githubusercontent.com/krishna-patil9/AeglysAI/qualification/krishna-patil9/community/qualification/build-test-evidence.txt
