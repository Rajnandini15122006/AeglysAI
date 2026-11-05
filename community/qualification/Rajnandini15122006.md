# AeglysAI qualification technical evidence

- Public fork URL: https://github.com/Rajnandini15122006/AeglysAI
- Qualification branch URL: https://github.com/Rajnandini15122006/AeglysAI/tree/qualification/Rajnandini15122006
- Exact base commit: `48047e46aee115181dc0fd67a45105a0b7a45a45`

---

## 1. Architecture: Domain, Application, Infrastructure, and API boundaries

AeglysAI implements Clean Architecture targeting .NET 8, where dependencies strictly point inward and core business rules remain independent of frameworks, external libraries, and infrastructure concerns:

- **AeglysAI.Domain**:
  The innermost layer with zero project or package dependencies. It defines fundamental security concepts, value objects, and domain entities:
  - Subject identity (`Subject` bound to subject identifier and issuer)
  - Resources and actions (`Resource`, `Action`, `Permission`)
  - RBAC structures (`Role`)
  - ABAC structures (`AbacRule`, `AttributeCondition`, `AttributeSet`, `AttributeScope`)
  - Risk models (`RiskContext`, `RiskSignal`)
  - Outcomes (`AuthorizationOutcome`: ALLOW, DENY, STEP_UP, LIMIT).

- **AeglysAI.Application**:
  Encapsulates core policy evaluation engines and business rules, depending only on `Domain`:
  - Identity abstraction (`ICurrentIdentity`, `AuthenticatedIdentity`)
  - Policy engines: `RbacAuthorizationEngine` (Model A), `ModelBAuthorizationEngine` (Model B: RBAC + ABAC), and `ModelCAuthorizationEngine` (Model C: Contextual Risk Engine)
  - Engine evaluation contracts and policy abstractions (`IAuthorizationEngine`, `IAbacEvaluator`, `IRbacPolicyProvider`, `IContextualRiskEngine`, `IRiskContextProvider`)
  - Audit definitions (`AuthorizationAuditEvent`).

- **AeglysAI.Infrastructure**:
  Implements domain and application interfaces using concrete in-memory and data-driven providers, depending on `Domain` and `Application`:
  - `InMemoryRbacPolicyProvider`
  - `InMemoryAbacContextProvider`
  - `InMemoryRiskContextProvider`.

- **AeglysAI.Api**:
  The entry point and composition root, depending on `Application` and `Infrastructure`:
  - Minimal API routing (`/health`, `/identity`, `/authorization/evaluate`, `/authorization/evaluate/model-b`, `/authorization/evaluate/model-c`)
  - JWT Bearer authentication setup and identity extraction (`HttpCurrentIdentity`)
  - Strongly typed input validation (`EvaluationInput` with disallowed unmapped JSON fields)
  - Structured logging and observability sinks (`AuthorizationObservation`, `LoggingAuthorizationAuditSink`)
  - Local development trust configuration for ephemeral public-key validation.

### Request and Decision Flow
1. **Client Request**: An HTTP request reaches the API with a signed JWT Bearer token and JSON payload specifying `{ "resource": "...", "action": "..." }`.
2. **Authentication Gate**: ASP.NET Core validates the JWT. `HttpCurrentIdentity` strictly extracts a single identity containing exactly one `sub` and one `iss` claim, constructing an immutable `Subject(sub, iss)`. If missing or invalid, evaluation terminates immediately with HTTP 401 Unauthorized.
3. **Payload Validation**: `EvaluationInput` enforces non-blank string inputs with a maximum length of 256 characters and rejects unmapped JSON properties.
4. **Model A Evaluation (RBAC)**: The request is mapped against `IRbacPolicyProvider`. If the subject has no assigned roles or lacks matching permissions, evaluation terminates with `DENY` (`NoAssignedRoles` or `NoMatchingPermission`).
5. **Model B Evaluation (RBAC + ABAC)**: Evaluates Model A first. If allowed, evaluates configured ABAC rules across Subject, Resource, Environment, and Action scopes. If any required attribute is missing, it evaluates to `DENY` (`MissingAttribute`). If conditions fail, it returns `DENY` (`ConditionNotSatisfied`).
6. **Model C Evaluation (Contextual Risk)**: Evaluates Model B first. If allowed, queries `IRiskContextProvider` for the request's `RiskContext`. `ContextualRiskEngine` computes a deterministic weighted score (0.00 to 1.00) across 5 risk signals. Missing signals default to conservative maximum weight (1.0) and flag `RiskLevel.Unknown`, resulting in `DENY` (`MissingRiskContext`). Otherwise:
   - Score < 0.25: `ALLOW` (`LowContextualRisk`)
   - 0.25 <= Score < 0.50: `STEP_UP` (`AdditionalAssuranceRequired` with challenge obligation)
   - 0.50 <= Score < 0.75: `LIMIT` (`RateRestrictionRequired` with rate limit obligation of 10 req/min)
   - Score >= 0.75: `DENY` (`HighContextualRisk`).
7. **Audit & Observability**: Every evaluation emits an OpenTelemetry activity and structured JSON audit event containing a unique correlation ID, subject pseudonym, timestamps, model version, and decision breakdown without mutating the decision.

---

## 2. A/B/C baseline understanding

- **Model A (Role-Based Access Control)**:
  Evaluates discrete permissions (`Resource` + `Action`) granted through assigned `Role`s configured on the server. Default policy has no grants and fails closed (`DENY`). No runtime environmental context or attributes are evaluated.
- **Model B (RBAC + Attribute-Based Access Control)**:
  Requires an explicit Model A grant before evaluating ABAC rules. ABAC attributes are server-owned snapshot fixtures categorized into Subject, Resource, and Environment scopes. Conditions must strictly match; missing attributes or unmatched rules default to `DENY` (`MissingAttribute` taking precedence over condition mismatches).
- **Model C (Deterministic Contextual Risk Assessment)**:
  Adds a fixed-weight heuristic risk calculation after Model B grants access. The risk engine assesses 5 weighted signals (AuthenticationWeakness: 0.25, ResourceSensitivity: 0.25, OperationSensitivity: 0.20, NetworkExposure: 0.15, DeviceExposure: 0.15). Missing signals conservatively escalate to maximum risk and level `Unknown`, which denies access. It introduces non-binary responses: `STEP_UP` (step-up verification obligation) and `LIMIT` (rate restriction obligation).

---

## 3. Setup and .NET 8 prerequisites

- Operating System: Windows 11 (build 10.0.26200, x64)
- Runtime & SDK:
  - Microsoft .NET SDK 8.0.427
  - Microsoft .NET Core Runtime 8.0.33
  - Microsoft ASP.NET Core Runtime 8.0.33
  - Microsoft Windows Desktop Runtime 8.0.33
- Prerequisites verification:
  - SDK installation managed via `dotnet-install.ps1` targeting .NET 8 channel.
  - Verification commands executed: `dotnet --info`, `dotnet restore AeglysAI.sln`, `dotnet build AeglysAI.sln -c Release --no-restore`, `dotnet test AeglysAI.sln -c Release --no-build`.

---

## 4. One technical observation

### Observation
In `src/AeglysAI.Application/Authorization/ContextualRiskEngine.cs` and `ModelCAuthorizationEngine.cs`:
1. **Semantic Taxonomy Divergence**: `ContextualRiskEngine` classifies risk scores into three discrete levels: `Low` (< 0.25), `Medium` (0.25 to < 0.50), and `High` (>= 0.50), plus `Unknown`. However, `ModelCAuthorizationEngine` maps decisions into four distinct outcomes: `ALLOW` (< 0.25), `STEP_UP` (0.25 to < 0.50), `LIMIT` (0.50 to < 0.75), and `DENY` (>= 0.75). Consequently, both `LIMIT` and `DENY` share the `RiskLevel.High` classification, meaning the risk taxonomy lacks an intermediate `Elevated` level corresponding to rate-restricted access.
2. **Conservative Fail-Closed Handling**: When any signal value in `RiskContext` is null, `ContextualRiskEngine` computes that contribution using `(value ?? 1m) * item.Weight` ("MissingContextConservativeMaximum") and marks the assessment level as `RiskLevel.Unknown`. `ModelCAuthorizationEngine` strictly inspects `assessment.Level == RiskLevel.Unknown` and immediately returns `DENY` with reason `MissingRiskContext`.
3. **Hard-coded Decision Boundaries**: The score thresholds (`0.25m`, `0.50m`, `0.75m`) and obligations (`VerifyStrongerAuthenticationAndReevaluate`, `EnforcePerSubjectResourceActionRateLimit` with fixed 10 req/min limit) are hard-coded directly in application engine code rather than configurable via options.

### How Tested
- Validated via `ContextualRiskTests.Exact_boundaries_control_levels_and_outcomes` where test cases `InlineData("0.50", RiskLevel.High, AuthorizationOutcome.LIMIT)` and `InlineData("0.75", RiskLevel.High, AuthorizationOutcome.DENY)` explicitly demonstrate `RiskLevel.High` mapping to two different outcomes.
- Validated via `ContextualRiskTests.Any_missing_signal_is_unknown_and_denied` verifying fail-closed denial on omitted signals.
- Validated via benchmark execution `dotnet run --project benchmarks/AeglysAI.Experiments -c Release -- --manifest research/experiments/smoke-v1.json`, which produced 2,400 Model C evaluations (300 ALLOW, 300 STEP_UP, 300 LIMIT, 1500 DENY) with 0 errors.

### Limitations
- The current implementation is an offline, in-memory heuristic simulator with static risk fixtures; it does not connect to live streaming telemetry or real-time behavioral scorers.
- `STEP_UP` and `LIMIT` outcomes are policy recommendations accompanied by obligation metadata, but the system currently contains no active challenge or rate-limiting enforcement gateway.

---

## 5. One proposed improvement

### Proposed Improvement: Configurable Risk Threshold Policy and Obligations via Options Pattern
Extract hard-coded risk score thresholds (`0.25m`, `0.50m`, `0.75m`), obligation action codes, and rate limits into an injectable options class (`RiskDecisionOptions`) adhering to the .NET Options Pattern (`IOptions<RiskDecisionOptions>`). Additionally, extend `RiskLevel` with an `Elevated` enum member so that `RiskLevel` aligns 1:1 with decision outcomes (`Low` -> `ALLOW`, `Medium` -> `STEP_UP`, `Elevated` -> `LIMIT`, `High` -> `DENY`, `Unknown` -> `DENY`).

### Engineering Value
1. **Configurable Policy Adaptation**: Different operational environments (e.g. low-risk internal tooling vs. high-assurance financial operations) require distinct risk appetites. A configurable options model allows tuning thresholds and rate limits via `appsettings.json` or environment variables without recompilation or code modifications.
2. **Taxonomic Clarity**: Adding `RiskLevel.Elevated` aligns risk classification with decision semantics, providing precise telemetry and audit records without conflating rate-restricted traffic with blocked high-risk traffic.
3. **Clean Architecture Adherence**: The options contract belongs in `AeglysAI.Application.Authorization`, while configuration binding remains in `AeglysAI.Api.Authorization`, preserving inward dependency rules and SOLID principles.

### Validation Approach
1. **Unit Testing**:
   - Test default options maintain exact backward compatibility with existing thresholds (`0.25`, `0.50`, `0.75`) and obligations.
   - Test custom configured options (e.g., threshold set at `0.10`, `0.30`, `0.60` with rate limit `25`) correctly alter decision boundaries.
   - Test configuration validation: ensure thresholds are monotonic (`LowThreshold < MediumThreshold < HighThreshold`) and between 0.0 and 1.0; throw descriptive validation exceptions on invalid configurations.
2. **Architecture and Integration Testing**:
   - Verify `AeglysAI.ArchitectureTests` continues to pass with no circular or forbidden dependencies.
   - Verify `ModelCEndpointTests` correctly reflects configured options in HTTP responses.

---

## 6. Validation results: exact commands, environment, actual outcomes and limitations

### Exact Commands Run
```powershell
dotnet --info
dotnet restore AeglysAI.sln
dotnet build AeglysAI.sln -c Release --no-restore
dotnet test AeglysAI.sln -c Release --no-build
dotnet run --project benchmarks/AeglysAI.Experiments -c Release -- --manifest research/experiments/smoke-v1.json
```

### Environment
- OS: Windows 11 (build 10.0.26200, 64-bit)
- .NET SDK: 8.0.427
- .NET Core Runtime: 8.0.33
- Build Configuration: Release

### Actual Outcomes
- **Restore**: Succeeded across all 11 projects in the solution.
- **Build**: Succeeded with `0 Warning(s)`, `0 Error(s)`.
- **Test Results**: All **168** tests passed across all 5 test assemblies:
  - `AeglysAI.Application.Tests`: 53 passed, 0 failed, 0 skipped (duration: 59 ms)
  - `AeglysAI.Experiments.Tests`: 4 passed, 0 failed, 0 skipped (duration: 71 ms)
  - `AeglysAI.Domain.Tests`: 14 passed, 0 failed, 0 skipped (duration: 50 ms)
  - `AeglysAI.ArchitectureTests`: 4 passed, 0 failed, 0 skipped (duration: 4 ms)
  - `AeglysAI.IntegrationTests`: 93 passed, 0 failed, 0 skipped (duration: 16 s)
  - **Total**: 168 passed, 0 failed, 0 skipped.
- **Benchmark / Smoke Experiment Run**:
  - Model A: 2,400 attempts, 2,400 completed, 0 errors, 339,760 decisions/sec, P50: 1.0 µs, P99: 7.1 µs (ALLOW: 1,800, DENY: 600)
  - Model B: 2,400 attempts, 2,400 completed, 0 errors, 193,261 decisions/sec, P50: 4.5 µs, P99: 16.8 µs (ALLOW: 1,500, DENY: 900)
  - Model C: 2,400 attempts, 2,400 completed, 0 errors, 98,789 decisions/sec, P50: 8.5 µs, P99: 26.6 µs (ALLOW: 300, STEP_UP: 300, LIMIT: 300, DENY: 1,500)

### Limitations
- Tests and benchmarks use synthetic in-memory fixtures; they do not measure production I/O or database latency.
- Local execution used Development trust; production Identity Provider (OIDC) integration remains planned.
- Obligations (`STEP_UP`, `LIMIT`) are evaluated but not enforced by an active gateway proxy.

---

## 7. Sanitized build/run/test evidence location

- Local qualification log: `community/qualification/build-test-evidence.txt`
- Repository file URL: https://github.com/Rajnandini15122006/AeglysAI/blob/qualification/Rajnandini15122006/community/qualification/build-test-evidence.txt
- Raw sanitized log URL: https://raw.githubusercontent.com/Rajnandini15122006/AeglysAI/qualification/Rajnandini15122006/community/qualification/build-test-evidence.txt
