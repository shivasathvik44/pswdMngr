# VaultSync Dependency Management & Vulnerability Remediation Policy

## 1. Overview & Security Philosophy


As a security-sensitive password manager operating under a **Zero-Knowledge, Two-Credential, Defense-in-Depth** model, VaultSync maintains rigorous control over all external software dependencies across its ecosystem:

- **Backend Server** (FastAPI / SQLAlchemy / Argon2id / Cryptography)
- **Desktop Application** (PySide6 / Cryptography / Argon2id)
- **Android Mobile Application** (Jetpack Compose / BouncyCastle / AndroidX Security)
- **CI/CD Automation** (GitHub Actions / Dependabot)

Dependency management strictly prioritizes correctness, reproducibility, reviewability, and fail-closed vulnerability monitoring over automated convenience.

---

## 2. Dependency Inventory & Ecosystem Baseline

### 2.1 Python Backend Server

- **Manifest Path**: `server/pyproject.toml`
- **Lockfile Status**: Managed via standard PEP 621 declarative specification. Pinned lockfiles are decoupled from development editable installs to prevent conflicting resolution workflows across platforms.
- **Python Version Constraint**: Requires Python `>=3.12`.
- **Build System**: `setuptools>=68.0.0`, `wheel`.
- **Dependency Classification**:
  - **Runtime Dependencies**:
    - `fastapi>=0.110.0` (ASGI Web Framework)
    - `uvicorn[standard]>=0.28.0` (ASGI Production Server)
    - `pydantic>=2.6.0` (Data Validation & Model Schemas)
    - `pydantic-settings>=2.2.0` (Environment Settings Management)
    - `cryptography>=42.0.0` (Core Cryptographic Primitives & AES-GCM)
    - `argon2-cffi>=23.1.0` (Argon2id Key Derivation & Account Password Hashing)
    - `sqlalchemy>=2.0.0` (Database ORM & Query Construction)
    - `alembic>=1.13.0` (Database Schema Migrations)
  - **Development & Test Dependencies (`[project.optional-dependencies] dev`)**:
    - `pytest>=8.0.0` (Test Framework)
    - `httpx>=0.27.0` (Async HTTP Test Client)

### 2.2 Python Desktop Application

- **Manifest Path**: `desktop/pyproject.toml`
- **Lockfile Status**: Managed via standard PEP 621 declarative specification.
- **Python Version Constraint**: Requires Python `>=3.12`.
- **Build System**: `setuptools>=68.0.0`, `wheel`.
- **Dependency Classification**:
  - **Runtime Dependencies**:
    - `PySide6>=6.6.0` (Official Qt6 GUI Bindings)
    - `pydantic>=2.6.0` (Client-side Data Schemas)
    - `httpx>=0.27.0` (Client HTTP Communication with Sync Server)
    - `argon2-cffi>=23.1.0` (Client-side Argon2id Key Derivation)
    - `cryptography>=42.0.0` (AES-256-GCM Vault Record Encryption/Decryption)
  - **Development & Test Dependencies (`[project.optional-dependencies] dev`)**:
    - `pytest>=8.0.0` (Test Framework)
    - `pytest-qt>=4.4.0` (Headless Qt Test Plugin)

### 2.3 Android Mobile Client (Gradle / Kotlin)

- **Root Build Manifest**: `android/build.gradle.kts`
- **App Module Manifest**: `android/app/build.gradle.kts`
- **Settings Manifest**: `android/settings.gradle.kts`
- **Gradle Wrapper**: `android/gradle/wrapper/gradle-wrapper.properties` (Gradle `8.7`)
- **Version Catalogs**: None currently declared; versions are centralized directly in module Gradle DSL scripts.
- **Toolchain Requirements**:
  - **JDK**: Java 17 (`sourceCompatibility = JavaVersion.VERSION_17`, `targetCompatibility = JavaVersion.VERSION_17`, `jvmTarget = "17"`).
  - **Android Gradle Plugin (AGP)**: `8.5.2`
  - **Kotlin**: `2.0.0`
  - **Android SDK**: `compileSdk = 34`, `targetSdk = 34`, `minSdk = 26`.
- **Dependency Classification**:
  - **Runtime (Implementation)**:
    - `androidx.core:core-ktx:1.13.1` (AndroidX Core Extensions)
    - `androidx.lifecycle:lifecycle-runtime-ktx:2.8.3` (Lifecycle Runtime)
    - `androidx.lifecycle:lifecycle-viewmodel-compose:2.8.3` (Compose ViewModel Integration)
    - `androidx.activity:activity-compose:1.9.0` (Activity Compose Bindings)
    - `androidx.compose:compose-bom:2024.06.00` (Jetpack Compose Bill of Materials)
    - `androidx.compose.ui:ui`, `ui-graphics`, `ui-tooling-preview` (Compose UI Toolkit)
    - `androidx.compose.material3:material3`, `material-icons-extended` (Material 3 Components)
    - `androidx.navigation:navigation-compose:2.7.7` (Navigation Routing)
    - `org.bouncycastle:bcprov-jdk18on:1.78.1` (Cryptographic Provider: Argon2id, HKDF)
    - `androidx.security:security-crypto:1.1.0-alpha06` (Android Keystore / EncryptedSharedPreferences)
    - `androidx.biometric:biometric:1.1.0` (BiometricPrompt Authentication)
    - `androidx.room:room-runtime:2.6.1`, `room-ktx:2.6.1` (SQLite Database Layer)
    - `com.squareup.okhttp3:okhttp:4.12.0`, `logging-interceptor:4.12.0` (Networking)
    - `org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.3` (JSON Parsing)
    - `org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1` (Coroutines)
  - **Build & Annotation Processing**:
    - `androidx.room:room-compiler:2.6.1` (KAPT Room Code Generator)
  - **Testing**:
    - `junit:junit:4.13.2` (Unit Testing)
    - `org.jetbrains.kotlinx:kotlinx-coroutines-test:1.8.1` (Coroutines Test Dispatchers)
    - `com.squareup.okhttp3:mockwebserver:4.12.0` (Mock HTTP Server)
    - `org.json:json:20240303` (JSON Test Doubles)
    - `androidx.room:room-testing:2.6.1` (Room Test Helpers)
    - `org.robolectric:robolectric:4.12.2` (Robolectric Android Simulation)
    - `androidx.test:core:1.6.1`, `androidx.test.ext:junit:1.2.1` (AndroidX Testing)
    - `androidx.test.espresso:espresso-core:3.6.1` (Espresso UI Instrumentation)
    - `androidx.compose.ui:ui-test-junit4` (Compose UI Instrumentation)
  - **Debug Only**:
    - `androidx.compose.ui:ui-tooling`, `ui-test-manifest`

### 2.4 GitHub Actions Workflows

- **Manifests**:
  - `.github/workflows/tests.yml` (Automated backend server and desktop client tests)
  - `.github/workflows/dependency-security.yml` (Continuous dependency auditing and policy enforcement)
  - `.github/workflows/codeql.yml` (CodeQL static application security testing for Python)
- **Action Pinning Policy**:
  Third-party GitHub Actions must be pinned to verified immutable 40-character commit SHAs with human-readable release tags preserved as trailing comments.
  - `actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2`
  - `actions/setup-python@0b93645e9fea7318ecaed2b359559ac225c90a2b # v5.3.0`
  - `actions/setup-java@8df1039502a15bceb9433410b1a100fbe190c53b # v4.5.0`
  - `actions/upload-artifact@b4b15b8c7c6ac21ea08fcf65892d2ee8f75cf882 # v4.4.3`
  - `github/codeql-action/init@b56ba49b26e50535fa1e7f7db0f4f7b4bf65d80d # v3.28.10`
  - `github/codeql-action/analyze@b56ba49b26e50535fa1e7f7db0f4f7b4bf65d80d # v3.28.10`

---

## 3. Dependency Resolution & Reproducibility Expectations

1. **Independent Package Ecosystems**:
   - The backend (`server`) and desktop client (`desktop`) maintain separate manifests because they target distinct runtime environments (headless cloud/container Linux vs desktop GUI with Qt6 bindings).
   - Installing either package does not contaminate or require the dependencies of the other.
2. **Installation Workflow**:
   - Local development and CI install packages via standard pip editable commands:
     ```bash
     pip install -e "server[dev]"
     pip install -e "desktop[dev]"
     ```
   - Lockfile mechanisms must not interfere with developer workflows or introduce incompatible binary wheel constraints for heterogeneous environments.
3. **Android Build Preservation**:
   - The Android toolchain strictly requires JDK 17 and AGP 8.5.2.
   - Upgrading Gradle wrapper, AGP, or Kotlin versions requires explicit verification against Android compile and runtime compatibility matrices.

---

## 4. Automated Dependency Update PRs (Dependabot)

Automated dependency updates are managed via `.github/dependabot.yml`.

### 4.1 Configured Ecosystems
1. **Python Backend**: `package-ecosystem: "pip"`, `directory: "/server"`
2. **Python Desktop**: `package-ecosystem: "pip"`, `directory: "/desktop"`
3. **Android Gradle**: `package-ecosystem: "gradle"`, `directory: "/android"`
4. **GitHub Actions**: `package-ecosystem: "github-actions"`, `directory: "/"`

### 4.2 Grouping and Review Strategy
- **Patch and Minor Updates**: Grouped into a single consolidated weekly PR per ecosystem to minimize PR fatigue.
- **Major Version Updates**: Deliberately excluded from grouping. Major version bumps generate isolated PRs to ensure mandatory security and breaking-change evaluation.
- **Schedule**: Weekly on Monday at 04:00 UTC.
- **Open PR Limit**: Capped at 5 open pull requests per ecosystem.
- **Safety Constraints**:
  - **No Automatic Merging**: Dependabot updates must never merge automatically.
  - **Required Reviews**: All dependency PRs require passing CI test and vulnerability scan gates alongside human peer review.

> [!NOTE]
> Dependabot PR generation requires GitHub repository-level enablement under **Settings > Code security and analysis > Dependabot**. Committed configuration files provide the specification, while GitHub repository infrastructure triggers execution.

---

## 5. Vulnerability Scanning Architecture

### 5.1 Python Ecosystem (`pip-audit`)

- **Scanner Tool**: `pip-audit`
- **Scanning Mode**: Audits the fully resolved package set (direct and transitive) against the Open Source Vulnerabilities (OSV) and PyPA advisory databases.
- **Policy Enforcement Script**: `scripts/vulnerability_scanner.py`
  - Parses `pyproject.toml` manifests to categorize direct dependencies as runtime, dev/test, or build.
  - Enriches scanner output with dependency context.
  - Cross-references findings against `docs/security/vulnerability-exceptions.json`.
  - Enforces remediation SLAs and flags expired exceptions as critical CI violations.
  - Generates machine-readable JSON reports alongside formatted Markdown summaries.
- **Failure Behavior**:
  - **Fail-Closed**: If `pip-audit` is unavailable, network resolution fails, or the advisory database is unreachable, the scanner terminates with exit code `2` (ERROR). Scanner execution errors are never treated as successful scans.

### 5.2 Android / Gradle Ecosystem

- **CI Implementation**: In GitHub Actions CI, Android dependencies are resolved using JDK 17 (`actions/setup-java@8df1039502a15bceb9433410b1a100fbe190c53b # v4.5.0`) to inspect the resolved dependency tree (`app:dependencies --configuration releaseRuntimeClasspath`).
- **Continuous Advisory Monitoring**: GitHub Dependabot Alerts natively monitors Gradle dependency declarations against the GitHub Advisory Database (GHSA) for Maven/Gradle packages.
- **Local Toolchain Limitation & Blocker**:
  - **JDK 25 Incompatibility**: Local workstation environments with OpenJDK 25 cannot execute AGP 8.5.2 tasks because AGP 8.5.2 only supports up to Java 21, failing with `compileSdkVersion is not specified` during Android plugin initialization.
  - **Remediation**: Android Gradle scanning must run under JDK 17 in CI or in a dedicated container with a compatible JDK 17 runtime.

### 5.3 Continuous Integration Pipeline

Workflow `.github/workflows/dependency-security.yml`:
- Triggered on push to `main`, pull requests modifying dependency-relevant paths, weekly schedule, and manual dispatch.
- Employs least-privilege permissions: `permissions: contents: read`.
- Publishes machine-readable JSON reports (`server-audit-report.json`, `desktop-audit-report.json`) as CI artifacts with 14-day retention.

---

## 6. Remediation Targets & SLAs

From the date and time a vulnerability is confirmed:

| Severity | Triage Target | Remediation / Mitigation Target |
|---|---|---|
| **Critical** | Within **24 hours** | Mitigate or remediate within **72 hours** |
| **High** | Within **3 business days** | Remediate within **7 calendar days** |
| **Medium** | Within **14 calendar days** | Remediate within **30 calendar days** |
| **Low** | Within **30 calendar days** | Remediate within **90 calendar days** |

*Note: These represent project policy targets and operational standards.*

---

## 7. Exception Policy & Review Process

When an immediate patch is unavailable or an upgrade would introduce critical breaking changes, a temporary, time-bounded exception may be approved.

### 7.1 Mandatory Exception Requirements
Every exception must be recorded in `docs/security/vulnerability-exceptions.json` with all required fields:
1. `id`: Unique exception tracking identifier (e.g., `EXP-2026-001`).
2. `package`: Exact lowercase package name.
3. `advisory_id`: Primary advisory identifier (GHSA or CVE).
4. `severity`: Evaluated severity rating (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
5. `ecosystem`: Target ecosystem (`pip`, `gradle`, `actions`).
6. `context`: Dependency category (`runtime`, `dev`, `build`, `transitive`).
7. `justification`: Detailed technical explanation of risk evaluation and reachability analysis.
8. `compensating_controls`: Specific controls preventing exploitation (e.g., reverse proxy boundary, memory isolation).
9. `owner`: Named individual or security role accountable for tracking.
10. `created_at`: ISO 8601 creation date (`YYYY-MM-DD`).
11. `expires_at`: ISO 8601 expiration date (`YYYY-MM-DD`), not exceeding 90 days.
12. `planned_remediation`: Concrete remediation roadmap or upstream tracking link.

### 7.2 Strict Expiration Enforcement
- **Expired Exceptions Fail CI**: The vulnerability scanner (`scripts/vulnerability_scanner.py`) automatically evaluates `expires_at` against the current date.
- If an exception has passed its expiration date, it is classified as `EXPIRED_EXCEPTION`, and CI terminates with exit code `1` (FAIL).
- Exceptions cannot be renewed without re-triage and explicit updated risk acceptance.

### 7.3 Handling Unfixable Vulnerabilities
When an advisory has no upstream patch available:
1. **Path & Exposure Analysis**: Confirm whether vulnerable routines are imported or reachable from VaultSync code.
2. **Context Distinction**: Evaluate if the issue affects production runtime or is confined to development/test environments.
3. **Mitigations & Compensating Controls**: Implement input sanitization, body size limits, network proxy isolation, or feature toggling.
4. **Alternative Evaluation**: If reachability exists and exposure cannot be mitigated, evaluate replacing the library.
5. **Tracking**: Register a 30-day bounded exception in `docs/security/vulnerability-exceptions.json` and monitor upstream release trackers.

---

## 8. GitHub Security Settings (Administrator Configuration)

The following security features require one-time configuration by a repository administrator in GitHub web settings:

1. **Dependency Graph**:
   - Location: **Settings > Code security and analysis > Dependency graph**
   - Status: Enable. Generates dependency manifests for SBOM and supply chain analysis.
2. **Dependabot Alerts**:
   - Location: **Settings > Code security and analysis > Dependabot alerts**
   - Status: Enable. Continuously notifies of known vulnerabilities in tracked dependencies.
3. **Dependabot Security Updates**:
   - Location: **Settings > Code security and analysis > Dependabot security updates**
   - Status: Enable. Automatically submits automated pull requests to patch vulnerable dependencies.
4. **Secret Scanning & Push Protection**:
   - Location: **Settings > Code security and analysis > Secret scanning**
   - Status: Enable. Blocks accidental commits of API tokens, private keys, or passwords.

---

## 9. Branch Protection Ruleset & Required Status Checks

To protect the integrity of the `main` branch, repository administrators should configure branch rulesets (**Settings > Rules > Rulesets > New branch ruleset**):

### 9.1 Ruleset Policies
- **Target Branch**: `default` (or pattern `main`)
- **Enforcement Status**: Active
- **Restrict Deletions**: Enabled (prevents accidental or malicious branch deletion)
- **Block Force Pushes**: Enabled (disallows history rewriting)
- **Require a Pull Request before Merging**: Enabled
  - Minimum approvals: At least 1 review
  - Dismiss stale pull request approvals when new commits are pushed
  - Require conversation resolution before merging
- **Do Not Allow Bypassing Above Settings**: Enabled (enforces parity across all contributors, including administrators)

### 9.2 Verified Required Status Checks
Based on configured GitHub Actions workflows, the exact status check names to require are:

| Status Check Name | Workflow Origin | Job Description |
|---|---|---|
| `Backend Server Tests (3.12)` | `.github/workflows/tests.yml` | Validates backend server tests on Python 3.12 |
| `Backend Server Tests (3.13)` | `.github/workflows/tests.yml` | Validates backend server tests on Python 3.13 |
| `Desktop Client Tests` | `.github/workflows/tests.yml` | Validates desktop client tests in headless mode |
| `Audit Python Backend Dependencies` | `.github/workflows/dependency-security.yml` | Audits server dependencies and enforces exception policy |
| `Audit Python Desktop Dependencies` | `.github/workflows/dependency-security.yml` | Audits desktop dependencies and enforces exception policy |
| `Analyze Python Code` | `.github/workflows/codeql.yml` | CodeQL static security analysis for Python code |

> [!NOTE]
> `Audit Android Gradle Dependencies` runs in `.github/workflows/dependency-security.yml` to resolve the Android dependency classpath under JDK 17. Because local host environments without Android SDK / JDK 17 cannot reproduce it locally, it is recommended to observe initial passing runs on GitHub Actions before adding it to mandatory blocking rules.

