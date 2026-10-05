# GitVersion Security Audit - Executive Summary

## Quick Reference

**Audit Date:** October 5, 2026  
**Scope:** GitVersion `src/` directory (legacy CLI and output generators)  
**Findings:** 12 injection vulnerabilities identified  
**Severity:** 2 CRITICAL, 5 HIGH, 5 MEDIUM-HIGH

---

## Critical Vulnerabilities (Immediate Action Required)

### 1. Source Code Generation - Remote Code Injection
- **Affected Files:** `GitVersionInformation.cs` (line 53), `AssemblyInfoFileUpdater.cs` (lines 67-83)
- **Risk:** Attacker-controlled branch names or commit messages can inject arbitrary C#/VB.NET/F# code into generated source files
- **Attack Vector:** Git branch name like `feature/"; throw new Exception("pwned`
- **Impact:** Arbitrary .NET code execution during build process
- **CVSS Estimated:** 9.0+ (Code Injection)

### 2. Shell Script Injection - RCE on Build Agents  
- **Affected File:** `BitBucketPipelines.cs` (lines 57-59) 
- **Risk:** Bash export statements without quoting allow shell metacharacter escape
- **Attack Vector:** Branch name like `master'; rm -rf /; echo '`
- **Impact:** Remote Code Execution with build agent privileges
- **CVSS Estimated:** 9.1 (CWE-94: Improper Control of Generation of Code)

### 3. PowerShell Code Injection - RCE on Windows Agents
- **Affected File:** `BitBucketPipelines.cs` (lines 61-63)
- **Risk:** Double-quoted PowerShell strings allow variable expansion and command substitution
- **Attack Vector:** Version value like `master$(whoami)` or `master\$(pwsh -c 'net user attacker pass /add')`
- **Impact:** Remote Code Execution on Windows build agents
- **CVSS Estimated:** 9.1

---

## High Priority Vulnerabilities (Fix Before Next Release)

### 4. Properties File Injection - Multi-Agent Compromise
- **Affected Files:** GitLabCi, Jenkins, Drone, CodeBuild (all lines 22-24)
- **Risk:** Unescaped newlines allow injecting new properties into build configuration
- **Attack Vector:** Branch name like `master\nGitVersion_Injected=malicious_value`
- **Impact:** Build configuration manipulation, credential injection, arbitrary environment variables
- **CVSS Estimated:** 8.2

### 5. WIX XML Injection - Installer Tampering
- **Affected File:** `WixVersionFileUpdater.cs` (lines 45-46)
- **Risk:** XML generated without escaping key and value elements
- **Attack Vector:** Branch name with XML special characters `< > " &` and XML injection sequences
- **Impact:** Malformed WIX configuration, modified installer behavior, supply chain attack vector
- **CVSS Estimated:** 7.8

### 6. JSON with Unsafe Escaping - XSS in Web Dashboards
- **Affected File:** `VersionVariablesJsonContext.cs` (line 16)
- **Risk:** Uses `JavaScriptEncoder.UnsafeRelaxedJsonEscaping` which doesn't escape HTML entities
- **Attack Vector:** Version value containing `<`, `>`, `&`, `'` characters that execute in web contexts
- **Impact:** Cross-Site Scripting (XSS) if JSON displayed in web-based build dashboards
- **CVSS Estimated:** 6.1

### 7. Regex Replacement Injection - Information Disclosure
- **Affected File:** `AzurePipelines.cs` (lines 62-70)
- **Risk:** Unescaped replacement string in regex operations
- **Attack Vector:** Version value containing `$&`, `$1` (regex backreferences)
- **Impact:** Build number manipulation, potential information leakage via group captures
- **CVSS Estimated:** 5.5

---

## Affected Build Systems

| Build System | Injection Type | Severity |
|---|---|---|
| BitBucketPipelines | Bash + PowerShell export | CRITICAL |
| GitLabCi | Properties file newlines | HIGH |
| Jenkins | Properties file newlines | HIGH |
| Drone | Properties file newlines | HIGH |
| CodeBuild | Properties file newlines | HIGH |
| AzurePipelines | Regex replacement | MEDIUM |
| TeamCity | (Properly escaped via ServiceMessageEscapeHelper) | SAFE ✓ |
| GitHub Actions | (Properly handled via GitHub env file protocol) | SAFE ✓ |
| All Agents | Generated source code files | CRITICAL |
| All Agents | Assembly attribute generation | CRITICAL |
| All Agents | WIX XML generation | HIGH |
| All Agents | JSON output with UnsafeEscaping | MEDIUM |

---

## Root Cause Analysis

### Why These Vulnerabilities Exist

1. **Assumption of Trust:** Code assumes Git repository metadata is "safe" because it comes from your own repo
   - Reality: Attackers can create branches with malicious names or forge commit messages

2. **Inconsistent Escaping:** Some build agents properly escape (TeamCity), others don't (7 others)
   - Indicates this was an oversight rather than intentional design

3. **String Interpolation Culture:** Prevalent use of C# string interpolation and `string.Format()`
   - Makes it easy to miss escaping requirements
   - Consider: Could use parameterized builders instead

4. **Template-Based Code Generation:** Formatting Git data into code templates without validation
   - No static validation that values are valid for their context

5. **External Dependency Trust:** Trusting user configuration values without validation
   - GitVersion.yml fields could contain injection payloads

---

## Recommended Remediation Strategy

### Immediate (Next Patch Release)
1. Escape shell metacharacters in BitBucketPipelines (CRITICAL)
2. Escape quotes in PowerShell variables (CRITICAL)
3. Escape quotes in generated C# code (CRITICAL)
4. Change `UnsafeRelaxedJsonEscaping` to `Default` encoder (MEDIUM, low-risk fix)

### Short Term (Next Minor Release)
1. Implement proper escaping for all properties-format build agents
2. Escape XML special characters in WIX generator
3. Use `Regex.Escape()` in Azure Pipelines regex replacement

### Long Term (Architectural)
1. Create centralized `ValueEscaper` service with escape functions for each output format
2. Add security unit tests for each build agent with injection payloads
3. Consider parameterized/builder APIs instead of string interpolation
4. Add YAML schema validation to prevent injection via configuration
5. Regular security audits when adding new output formats

---

## Files for Review

**Primary Finding Documents:**
1. `SECURITY_AUDIT_FINDINGS.md` - Summary of all 12 vulnerabilities with descriptions
2. `SECURITY_AUDIT_CODE_REFERENCES.md` - Detailed file:line references and code snippets

**Source Files With Vulnerabilities:**
- `src/GitVersion.Output/GitVersionInfo/GitVersionInfoGenerator.cs` — CRITICAL
- `src/GitVersion.Output/AssemblyInfo/AssemblyInfoFileUpdater.cs` — CRITICAL
- `src/GitVersion.BuildAgents/Agents/BitBucketPipelines.cs` — CRITICAL (2 vulns)
- `src/GitVersion.BuildAgents/Agents/GitLabCi.cs` — HIGH
- `src/GitVersion.BuildAgents/Agents/Jenkins.cs` — HIGH
- `src/GitVersion.BuildAgents/Agents/Drone.cs` — HIGH
- `src/GitVersion.BuildAgents/Agents/CodeBuild.cs` — HIGH
- `src/GitVersion.Output/WixUpdater/WixVersionFileUpdater.cs` — HIGH
- `src/GitVersion.Output/Serializer/VersionVariablesJsonContext.cs` — HIGH
- `src/GitVersion.BuildAgents/Agents/AzurePipelines.cs` — MEDIUM
- `src/GitVersion.BuildAgents/Agents/EnvRun.cs` — MEDIUM

---

## Testing Recommendations

### Proof-of-Concept Test Cases

#### Shell Injection (BitBucketPipelines)
```bash
# Setup: Create branch with injection payload
git checkout -b "master'; whoami > /tmp/pwned; echo '"

# Run GitVersion
dotnet run --project src/GitVersion.App

# Check: File should exist and contain output of 'whoami'
cat /tmp/pwned
```

#### C# Code Injection (Generated Assembly)
```bash
# Setup: Create branch
git checkout -b 'feature/"); throw Exception("injection'

# Run GitVersion
dotnet run --project src/GitVersion.App --output json

# Check: Generated source file contains invalid C# syntax
cat GitVersionInformation.cs | grep -i "throw"
```

#### Properties File Injection (Jenkins)
```bash
# Setup: Create branch
git checkout -b 'master
GitVersion_Injected=pwned'

# Run GitVersion
dotnet run --project src/GitVersion.App

# Check: gitversion.properties contains injected property
grep "Injected" gitversion.properties
```

---

## References

**CWE-related:**
- CWE-94: Improper Control of Generation of Code (Code Injection)
- CWE-77: Improper Neutralization of Special Elements used in a Command
- CWE-79: Improper Neutralization of Input During Web Page Generation (XSS)
- CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine
- CWE-116: Improper Encoding or Escaping of Output

**OWASP:**
- A03:2021 – Injection
- A06:2021 – Vulnerable and Outdated Components

**Related Advisories:**
- CVE-2021-25940 (Gitpod - Branch name code injection)
- CVE-2020-5410 (Spring Cloud - Build variable injection)
- CVE-2014-3856 (Jenkins - Properties file injection)

---

## Questions?

For detailed code references, see:
- `SECURITY_AUDIT_CODE_REFERENCES.md` - Line-by-line analysis with code snippets
- Individual vulnerability descriptions in `SECURITY_AUDIT_FINDINGS.md`
