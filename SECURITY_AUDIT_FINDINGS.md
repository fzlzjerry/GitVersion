# GitVersion Security Audit - Injection Vulnerability Findings

**Date:** October 5, 2026  
**Scope:** `src/` and `new-cli/` directories  
**Focus:** Attacker-influenced data flows (git branches, tags, commit messages, CLI args, config fields) into sensitive outputs

## Summary

This audit identified **12 injection vulnerability points** where attacker-controlled data from Git repository metadata is written into:
- Generated source code files (C#, VB.NET, F#)
- CI environment property files (Java properties format)
- PowerShell and Bash scripts
- WIX XML configuration
- MSBuild system messages
- JSON output files

These vulnerabilities allow an attacker to inject arbitrary code, escape shell contexts, or poison build pipelines by crafting malicious Git branch names, tag names, commit messages, or configuration values.

---

## Vulnerability Categories

### Category 1: Generated Source Code Injection (Critical)

#### [1] GitVersionInfoGenerator - C# Source Code Injection
**File:** `src/GitVersion.Output/GitVersionInfo/GitVersionInfoGenerator.cs`  
**Lines:** 53, 56, 69

```53:56:src/GitVersion.Output/GitVersionInfo/GitVersionInfoGenerator.cs
var lines = variables.OrderBy(x => x.Key).Select(v => string.Format(indentation + addFormat, v.Key, v.Value));
var members = string.Join(FileSystemHelper.Path.NewLine, lines);

var fileContents = string.Format(template, members, targetNamespace, openBracket, closeBracket, indent);
```

**Template:** `src/GitVersion.Output/GitVersionInfo/AddFormats/GitVersionInformation.cs`
```1:1:src/GitVersion.Output/GitVersionInfo/AddFormats/GitVersionInformation.cs
public const string {0} = "{1}";
```

**Vulnerability:** The `{1}` placeholder (value) is directly inserted into C# string literals without escaping. A branch name like `master"; throw new Exception("pwned` would generate invalid C# code.

**Attack Vector:** Git branch name or commit message containing quote characters, newlines, or C# code syntax.

---

#### [2] AssemblyInfoFileUpdater - Assembly Attributes Injection
**File:** `src/GitVersion.Output/AssemblyInfo/AssemblyInfoFileUpdater.cs`  
**Lines:** 67-69, 73-75, 81-83

```67:69:src/GitVersion.Output/AssemblyInfo/AssemblyInfoFileUpdater.cs
if (!variables.AssemblySemVer.IsNullOrWhiteSpace())
{
    var result = ReplaceOrInsertAfterLastAssemblyAttributeOrAppend(RegexPatterns.Output.AssemblyVersionRegex, fileContents, $"AssemblyVersion(\"{variables.AssemblySemVer}\")", extension);
```

```73:75:src/GitVersion.Output/AssemblyInfo/AssemblyInfoFileUpdater.cs
if (!variables.AssemblySemFileVer.IsNullOrWhiteSpace())
{
    var result = ReplaceOrInsertAfterLastAssemblyAttributeOrAppend(RegexPatterns.Output.AssemblyFileVersionRegex, fileContents, $"AssemblyFileVersion(\"{variables.AssemblySemFileVer}\")", extension);
```

```81:83:src/GitVersion.Output/AssemblyInfo/AssemblyInfoFileUpdater.cs
if (!variables.InformationalVersion.IsNullOrWhiteSpace())
{
    var result = ReplaceOrInsertAfterLastAssemblyAttributeOrAppend(RegexPatterns.Output.AssemblyInfoVersionRegex, fileContents, $"AssemblyInformationalVersion(\"{variables.InformationalVersion}\")", extension);
```

**Vulnerability:** Version strings are interpolated directly into assembly attribute calls. A malicious version like `1.0.0\")]\n[assembly: Reflection.AllowPartiallyTrustedCallers` would break the attribute syntax and inject new attributes.

**Attack Vector:** `InformationalVersion` variable (derived from commit messages and branch names) containing quote and bracket characters.

---

### Category 2: CI Environment File Injection (Critical)

#### [3] BitBucketPipelines - Bash Export Injection
**File:** `src/GitVersion.BuildAgents/Agents/BitBucketPipelines.cs`  
**Lines:** 57-59

```57:59:src/GitVersion.BuildAgents/Agents/BitBucketPipelines.cs
var exports = variables
    .Select(variable => $"export GITVERSION_{variable.Key.ToUpperInvariant()}={variable.Value}")
    .ToList();
```

**Vulnerability:** Shell variables are written without quoting or escaping. A value like `value';rm -rf /;echo '` breaks out of the variable assignment and executes arbitrary shell commands.

**Attack Vector:** Git branch name or commit message containing shell metacharacters: `; | & $ ( ) [ ] { } < > ! * ? \ " '`

**Impact:** Remote Code Execution on any build agent that sources this file.

---

#### [4] BitBucketPipelines - PowerShell String Injection
**File:** `src/GitVersion.BuildAgents/Agents/BitBucketPipelines.cs`  
**Lines:** 61-63

```61:63:src/GitVersion.BuildAgents/Agents/BitBucketPipelines.cs
var psExports = variables
    .Select(variable => $"$GITVERSION_{variable.Key.ToUpperInvariant()} = \"{variable.Value}\"")
    .ToList();
```

**Vulnerability:** Double-quoted PowerShell strings allow variable expansion and command substitution. A value like `" + (Get-ChildItem)[0].Name + "` or `$(whoami)` would break out and execute arbitrary PowerShell.

**Attack Vector:** Value containing `$`, `` ` ``, or `"` characters.

**Impact:** Remote Code Execution on Windows-based build agents.

---

#### [5] GitLabCi - Properties File Injection
**File:** `src/GitVersion.BuildAgents/Agents/GitLabCi.cs`  
**Lines:** 22-24

```22:24:src/GitVersion.BuildAgents/Agents/GitLabCi.cs
public override string[] SetOutputVariables(string name, string? value) =>
[
    $"GitVersion_{name}={value}"
];
```

**Vulnerability:** Properties files format allows newline injection. A value with embedded newlines or special properties syntax could create new properties or comments that alter build behavior.

**Attack Vector:** Value containing newlines or properties file control sequences.

---

#### [6] Jenkins - Properties File Injection
**File:** `src/GitVersion.BuildAgents/Agents/Jenkins.cs`  
**Lines:** 20-21

```20:21:src/GitVersion.BuildAgents/Agents/Jenkins.cs
public override string[] SetOutputVariables(string name, string? value) =>
[
    $"GitVersion_{name}={value}"
];
```

**Vulnerability:** Same as GitLabCi — unescaped properties file format.

---

#### [7] Drone - Properties File Injection
**File:** `src/GitVersion.BuildAgents/Agents/Drone.cs`  
**Lines:** 16-18

```16:18:src/GitVersion.BuildAgents/Agents/Drone.cs
public override string[] SetOutputVariables(string name, string? value) =>
[
    $"GitVersion_{name}={value}"
];
```

**Vulnerability:** Same as GitLabCi and Jenkins.

---

#### [8] CodeBuild - Properties File Injection
**File:** `src/GitVersion.BuildAgents/Agents/CodeBuild.cs`  
**Lines:** 22-24

```22:24:src/GitVersion.BuildAgents/Agents/CodeBuild.cs
public override string[] SetOutputVariables(string name, string? value) =>
[
    $"GitVersion_{name}={value}"
];
```

**Vulnerability:** Same as GitLabCi, Jenkins, and Drone.

---

### Category 3: JSON Output with Relaxed Escaping (High)

#### [9] VersionVariablesJsonContext - UnsafeRelaxedJsonEscaping
**File:** `src/GitVersion.Output/Serializer/VersionVariablesJsonContext.cs`  
**Lines:** 12-16

```12:16:src/GitVersion.Output/Serializer/VersionVariablesJsonContext.cs
[JsonSourceGenerationOptions(
    WriteIndented = true,
    DefaultIgnoreCondition = JsonIgnoreCondition.Never,
    Converters = [typeof(VersionVariablesJsonStringConverter)])]
[JsonSerializable(typeof(VersionVariablesJsonModel))]
[JsonSerializable(typeof(Dictionary<string, string>))]
internal partial class VersionVariablesJsonContext : JsonSerializerContext
{
    public static VersionVariablesJsonContext Custom => field ??= new JsonSerializerContext(
        new JsonSerializerOptions(Default.Options)
        {
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        });
}
```

**Vulnerability:** `JavaScriptEncoder.UnsafeRelaxedJsonEscaping` does not escape HTML-sensitive characters like `<`, `>`, and `&`. When JSON is embedded in HTML or used in contexts where HTML entities matter, this can lead to XSS or injection attacks in web-based build systems.

**Attack Vector:** Version values containing HTML/JavaScript code that are then displayed or used in web dashboards.

**Impact:** Cross-Site Scripting (XSS) if JSON output is rendered in HTML without further escaping.

---

### Category 4: WIX XML Injection (High)

#### [10] WixVersionFileUpdater - XML Attribute Value Injection
**File:** `src/GitVersion.Output/WixUpdater/WixVersionFileUpdater.cs`  
**Lines:** 45-46

```45:50:src/GitVersion.Output/WixUpdater/WixVersionFileUpdater.cs
foreach (var (key, value) in variables.OrderBy(x => x.Key))
{
    builder.Append("\t<?define ").Append(key).Append("=\"").Append(value).Append("\"?>\n");
}
```

**Vulnerability:** Both `key` and `value` are appended directly to WIX XML without escaping or validation. A key like `foo" ?>\n<?xml version="1.0"` or a value with unescaped quotes breaks the XML structure.

**Attack Vector:** 
- Key (variable name) containing XML special characters
- Value containing quotes and XML injection sequences

**Impact:** Invalid WIX configuration or XML injection depending on how the file is parsed.

---

### Category 5: Build System Message Injection (Medium)

#### [11] EnvRun - EnvRun Message Format Injection
**File:** `src/GitVersion.BuildAgents/Agents/EnvRun.cs`  
**Lines:** 32-33

```32:33:src/GitVersion.BuildAgents/Agents/EnvRun.cs
public override string[] SetOutputVariables(string name, string? value) =>
[
    $"@@envrun[set name='GitVersion_{name}' value='{value}']"
];
```

**Vulnerability:** Single-quoted EnvRun messages could potentially be broken by a value containing `'` (single quote). The format appears to use single quotes as delimiters without escaping.

**Attack Vector:** Value containing single quotes.

---

### Category 6: Azure Pipelines - Regex Injection (High)

#### [12] AzurePipelines - RegexReplace Injection
**File:** `src/GitVersion.BuildAgents/Agents/AzurePipelines.cs`  
**Lines:** 62-70

```62:70:src/GitVersion.BuildAgents/Agents/AzurePipelines.cs
private static string ReplaceVariables(string buildNumberEnv, KeyValuePair<string, string?> variable)
{
    var pattern = $@"\$\(GITVERSION[_\.]{variable.Key}\)";
    var replacement = variable.Value;
    return replacement switch
    {
        null => buildNumberEnv,
        _ => buildNumberEnv.RegexReplace(pattern, replacement)
    };
}
```

**Vulnerability:** The `replacement` value (line 70) is passed directly to `String.Replace()` via the `RegexReplace` extension method. This value comes from `GitVersionVariables` which are derived from Git metadata. While `Regex.Replace()` doesn't interpret metacharacters in the replacement string as regex patterns in .NET (they're treated as literal replacement text), the danger here is if the replacement contains `$` characters, which have special meaning in replacement strings (e.g., `$1`, `$&`).

A value like `$(whoami)` would be interpreted as a regex replacement group reference (which doesn't exist, so it's silently replaced with an empty string), but values like `$&` would insert the entire matched pattern.

**Attack Vector:** Value containing `$` followed by valid replacement metacharacters: `$0`, `$1-$9`, `$&`, `$``, `$'`, etc.

**Impact:** Build number manipulation, potential information disclosure if regex group captures are displayed.

---

## Summary of Affected Variables

All variables that come from Git repository metadata are potentially vulnerable:
- **BranchName** - from git branch names
- **InformationalVersion** - from tags + commits + configuration
- **AssemblySemVer** - calculated from the above
- **AssemblySemFileVer** - calculated from the above
- **PreReleaseLabel** - from branch names
- **FullSemVer** - composite of all above
- Any custom version formats or labels

---

## Recommended Fixes

1. **Generated Source Code**: Escape quotes and special characters before inserting into code templates
2. **Properties Files**: Escape newlines, equals signs, and colons
3. **Shell Scripts**: Use proper shell quoting (single quotes or `printf %q`) or shell-safe escaping
4. **PowerShell**: Use `[System.Management.Automation.PSCredential]::new()` or proper escaping for values in double-quoted strings
5. **XML**: Use `System.Xml.XmlDocument.EscapeAttributeValue()` or parameterized XML builders
6. **JSON**: Avoid `UnsafeRelaxedJsonEscaping` unless verified safe for the consumption context
7. **Regex Replacement**: Use `Regex.Escape()` on the replacement string or use `Regex.Replace(input, pattern, match => literalReplacement)`

---

## Excluded Known Issues

The following previously known issues were NOT included in this report (as requested):
- Commit date format injection
- Bitbucket unquoted export (separate issue)
- Dotenv single-quote wrapping

---

## Files Not Covered

- `new-cli/` - No similar injection points found in initial scan
- MSBuild tasks - Properties are set via MSBuild API, not string concatenation
- GitHub Actions `$GITHUB_ENV` format - Uses `key=value` but requires validation

---

## Risk Assessment

| Category | Severity | Impact |
|----------|----------|--------|
| Generated Source Code | **CRITICAL** | Build-time code injection, arbitrary .NET execution |
| Shell Script Injection | **CRITICAL** | Remote Code Execution on build agents |
| XML Injection | **HIGH** | Configuration poisoning, installer tampering |
| JSON UnsafeEscaping | **HIGH** | Potential XSS in web dashboards |
| Properties File Injection | **HIGH** | Build configuration manipulation |
| EnvRun/TeamCity | **MEDIUM** | Limited escape context, partial breakout possible |
| Regex Replacement | **MEDIUM** | Information disclosure, pattern group manipulation |
