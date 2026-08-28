[CmdletBinding()]
param(
    [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$directPullRequestHead = '${{ github.event.pull_request.head.sha }}'
$actionPattern = '^(?<action>[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*(?:/[A-Za-z0-9_.-]+)*)@(?<commit>[0-9a-f]{40})$'
$actionNamePattern = '^[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*(?:/[A-Za-z0-9_.-]+)*$'

if (-not (Get-Command ConvertFrom-Yaml -ErrorAction SilentlyContinue)) {
    throw 'ConvertFrom-Yaml is required for semantic validation; refusing a text-only fallback.'
}

function ConvertFrom-StrictYaml {
    param(
        [Parameter(Mandatory)]
        [string]$Content,

        [Parameter(Mandatory)]
        [string]$Source
    )

    try {
        $document = ConvertFrom-Yaml -Yaml $Content -Ordered -ErrorAction Stop
    }
    catch {
        throw "Unable to parse $Source as YAML: $($_.Exception.Message)"
    }

    if ($document -isnot [System.Collections.IDictionary]) {
        throw "$Source must contain one YAML mapping document."
    }

    return ,$document
}

function Get-UsesReference {
    param(
        [AllowNull()]
        [object]$Node,

        [string]$Path = ''
    )

    if ($Node -is [System.Collections.IDictionary]) {
        foreach ($key in $Node.Keys) {
            $childPath = if ($Path) { "$Path.$key" } else { [string]$key }
            if ([string]$key -ceq 'uses') {
                [pscustomobject]@{
                    Path = $childPath
                    Uses = [string]$Node[$key]
                    Parent = $Node
                }
            }
            Get-UsesReference -Node $Node[$key] -Path $childPath
        }
    }
    elseif ($Node -is [System.Collections.IEnumerable] -and $Node -isnot [string]) {
        $index = 0
        foreach ($item in $Node) {
            Get-UsesReference -Node $item -Path "$Path[$index]"
            $index++
        }
    }
}

function Test-MapKey {
    param(
        [AllowNull()]
        [object]$Map,

        [Parameter(Mandatory)]
        [string]$Key
    )

    return $Map -is [System.Collections.IDictionary] -and $Map.Contains($Key)
}

function Test-PullRequestTrigger {
    param(
        [AllowNull()]
        [object]$Triggers
    )

    if ($Triggers -is [System.Collections.IDictionary]) {
        return $Triggers.Contains('pull_request')
    }

    if ($Triggers -is [System.Collections.IEnumerable] -and $Triggers -isnot [string]) {
        return @($Triggers) -ccontains 'pull_request'
    }

    return [string]$Triggers -ceq 'pull_request'
}

function New-PinPolicy {
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Provenance
    )

    if (-not (Test-MapKey -Map $Provenance -Key 'actions')) {
        throw 'Provenance document is missing the actions list.'
    }

    $approved = [System.Collections.Generic.Dictionary[string, string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    $disabled = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    $known = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )

    foreach ($record in @($Provenance['actions'])) {
        if ($record -isnot [System.Collections.IDictionary]) {
            throw 'Each provenance action entry must be a mapping.'
        }

        foreach ($requiredKey in 'uses', 'disposition', 'commit', 'tree', 'verification', 'action', 'input_audit') {
            if (-not (Test-MapKey -Map $record -Key $requiredKey)) {
                throw "A provenance action entry is missing $requiredKey."
            }
        }

        $action = [string]$record['uses']
        $commit = [string]$record['commit']
        $disposition = [string]$record['disposition']

        if ($action -cnotmatch $actionNamePattern) {
            throw "Invalid provenance action name: $action"
        }
        if ($commit -cnotmatch '^[0-9a-f]{40}$') {
            throw "Invalid provenance commit for ${action}: $commit"
        }
        if (-not $known.Add($action)) {
            throw "Duplicate provenance action entry: $action"
        }

        switch -CaseSensitive ($disposition) {
            'approved' {
                $approved.Add($action, $commit)
            }
            'disabled' {
                $null = $disabled.Add($action)
            }
            default {
                throw "Unknown disposition for ${action}: $disposition"
            }
        }
    }

    return [pscustomobject]@{
        Approved = $approved
        Disabled = $disabled
    }
}

function Test-WorkflowDocument {
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Document,

        [Parameter(Mandatory)]
        [string]$Source,

        [Parameter(Mandatory)]
        [System.Collections.Generic.Dictionary[string, string]]$Approved,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.HashSet[string]]$Disabled,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.HashSet[string]]$UsedApproved
    )

    $findings = [System.Collections.Generic.List[string]]::new()
    $pullRequestWorkflow = (Test-MapKey -Map $Document -Key 'on') -and
        (Test-PullRequestTrigger -Triggers $Document['on'])

    foreach ($reference in @(Get-UsesReference -Node $Document)) {
        $value = $reference.Uses
        if ($value.StartsWith('./', [System.StringComparison]::Ordinal)) {
            continue
        }

        if ($pullRequestWorkflow -and
            $value.StartsWith('actions/checkout@', [System.StringComparison]::OrdinalIgnoreCase)) {
            $with = if (Test-MapKey -Map $reference.Parent -Key 'with') {
                $reference.Parent['with']
            }
            else {
                $null
            }
            $ref = if (Test-MapKey -Map $with -Key 'ref') {
                [string]$with['ref']
            }
            else {
                ''
            }

            if ($ref -cne $directPullRequestHead) {
                $findings.Add(
                    "${Source}:$($reference.Path) must bind ref directly to $directPullRequestHead; got '$ref'."
                )
            }
        }

        $match = [regex]::Match($value, $actionPattern)
        if (-not $match.Success) {
            $findings.Add("${Source}:$($reference.Path) is not an external action pinned to a lowercase 40-hex commit: $value")
            continue
        }

        $action = $match.Groups['action'].Value
        $commit = $match.Groups['commit'].Value

        if ($Disabled.Contains($action)) {
            $findings.Add("${Source}:$($reference.Path) references disabled action $action.")
            continue
        }

        $approvedCommit = ''
        if (-not $Approved.TryGetValue($action, [ref]$approvedCommit)) {
            $findings.Add("${Source}:$($reference.Path) has no approved provenance entry for $action.")
            continue
        }
        if ($commit -cne $approvedCommit) {
            $findings.Add("${Source}:$($reference.Path) pins $action to $commit instead of audited commit $approvedCommit.")
            continue
        }

        $null = $UsedApproved.Add($action)
    }

    return $findings.ToArray()
}

function Invoke-SelfTest {
    $commit = '1111111111111111111111111111111111111111'
    $provenanceYaml = @'
actions:
  - uses: actions/checkout
    disposition: approved
    commit: __COMMIT__
    tree: '2222222222222222222222222222222222222222'
    verification: { verified: true }
    action: { path: action.yml }
    input_audit: { status: compatible }
'@.Replace('__COMMIT__', $commit)
    $validWorkflowYaml = @'
name: test
on:
  pull_request:
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@__COMMIT__
        with:
          ref: ${{ github.event.pull_request.head.sha }}
'@.Replace('__COMMIT__', $commit)

    $provenance = ConvertFrom-StrictYaml -Content $provenanceYaml -Source 'self-test provenance'
    $policy = New-PinPolicy -Provenance $provenance
    $used = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    $valid = ConvertFrom-StrictYaml -Content $validWorkflowYaml -Source 'valid self-test workflow'
    $validFindings = @(Test-WorkflowDocument -Document $valid -Source 'valid.yml' -Approved $policy.Approved -Disabled $policy.Disabled -UsedApproved $used)
    if ($validFindings.Count -ne 0) {
        throw "Valid self-test fixture failed: $($validFindings -join '; ')"
    }

    $floating = ConvertFrom-StrictYaml -Content $validWorkflowYaml.Replace("@$commit", '@v4') -Source 'floating-ref self-test workflow'
    $floatingFindings = @(Test-WorkflowDocument -Document $floating -Source 'floating.yml' -Approved $policy.Approved -Disabled $policy.Disabled -UsedApproved $used)
    if (-not ($floatingFindings -match 'not an external action pinned')) {
        throw 'Floating-ref self-test fixture was not rejected.'
    }

    $synthetic = ConvertFrom-StrictYaml -Content $validWorkflowYaml.Replace(
        '${{ github.event.pull_request.head.sha }}',
        'refs/pull/1/merge'
    ) -Source 'synthetic-merge self-test workflow'
    $syntheticFindings = @(Test-WorkflowDocument -Document $synthetic -Source 'synthetic.yml' -Approved $policy.Approved -Disabled $policy.Disabled -UsedApproved $used)
    if (-not ($syntheticFindings -match 'must bind ref directly')) {
        throw 'Synthetic-merge self-test fixture was not rejected.'
    }

    Write-Output 'Workflow action pin policy self-tests passed.'
}

if ($SelfTest) {
    Invoke-SelfTest
    return
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$provenancePath = Join-Path $repoRoot '.github\workflow-action-pins.yml'
$workflowDirectory = Join-Path $repoRoot '.github\workflows'

if (-not (Test-Path -LiteralPath $provenancePath -PathType Leaf)) {
    throw "Missing provenance document: $provenancePath"
}
if (-not (Test-Path -LiteralPath $workflowDirectory -PathType Container)) {
    throw "Missing workflow directory: $workflowDirectory"
}

$provenance = ConvertFrom-StrictYaml -Content (Get-Content -LiteralPath $provenancePath -Raw) -Source '.github/workflow-action-pins.yml'
$policy = New-PinPolicy -Provenance $provenance
$usedApproved = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase
)
$violations = [System.Collections.Generic.List[string]]::new()
$externalCount = 0
$workflowFiles = @(
    Get-ChildItem -LiteralPath $workflowDirectory -File |
        Where-Object { $_.Extension -in '.yml', '.yaml' } |
        Sort-Object Name
)

if ($workflowFiles.Count -eq 0) {
    throw "No workflow YAML files found in $workflowDirectory"
}

foreach ($file in $workflowFiles) {
    $relativePath = [System.IO.Path]::GetRelativePath($repoRoot, $file.FullName).Replace('\', '/')
    $document = ConvertFrom-StrictYaml -Content (Get-Content -LiteralPath $file.FullName -Raw) -Source $relativePath
    foreach ($reference in @(Get-UsesReference -Node $document)) {
        if (-not $reference.Uses.StartsWith('./', [System.StringComparison]::Ordinal)) {
            $externalCount++
        }
    }
    foreach ($finding in @(Test-WorkflowDocument -Document $document -Source $relativePath -Approved $policy.Approved -Disabled $policy.Disabled -UsedApproved $usedApproved)) {
        $violations.Add($finding)
    }
}

foreach ($action in $policy.Approved.Keys) {
    if (-not $usedApproved.Contains($action)) {
        $violations.Add("Approved provenance entry is not used by a workflow: $action")
    }
}

if ($violations.Count -ne 0) {
    foreach ($violation in $violations | Sort-Object -Unique) {
        Write-Output "ERROR: $violation"
    }
    throw "Workflow action pin policy failed with $($violations.Count) violation(s)."
}

Write-Output "Validated $($workflowFiles.Count) workflow files and $externalCount external action references against $($policy.Approved.Count) approved immutable pins."
