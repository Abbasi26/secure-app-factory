# Minimal YAML reader for app manifests. Block maps, block lists, scalars, and comments.
# Flow collections, anchors, and multiline scalars are rejected by not being implemented.

function Split-SafYamlKey {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Text,
        [Parameter(Mandatory = $true)]
        [int]$Line
    )

    if ($Text -notmatch '^([^:]+):(.*)$') {
        throw "Expected 'key: value' at line $Line."
    }

    $key = $Matches[1].Trim()
    $rest = $Matches[2]
    if ($rest.StartsWith(' ')) {
        $rest = $rest.Substring(1)
    }
    $rest = $rest.TrimEnd()
    if ([string]::IsNullOrWhiteSpace($key)) {
        throw "Empty key at line $Line."
    }

    $hasValue = $false
    if ($rest -eq '""' -or $rest -eq "''") {
        $hasValue = $true
    }
    elseif (-not [string]::IsNullOrWhiteSpace($rest)) {
        $hasValue = $true
    }
    else {
        $rest = ''
    }

    return [pscustomobject]@{
        Key = $key
        Rest = $rest
        Has = $hasValue
    }
}

function ConvertFrom-SafYamlDoubleQuoted {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Text
    )

    $builder = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $Text.Length; $i++) {
        $char = $Text[$i]
        if ($char -ne '\') {
            [void]$builder.Append($char)
            continue
        }
        if (($i + 1) -ge $Text.Length) {
            throw 'Dangling escape in a double-quoted string.'
        }
        $next = $Text[$i + 1]
        $i++
        switch ($next) {
            '\' { [void]$builder.Append('\') }
            '"' { [void]$builder.Append('"') }
            'n' { [void]$builder.Append("`n") }
            't' { [void]$builder.Append("`t") }
            default { throw "Unsupported escape in a double-quoted string." }
        }
    }
    return $builder.ToString()
}

function ConvertFrom-SafYamlScalar {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Text
    )

    if ($Text.Length -ge 2 -and $Text.StartsWith('"') -and $Text.EndsWith('"')) {
        return (ConvertFrom-SafYamlDoubleQuoted -Text $Text.Substring(1, $Text.Length - 2))
    }
    if ($Text.Length -ge 2 -and $Text.StartsWith("'") -and $Text.EndsWith("'")) {
        return (($Text.Substring(1, $Text.Length - 2)) -replace "''", "'")
    }
    switch ($Text) {
        'true' { return $true }
        'false' { return $false }
        'null' { return $null }
        '~' { return $null }
    }
    if ($Text -match '^-?(0|[1-9][0-9]*)$') {
        return [int64]$Text
    }
    return $Text
}

function Read-SafYamlMap {
    param(
        [Parameter(Mandatory = $true)]
        $State,
        [Parameter(Mandatory = $true)]
        [int]$Indent
    )

    $map = [ordered]@{}
    $items = $State.Items
    while ($State.Index -lt $items.Count) {
        $item = $items[$State.Index]
        if ($item.Indent -lt $Indent) { break }
        if ($item.Indent -gt $Indent) {
            throw "Unexpected indent at line $($item.Line)."
        }
        if ($item.Text.StartsWith('- ')) {
            throw "Expected a key at line $($item.Line)."
        }

        $State.Index++
        $split = Split-SafYamlKey -Text $item.Text -Line $item.Line
        if ($map.Contains($split.Key)) {
            throw "Duplicate key '$($split.Key)' at line $($item.Line)."
        }

        if ($split.Has) {
            $map[$split.Key] = ConvertFrom-SafYamlScalar -Text $split.Rest
            continue
        }

        if ($State.Index -lt $items.Count -and $items[$State.Index].Indent -gt $Indent) {
            $childIndent = $items[$State.Index].Indent
            if ($items[$State.Index].Text.StartsWith('- ')) {
                $map[$split.Key] = Read-SafYamlList -State $State -Indent $childIndent
            }
            else {
                $map[$split.Key] = Read-SafYamlMap -State $State -Indent $childIndent
            }
        }
        else {
            $map[$split.Key] = $null
        }
    }
    return $map
}

function Read-SafYamlList {
    param(
        [Parameter(Mandatory = $true)]
        $State,
        [Parameter(Mandatory = $true)]
        [int]$Indent
    )

    $list = New-Object System.Collections.Generic.List[object]
    $items = $State.Items
    while ($State.Index -lt $items.Count) {
        $item = $items[$State.Index]
        if ($item.Indent -lt $Indent) { break }
        if ($item.Indent -gt $Indent) {
            throw "Unexpected indent at line $($item.Line)."
        }
        if (-not $item.Text.StartsWith('- ')) {
            throw "Expected a list item at line $($item.Line)."
        }

        $State.Index++
        $payload = $item.Text.Substring(2).Trim()
        if ($payload.Length -eq 0) {
            if ($State.Index -lt $items.Count -and $items[$State.Index].Indent -gt $Indent) {
                $childIndent = $items[$State.Index].Indent
                if ($items[$State.Index].Text.StartsWith('- ')) {
                    $list.Add((Read-SafYamlList -State $State -Indent $childIndent))
                }
                else {
                    $list.Add((Read-SafYamlMap -State $State -Indent $childIndent))
                }
            }
            else {
                $list.Add($null)
            }
            continue
        }

        $isKey = $payload -match '^([^:]+):(\s.*)?$'
        if (-not $isKey) {
            $list.Add((ConvertFrom-SafYamlScalar -Text $payload))
            continue
        }

        $split = Split-SafYamlKey -Text $payload -Line $item.Line
        $entry = [ordered]@{}
        if ($split.Has) {
            $entry[$split.Key] = ConvertFrom-SafYamlScalar -Text $split.Rest
        }
        elseif ($State.Index -lt $items.Count -and $items[$State.Index].Indent -gt $Indent) {
            $childIndent = $items[$State.Index].Indent
            if ($items[$State.Index].Text.StartsWith('- ')) {
                $entry[$split.Key] = Read-SafYamlList -State $State -Indent $childIndent
            }
            else {
                $entry[$split.Key] = Read-SafYamlMap -State $State -Indent $childIndent
            }
        }
        else {
            $entry[$split.Key] = $null
        }

        if ($State.Index -lt $items.Count -and $items[$State.Index].Indent -gt $Indent -and -not $items[$State.Index].Text.StartsWith('- ')) {
            $contIndent = $items[$State.Index].Indent
            $rest = Read-SafYamlMap -State $State -Indent $contIndent
            foreach ($key in @($rest.Keys)) {
                if ($entry.Contains($key)) {
                    throw "Duplicate key '$key' in a list item near line $($item.Line)."
                }
                $entry[$key] = $rest[$key]
            }
        }
        $list.Add($entry)
    }
    return ,$list.ToArray()
}

function ConvertFrom-SafYaml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Yaml
    )

    if ($Yaml.Length -gt 0 -and [int][char]$Yaml[0] -eq 0xFEFF) {
        $Yaml = $Yaml.Substring(1)
    }

    $normalized = $Yaml.Replace("`r`n", "`n").Replace("`r", "`n")
    $rawLines = $normalized.Split([char]10)
    $items = New-Object System.Collections.Generic.List[object]
    $lineNo = 0
    foreach ($raw in $rawLines) {
        $lineNo++
        if ($raw -match '^\s*$') { continue }
        if ($raw -match '^\s*#') { continue }
        if ($raw.Contains("`t")) {
            throw "Tabs are not allowed (line $lineNo)."
        }
        if ($raw -notmatch '^(\s*)(\S.*)$') {
            throw "Unable to parse line $lineNo."
        }
        $items.Add([pscustomobject]@{
            Indent = $Matches[1].Length
            Text   = $Matches[2]
            Line   = $lineNo
        })
    }

    if ($items.Count -eq 0) {
        throw 'YAML is empty.'
    }
    if ($items[0].Indent -ne 0) {
        throw 'YAML root must start at column 0.'
    }
    if ($items[0].Text.StartsWith('- ')) {
        throw 'YAML root must be a map.'
    }

    $state = @{
        Items = $items
        Index = 0
    }
    $map = Read-SafYamlMap -State $state -Indent 0
    if ($state.Index -lt $items.Count) {
        throw "Unexpected content at line $($items[$state.Index].Line)."
    }
    return $map
}

function ConvertTo-SafData {
    param($Node)

    if ($null -eq $Node) {
        return $null
    }
    if ($Node -is [string] -or $Node -is [bool] -or $Node -is [int] -or $Node -is [long] -or $Node -is [double]) {
        return $Node
    }
    if ($Node -is [System.Collections.IDictionary]) {
        $hash = @{}
        foreach ($key in @($Node.Keys)) {
            $hash[$key] = ConvertTo-SafData -Node $Node[$key]
        }
        return [pscustomobject]$hash
    }
    if ($Node -is [System.Collections.IList]) {
        $list = New-Object System.Collections.Generic.List[object]
        foreach ($item in $Node) {
            $list.Add((ConvertTo-SafData -Node $item))
        }
        return ,$list.ToArray()
    }
    return $Node
}
