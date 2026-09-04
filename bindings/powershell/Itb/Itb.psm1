# ITB PowerShell binding — thin proxy over the C# binding's Itb.dll
# assembly (../../csharp). Plain CLR interop via Add-Type: no FFI hop
# of its own; the C# binding carries the source-generated P/Invoke
# surface over the libitb ITB_Triple_* C ABI, including the P1
# BUFFER_TOO_SMALL retry and the native-library resolver. Every
# hash-name / MAC-name / cipher-name / profile-name is an opaque
# string passed through to Go for validation; the binding carries no
# ITB construction logic.
#
# PowerShell cannot hold ByRef-like values (ReadOnlySpan / Span);
# every C# entry consumed here returns byte[] / Profile / string
# values. Passing byte[] arguments INTO span-typed parameters
# (EncryptMessage, Load, Inspect, Rekey, session Write) is handled by
# the PowerShell binder natively.

Set-StrictMode -Version Latest

# --------------------------------------------------------------------
# Assembly load
# --------------------------------------------------------------------

function Script:Resolve-ItbAssembly {
    # Lookup order:
    #   1. ITB_CSHARP_DLL environment variable (path to Itb.dll).
    #   2. The sibling C# binding's Release then Debug output,
    #      relative to this module (in-repo builds).
    $candidates = [System.Collections.Generic.List[string]]::new()
    if ($env:ITB_CSHARP_DLL) {
        $candidates.Add($env:ITB_CSHARP_DLL)
    }
    foreach ($config in 'Release', 'Debug') {
        $glob = Join-Path $PSScriptRoot "../../csharp/Itb/bin/$config/net*/Itb.dll"
        foreach ($hit in (Get-Item -Path $glob -ErrorAction Ignore)) {
            $candidates.Add($hit.FullName)
        }
    }
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    throw ("Itb.dll not found. Build the C# binding first " +
        "(bindings/csharp/build.sh) or point ITB_CSHARP_DLL at the assembly.")
}

if (-not ('Itb.Pipeline' -as [type])) {
    Add-Type -Path (Script:Resolve-ItbAssembly)
}

# --------------------------------------------------------------------
# Private helpers
# --------------------------------------------------------------------

# Re-throws the Itb.ItbException buried inside PowerShell's
# MethodInvocationException wrapper so callers catch the structural
# status code directly ($_.Exception.Status).
function Script:Get-ItbInnerException {
    param([System.Management.Automation.ErrorRecord]$ErrorRecord)
    $exception = $ErrorRecord.Exception
    while ($null -ne $exception) {
        if ($exception -is [Itb.ItbException]) {
            return $exception
        }
        $exception = $exception.InnerException
    }
    return $ErrorRecord.Exception
}

# Accumulates pipeline/parameter input into a MemoryStream: byte[]
# fast path, strings as UTF-8, loose byte/object[] items element-wise.
function Script:Write-ItbSpool {
    param([System.IO.MemoryStream]$Spool, [object]$Item)
    if ($Item -is [byte[]]) {
        $Spool.Write($Item, 0, $Item.Length)
    }
    elseif ($Item -is [string]) {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Item)
        $Spool.Write($bytes, 0, $bytes.Length)
    }
    elseif ($Item -is [byte]) {
        $Spool.WriteByte($Item)
    }
    elseif ($Item -is [System.Collections.IEnumerable]) {
        $bytes = [byte[]]$Item
        $Spool.Write($bytes, 0, $bytes.Length)
    }
    else {
        $Spool.WriteByte([byte]$Item)
    }
}

# Normalizes the -Opts argument: $null passes through, Itb.Opts passes
# through, a hashtable is rendered via New-ItbOpts.
function Script:ConvertTo-ItbOpts {
    param([object]$Opts)
    if ($null -eq $Opts) {
        return $null
    }
    if ($Opts -is [Itb.Opts]) {
        return $Opts
    }
    if ($Opts -is [System.Collections.IDictionary]) {
        return (New-ItbOpts -Options $Opts)
    }
    throw 'Opts must be an [Itb.Opts], a hashtable, or $null.'
}

# Normalizes the -Profile argument: Itb.Profile passes through, a
# hashtable is rendered via New-ItbProfile.
function Script:ConvertTo-ItbProfile {
    param([object]$Profile)
    if ($Profile -is [Itb.Profile]) {
        return $Profile
    }
    if ($Profile -is [System.Collections.IDictionary]) {
        return (New-ItbProfile -Properties $Profile)
    }
    throw 'Profile must be an [Itb.Profile] or a hashtable.'
}

# Folds the optional master pair into the C# (permMaster, wrapMaster)
# arguments; both or neither.
function Script:Assert-ItbMasters {
    param([byte[]]$PermMaster, [byte[]]$WrapMaster)
    if (($null -eq $PermMaster) -ne ($null -eq $WrapMaster)) {
        throw 'PermMaster and WrapMaster must be supplied together or not at all.'
    }
}

# --------------------------------------------------------------------
# Opts
# --------------------------------------------------------------------

function New-ItbOpts {
    <#
    .SYNOPSIS
    Builds an [Itb.Opts] pass-through option set from a hashtable.
    .DESCRIPTION
    Every key/value pair is rendered into the URL-query opts string
    consumed by the Go side; no validation happens locally. Booleans
    render as true/false, byte arrays as lowercase hex (pm / wm
    masters), non-string enumerables comma-join (parallaxPalette,
    innerHashes), everything else stringifies invariantly. Use
    [ordered]@{} when key order matters for readability; the Go parser
    accepts keys in any order.
    #>
    [CmdletBinding()]
    [OutputType([Itb.Opts])]
    param(
        [Parameter(Position = 0)]
        [System.Collections.IDictionary]$Options
    )
    $opts = [Itb.Opts]::new()
    if ($null -ne $Options) {
        foreach ($key in $Options.Keys) {
            $value = $Options[$key]
            if ($value -is [bool]) {
                $rendered = if ($value) { 'true' } else { 'false' }
            }
            elseif ($value -is [byte[]]) {
                $rendered = [System.Convert]::ToHexStringLower([byte[]]$value)
            }
            elseif ($value -is [System.Collections.IEnumerable] -and $value -isnot [string]) {
                $rendered = @($value | ForEach-Object { [string]$_ }) -join ','
            }
            else {
                $rendered = [string]$value
            }
            [void]$opts.WithRaw([string]$key, $rendered)
        }
    }
    $opts
}

# --------------------------------------------------------------------
# Profile records
# --------------------------------------------------------------------

function New-ItbProfile {
    <#
    .SYNOPSIS
    Builds an [Itb.Profile] record from a hashtable.
    .DESCRIPTION
    Keys are the record's property names (Name, Mode, Width, Hash,
    Hashes, KeyBits, Mac, TagStub, Chunk, Wrapper, Outer, Parallax,
    Palette, Segment); values are assigned as-is. No validation
    happens locally — the Go side enforces every field rule at
    Register-ItbProfile / Import-ItbPipeline time.
    .EXAMPLE
    $p = New-ItbProfile @{ Mode = 'singlemsg-nomac'; Width = 512; Hash = 'areion512'; KeyBits = 1024 }
    #>
    [CmdletBinding()]
    [OutputType([Itb.Profile])]
    param(
        [Parameter(Position = 0)]
        [System.Collections.IDictionary]$Properties
    )
    $profile = [Itb.Profile]::new()
    if ($null -ne $Properties) {
        foreach ($key in $Properties.Keys) {
            $value = $Properties[$key]
            if ($value -is [System.Collections.IEnumerable] -and $value -isnot [string]) {
                $value = [string[]]@($value | ForEach-Object { [string]$_ })
            }
            $profile.$key = $value
        }
    }
    $profile
}

function Get-ItbProfile {
    <#
    .SYNOPSIS
    Reads a profile record by registry name or from a session blob.
    .DESCRIPTION
    -Name wraps [Itb.Pipeline]::Lookup (an unknown name fails with
    Status UnknownProfile). -Blob wraps [Itb.Pipeline]::Inspect —
    the blob's embedded record is decoded without opening a Pipeline.
    .EXAMPLE
    (Get-ItbProfile -Name 'singlemsg-triple-mac-v1').Mode
    .EXAMPLE
    (Get-ItbProfile -Blob (Save-ItbPipeline $sender)).Name
    #>
    [CmdletBinding(DefaultParameterSetName = 'Name')]
    [OutputType([Itb.Profile])]
    param(
        [Parameter(ParameterSetName = 'Name', Mandatory, Position = 0)]
        [string]$Name,

        [Parameter(ParameterSetName = 'Blob', Mandatory)]
        [byte[]]$Blob
    )
    try {
        if ($PSCmdlet.ParameterSetName -eq 'Name') {
            [Itb.Pipeline]::Lookup($Name)
        }
        else {
            [Itb.Pipeline]::Inspect($Blob)
        }
    }
    catch [System.Management.Automation.MethodInvocationException] {
        throw (Script:Get-ItbInnerException $_)
    }
}

function Get-ItbProfileName {
    <#
    .SYNOPSIS
    Lists every registered profile name (shipped catalogue plus
    Register-ItbProfile additions), sorted.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param()
    try {
        [Itb.Pipeline]::Profiles()
    }
    catch [System.Management.Automation.MethodInvocationException] {
        throw (Script:Get-ItbInnerException $_)
    }
}

function Register-ItbProfile {
    <#
    .SYNOPSIS
    Registers a profile record under a user-chosen name.
    .DESCRIPTION
    Wraps [Itb.Pipeline]::Register. -Profile is an [Itb.Profile]
    (see Get-ItbProfile / New-ItbProfile) or a hashtable of record
    properties. Every field rule is validated by Go; a duplicate
    name fails with Status ProfileExists.
    .EXAMPLE
    $copy = Get-ItbProfile -Name 'singlemsg-triple-nomac-v1'; $copy.Name = ''
    Register-ItbProfile -Name 'my-copy' -Profile $copy
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Name,

        [Parameter(Mandatory, Position = 1)]
        [object]$Profile
    )
    try {
        [Itb.Pipeline]::Register($Name, (Script:ConvertTo-ItbProfile $Profile))
    }
    catch [System.Management.Automation.MethodInvocationException] {
        throw (Script:Get-ItbInnerException $_)
    }
}

# --------------------------------------------------------------------
# Pipeline lifecycle
# --------------------------------------------------------------------

function New-ItbPipeline {
    <#
    .SYNOPSIS
    Constructs a fresh Triple Pipeline against a named profile.
    .DESCRIPTION
    Wraps [Itb.Pipeline]::Init. The session blob for the receiver
    side is read with Save-ItbPipeline. Dispose deterministically with
    Close-ItbPipeline (or $pipeline.Dispose()); an undisposed Pipeline
    is reclaimed by the SafeHandle finalizer.
    .EXAMPLE
    $sender = New-ItbPipeline -Profile 'singlemsg-triple-mac-v1'
    #>
    [CmdletBinding()]
    [OutputType([Itb.Pipeline])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Profile,

        [Parameter(Position = 1)]
        [object]$Opts
    )
    try {
        [Itb.Pipeline]::Init($Profile, (Script:ConvertTo-ItbOpts $Opts))
    }
    catch [System.Management.Automation.MethodInvocationException] {
        throw (Script:Get-ItbInnerException $_)
    }
}

function Import-ItbPipeline {
    <#
    .SYNOPSIS
    Reconstructs a Pipeline from a session blob (receiver side).
    .DESCRIPTION
    -Blob wraps [Itb.Pipeline]::Load; -Path wraps
    [Itb.Pipeline]::LoadF (the file is read inside the library). The
    blob's embedded profile record is the sole structural source — no
    profile name, no opts. Omitting -PermMaster / -WrapMaster uses
    the blob-embedded masters; supplying both overrides them (they
    must be supplied together or not at all).
    .EXAMPLE
    $receiver = Import-ItbPipeline -Blob $blob
    .EXAMPLE
    $receiver = Import-ItbPipeline -Path session.blob
    #>
    [CmdletBinding(DefaultParameterSetName = 'Blob')]
    [OutputType([Itb.Pipeline])]
    param(
        [Parameter(ParameterSetName = 'Blob', Mandatory, Position = 0)]
        [byte[]]$Blob,

        [Parameter(ParameterSetName = 'Path', Mandatory)]
        [string]$Path,

        [byte[]]$PermMaster,

        [byte[]]$WrapMaster
    )
    Script:Assert-ItbMasters $PermMaster $WrapMaster
    try {
        if ($PSCmdlet.ParameterSetName -eq 'Blob') {
            [Itb.Pipeline]::Load($Blob, $PermMaster, $WrapMaster)
        }
        else {
            [Itb.Pipeline]::LoadF($Path, $PermMaster, $WrapMaster)
        }
    }
    catch [System.Management.Automation.MethodInvocationException] {
        throw (Script:Get-ItbInnerException $_)
    }
}

function Save-ItbPipeline {
    <#
    .SYNOPSIS
    Exports the Pipeline's current self-describing session blob.
    .DESCRIPTION
    Without -Path wraps Pipeline.Save and returns the blob as byte[]:
    the bytes New-ItbPipeline produced, the bytes Import-ItbPipeline
    re-marshalled, or the bytes of the latest Invoke-ItbRekey. With
    -Path wraps Pipeline.SaveF — the blob is written inside the
    library with mode 0600 (the containing directory must exist) and
    nothing is returned.
    .EXAMPLE
    $blob = Save-ItbPipeline -Pipeline $sender
    .EXAMPLE
    Save-ItbPipeline -Pipeline $sender -Path session.blob
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [Itb.Pipeline]$Pipeline,

        [string]$Path
    )
    process {
        try {
            if ($Path) {
                $Pipeline.SaveF($Path)
            }
            else {
                Write-Output -NoEnumerate ([byte[]]$Pipeline.Save())
            }
        }
        catch [System.Management.Automation.MethodInvocationException] {
            throw (Script:Get-ItbInnerException $_)
        }
    }
}

function Set-ItbMaxWorkers {
    <#
    .SYNOPSIS
    Sets the Pipeline's worker cap for every subsequent cipher call.
    .DESCRIPTION
    Wraps Pipeline.MaxWorkers. -Count is clamped, never rejected: 0 or
    negative selects auto (CPU count), values above 256 are treated
    as 256. Only the handle statuses raise (BadHandle / TripleClosed).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [Itb.Pipeline]$Pipeline,

        [Parameter(Mandatory, Position = 1)]
        [int]$Count
    )
    process {
        try {
            $Pipeline.MaxWorkers($Count)
        }
        catch [System.Management.Automation.MethodInvocationException] {
            throw (Script:Get-ItbInnerException $_)
        }
    }
}

function Invoke-ItbRekey {
    <#
    .SYNOPSIS
    Rotates the parallax + wrapper masters and returns the refreshed
    session blob.
    .DESCRIPTION
    Wraps Pipeline.Rekey. Must not run concurrently with cipher calls
    or open stream sessions on the same Pipeline.
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [Itb.Pipeline]$Pipeline,

        [Parameter(Mandatory)]
        [byte[]]$PermMaster,

        [Parameter(Mandatory)]
        [byte[]]$WrapMaster
    )
    try {
        Write-Output -NoEnumerate ([byte[]]$Pipeline.Rekey($PermMaster, $WrapMaster))
    }
    catch [System.Management.Automation.MethodInvocationException] {
        throw (Script:Get-ItbInnerException $_)
    }
}

function Close-ItbPipeline {
    <#
    .SYNOPSIS
    Zeroes the Pipeline's key material and releases the native handle.
    .DESCRIPTION
    Calls Pipeline.Close (Go-side key zeroing; idempotent) and then
    Dispose. With -KeepHandle only Close runs — the handle stays
    allocated and subsequent cipher calls fail with Status
    TripleClosed until the Pipeline is disposed.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [Itb.Pipeline]$Pipeline,

        [switch]$KeepHandle
    )
    process {
        try {
            $Pipeline.Close()
        }
        catch [System.Management.Automation.MethodInvocationException] {
            throw (Script:Get-ItbInnerException $_)
        }
        if (-not $KeepHandle) {
            $Pipeline.Dispose()
        }
    }
}

# --------------------------------------------------------------------
# Single Message cipher calls
# --------------------------------------------------------------------

function Invoke-ItbEncrypt {
    <#
    .SYNOPSIS
    Single Message encrypt: one call, one self-contained wire.
    .DESCRIPTION
    Wraps Pipeline.EncryptMessage. -Data accepts byte[] (fast path) or
    a string (UTF-8 encoded); pipeline input is accumulated first, so
    `,$bytes | Invoke-ItbEncrypt $pipe` works (note the leading comma
    keeping the array as one item).
    .EXAMPLE
    $wire = Invoke-ItbEncrypt -Pipeline $sender -Data 'any text or binary data'
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [Itb.Pipeline]$Pipeline,

        [Parameter(Mandatory, Position = 1, ValueFromPipeline)]
        [object]$Data
    )
    begin { $spool = [System.IO.MemoryStream]::new() }
    process { Script:Write-ItbSpool $spool $Data }
    end {
        $plain = $spool.ToArray()
        $spool.Dispose()
        try {
            Write-Output -NoEnumerate $Pipeline.EncryptMessage($plain)
        }
        catch [System.Management.Automation.MethodInvocationException] {
            throw (Script:Get-ItbInnerException $_)
        }
    }
}

function Invoke-ItbDecrypt {
    <#
    .SYNOPSIS
    Receive-side counterpart of Invoke-ItbEncrypt.
    .DESCRIPTION
    Wraps Pipeline.DecryptMessage; returns the plaintext as byte[]
    (decode text with [System.Text.Encoding]::UTF8.GetString).
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [Itb.Pipeline]$Pipeline,

        [Parameter(Mandatory, Position = 1, ValueFromPipeline)]
        [object]$Data
    )
    begin { $spool = [System.IO.MemoryStream]::new() }
    process { Script:Write-ItbSpool $spool $Data }
    end {
        $wire = $spool.ToArray()
        $spool.Dispose()
        try {
            Write-Output -NoEnumerate $Pipeline.DecryptMessage($wire)
        }
        catch [System.Management.Automation.MethodInvocationException] {
            throw (Script:Get-ItbInnerException $_)
        }
    }
}

# --------------------------------------------------------------------
# Stream cipher calls
# --------------------------------------------------------------------

function Invoke-ItbEncryptStream {
    <#
    .SYNOPSIS
    Stream-shape encrypt: one-shot bytes, file-to-file, or
    stream-to-stream.
    .DESCRIPTION
    -Data runs Pipeline.EncryptStreamOneShot and returns the wire as
    byte[]. -InFile/-OutFile and -Source/-Destination run the
    bounded-memory Pipeline.EncryptStreamPump (feed a block, drain
    available wire, repeat). For caller-driven loops use
    New-ItbEncryptStream.
    .EXAMPLE
    Invoke-ItbEncryptStream -Pipeline $sender -InFile big.bin -OutFile big.itb
    #>
    [CmdletBinding(DefaultParameterSetName = 'Data')]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [Itb.Pipeline]$Pipeline,

        [Parameter(ParameterSetName = 'Data', Mandatory, Position = 1, ValueFromPipeline)]
        [object]$Data,

        [Parameter(ParameterSetName = 'File', Mandatory)]
        [string]$InFile,

        [Parameter(ParameterSetName = 'File', Mandatory)]
        [string]$OutFile,

        [Parameter(ParameterSetName = 'Stream', Mandatory)]
        [System.IO.Stream]$Source,

        [Parameter(ParameterSetName = 'Stream', Mandatory)]
        [System.IO.Stream]$Destination
    )
    begin {
        $spool = if ($PSCmdlet.ParameterSetName -eq 'Data') {
            [System.IO.MemoryStream]::new()
        }
    }
    process {
        if ($PSCmdlet.ParameterSetName -eq 'Data') {
            Script:Write-ItbSpool $spool $Data
        }
    }
    end {
        try {
            switch ($PSCmdlet.ParameterSetName) {
                'Data' {
                    $plain = $spool.ToArray()
                    $spool.Dispose()
                    Write-Output -NoEnumerate $Pipeline.EncryptStreamOneShot($plain)
                }
                'File' {
                    $in = [System.IO.File]::OpenRead($InFile)
                    try {
                        $out = [System.IO.File]::Create($OutFile)
                        try { $Pipeline.EncryptStreamPump($in, $out) }
                        finally { $out.Dispose() }
                    }
                    finally { $in.Dispose() }
                }
                'Stream' {
                    $Pipeline.EncryptStreamPump($Source, $Destination)
                }
            }
        }
        catch [System.Management.Automation.MethodInvocationException] {
            throw (Script:Get-ItbInnerException $_)
        }
    }
}

function Invoke-ItbDecryptStream {
    <#
    .SYNOPSIS
    Receive-side counterpart of Invoke-ItbEncryptStream.
    .DESCRIPTION
    -Data runs Pipeline.DecryptStreamOneShot; -InFile/-OutFile and
    -Source/-Destination run Pipeline.DecryptStreamPump.
    Streaming-decrypt caveat: chunked Streaming AEAD verifies per
    chunk, so plaintext of verified chunks is released before a later
    chunk can fail authentication.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Data')]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [Itb.Pipeline]$Pipeline,

        [Parameter(ParameterSetName = 'Data', Mandatory, Position = 1, ValueFromPipeline)]
        [object]$Data,

        [Parameter(ParameterSetName = 'File', Mandatory)]
        [string]$InFile,

        [Parameter(ParameterSetName = 'File', Mandatory)]
        [string]$OutFile,

        [Parameter(ParameterSetName = 'Stream', Mandatory)]
        [System.IO.Stream]$Source,

        [Parameter(ParameterSetName = 'Stream', Mandatory)]
        [System.IO.Stream]$Destination
    )
    begin {
        $spool = if ($PSCmdlet.ParameterSetName -eq 'Data') {
            [System.IO.MemoryStream]::new()
        }
    }
    process {
        if ($PSCmdlet.ParameterSetName -eq 'Data') {
            Script:Write-ItbSpool $spool $Data
        }
    }
    end {
        try {
            switch ($PSCmdlet.ParameterSetName) {
                'Data' {
                    $wire = $spool.ToArray()
                    $spool.Dispose()
                    Write-Output -NoEnumerate $Pipeline.DecryptStreamOneShot($wire)
                }
                'File' {
                    $in = [System.IO.File]::OpenRead($InFile)
                    try {
                        $out = [System.IO.File]::Create($OutFile)
                        try { $Pipeline.DecryptStreamPump($in, $out) }
                        finally { $out.Dispose() }
                    }
                    finally { $in.Dispose() }
                }
                'Stream' {
                    $Pipeline.DecryptStreamPump($Source, $Destination)
                }
            }
        }
        catch [System.Management.Automation.MethodInvocationException] {
            throw (Script:Get-ItbInnerException $_)
        }
    }
}

function New-ItbEncryptStream {
    <#
    .SYNOPSIS
    Opens an incremental encrypt session (plaintext in, wire out).
    .DESCRIPTION
    Wraps Pipeline.BeginEncryptStream and returns the
    [Itb.EncryptStream] session for caller-driven loops:
    $session.Write($bytes), $session.End(),
    $session.Read($buf, [ref]$finished). Dispose cancels the session
    and frees the Go-side state.
    #>
    [CmdletBinding()]
    [OutputType([Itb.EncryptStream])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [Itb.Pipeline]$Pipeline
    )
    process {
        try {
            $Pipeline.BeginEncryptStream()
        }
        catch [System.Management.Automation.MethodInvocationException] {
            throw (Script:Get-ItbInnerException $_)
        }
    }
}

function New-ItbDecryptStream {
    <#
    .SYNOPSIS
    Opens an incremental decrypt session (wire in, plaintext out).
    .DESCRIPTION
    Wraps Pipeline.BeginDecryptStream; the returned
    [Itb.DecryptStream] mirrors the encrypt session's Write / End /
    Read surface.
    #>
    [CmdletBinding()]
    [OutputType([Itb.DecryptStream])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [Itb.Pipeline]$Pipeline
    )
    process {
        try {
            $Pipeline.BeginDecryptStream()
        }
        catch [System.Management.Automation.MethodInvocationException] {
            throw (Script:Get-ItbInnerException $_)
        }
    }
}

# --------------------------------------------------------------------
# Runtime knobs + version
# --------------------------------------------------------------------

function Get-ItbVersion {
    <#
    .SYNOPSIS
    Returns the libitb, C# binding, and PowerShell module versions.
    #>
    [CmdletBinding()]
    param()
    [pscustomobject]@{
        Library       = [Itb.Runtime]::Version()
        CSharpBinding = [Itb.Runtime]::BindingVersion
        Module        = (Get-Module Itb).Version.ToString()
    }
}

function Set-ItbMemoryLimit {
    <#
    .SYNOPSIS
    Sets the Go runtime's soft heap limit in bytes; returns the
    previous limit. A negative value queries without changing.
    #>
    [CmdletBinding()]
    [OutputType([long])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [long]$Bytes
    )
    [Itb.Runtime]::SetMemoryLimit($Bytes)
}

function Set-ItbGCPercent {
    <#
    .SYNOPSIS
    Sets the Go GC trigger percentage; returns the previous value. A
    negative value queries without changing.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [int]$Percent
    )
    [Itb.Runtime]::SetGCPercent($Percent)
}

Export-ModuleMember -Function @(
    'New-ItbOpts'
    'New-ItbProfile'
    'Get-ItbProfile'
    'Get-ItbProfileName'
    'Register-ItbProfile'
    'New-ItbPipeline'
    'Import-ItbPipeline'
    'Save-ItbPipeline'
    'Set-ItbMaxWorkers'
    'Invoke-ItbRekey'
    'Close-ItbPipeline'
    'Invoke-ItbEncrypt'
    'Invoke-ItbDecrypt'
    'Invoke-ItbEncryptStream'
    'Invoke-ItbDecryptStream'
    'New-ItbEncryptStream'
    'New-ItbDecryptStream'
    'Get-ItbVersion'
    'Set-ItbMemoryLimit'
    'Set-ItbGCPercent'
)
