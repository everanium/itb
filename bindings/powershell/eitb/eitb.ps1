#!/usr/bin/env pwsh
# eitb — command-line demonstrator for the ITB PowerShell binding.
#
# Subcommands:
#
#   eitb.ps1 version                                   library + binding versions
#   eitb.ps1 hashes                                    shipped hash primitive roster
#   eitb.ps1 encrypt <profile> <in-file> <out-file>    Single Message encrypt
#   eitb.ps1 decrypt <profile> <blob-hex> <in-file> <out-file>
#
# `encrypt` prints the session blob to stderr as hex; feed that hex
# back to `decrypt` on the receiving side.
#
# The `hashes` diagnostic iterates the registry through the libitb
# C-ABI iteration surface directly (NativeLibrary function pointers
# over the same shared library the C# assembly loads) — the binding
# module itself deliberately exposes no primitive enumeration,
# mirroring the C# eitb's InternalsVisibleTo route.

[CmdletBinding()]
param(
    [Parameter(Position = 0)][string]$Command,
    [Parameter(Position = 1, ValueFromRemainingArguments)][string[]]$Rest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '../Itb/Itb.psd1') -Force

[void](Set-ItbMemoryLimit -Bytes (512MB))
[void](Set-ItbGCPercent -Percent 20)

function Show-Usage {
    [Console]::Error.WriteLine(@'
usage: eitb.ps1 version
       eitb.ps1 hashes
       eitb.ps1 encrypt <profile> <in-file> <out-file>
       eitb.ps1 decrypt <profile> <blob-hex> <in-file> <out-file>
'@)
    exit 2
}

function Resolve-LibItbPath {
    # Mirrors the C# NativeLoader lookup, minus the OS default loader
    # fallback (a concrete path is needed for the function-pointer
    # route):
    #   1. ITB_LIBITB_PATH environment variable.
    #   2. <repo>/dist/<os>-<arch>/libitb.<ext> located by walking up
    #      from this script's directory.
    if ($env:ITB_LIBITB_PATH -and (Test-Path -LiteralPath $env:ITB_LIBITB_PATH)) {
        return (Resolve-Path -LiteralPath $env:ITB_LIBITB_PATH).Path
    }
    $os = if ($IsWindows) { 'windows' } elseif ($IsMacOS) { 'darwin' } else { 'linux' }
    $arch = if ([System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -eq
        [System.Runtime.InteropServices.Architecture]::Arm64) { 'arm64' } else { 'amd64' }
    $ext = if ($IsWindows) { 'dll' } elseif ($IsMacOS) { 'dylib' } else { 'so' }
    $dir = Get-Item -LiteralPath $PSScriptRoot
    while ($null -ne $dir) {
        $candidate = Join-Path $dir.FullName "dist/$os-$arch/libitb.$ext"
        if (Test-Path -LiteralPath $candidate) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
        $dir = $dir.Parent
    }
    throw ('libitb shared library not found: set ITB_LIBITB_PATH or build it ' +
        '(bindings/powershell/build.sh).')
}

function Initialize-HashRegistry {
    if ('ItbPwshEitb.HashRegistry' -as [type]) {
        return
    }
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace ItbPwshEitb
{
    /// <summary>Function-pointer bridge to the libitb hash-registry
    /// iteration triple (diagnostic surface for the eitb CLI).</summary>
    public static class HashRegistry
    {
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int CountFn();
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int WidthFn(int i);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int NameFn(int i, byte[] buf, UIntPtr cap, out UIntPtr len);

        private static CountFn _count;
        private static WidthFn _width;
        private static NameFn _name;

        public static void Load(string libPath)
        {
            IntPtr handle = NativeLibrary.Load(libPath);
            _count = Marshal.GetDelegateForFunctionPointer<CountFn>(
                NativeLibrary.GetExport(handle, "ITB_HashCount"));
            _width = Marshal.GetDelegateForFunctionPointer<WidthFn>(
                NativeLibrary.GetExport(handle, "ITB_HashWidth"));
            _name = Marshal.GetDelegateForFunctionPointer<NameFn>(
                NativeLibrary.GetExport(handle, "ITB_HashName"));
        }

        public static int Count() { return _count(); }

        public static int Width(int i) { return _width(i); }

        public static string Name(int i)
        {
            // Two-phase read over the (out, cap, *outLen) C-string
            // contract: probe for the capacity, then read + NUL-strip.
            UIntPtr need;
            int rc = _name(i, null, UIntPtr.Zero, out need);
            if (rc != 0 && rc != 5)
            {
                throw new InvalidOperationException(
                    "ITB_HashName probe failed: status=" + rc);
            }
            if ((ulong)need <= 1)
            {
                return string.Empty;
            }
            byte[] buf = new byte[(int)(ulong)need];
            rc = _name(i, buf, (UIntPtr)buf.Length, out need);
            if (rc != 0)
            {
                throw new InvalidOperationException(
                    "ITB_HashName failed: status=" + rc);
            }
            int len = (ulong)need > 0 ? (int)(ulong)need - 1 : 0;
            return Encoding.UTF8.GetString(buf, 0, len);
        }
    }
}
'@
}

function Invoke-CmdVersion {
    $v = Get-ItbVersion
    Write-Output "libitb $($v.Library)"
    Write-Output "itb-csharp $($v.CSharpBinding)"
    Write-Output "itb-powershell $($v.Module)"
}

function Invoke-CmdHashes {
    Initialize-HashRegistry
    [ItbPwshEitb.HashRegistry]::Load((Resolve-LibItbPath))
    $count = [ItbPwshEitb.HashRegistry]::Count()
    for ($i = 0; $i -lt $count; $i++) {
        $name = [ItbPwshEitb.HashRegistry]::Name($i)
        $width = [ItbPwshEitb.HashRegistry]::Width($i)
        Write-Output ('{0,2}  {1,-12} {2} bits' -f $i, $name, $width)
    }
}

# Profiles whose canonical name begins with "streaming-" route
# through the one-shot streaming buffered pair instead of the Single
# Message pair.
function Test-StreamingProfile {
    param([string]$Profile)
    return $Profile.StartsWith('streaming-', [System.StringComparison]::Ordinal)
}

# Recursively create the parent directory of $Path (mkdir -p).
function Assert-ParentDir {
    param([string]$Path)
    $parent = Split-Path -Parent $Path
    if ($parent) {
        [void](New-Item -ItemType Directory -Force -Path $parent)
    }
}

function Invoke-CmdEncrypt {
    param([string]$Profile, [string]$InFile, [string]$OutFile)
    $plain = [System.IO.File]::ReadAllBytes($InFile)
    $pipe = New-ItbPipeline -Profile $Profile
    try {
        $wire = if (Test-StreamingProfile $Profile) {
            Invoke-ItbEncryptStream -Pipeline $pipe -Data $plain
        } else {
            Invoke-ItbEncrypt -Pipeline $pipe -Data $plain
        }
        Assert-ParentDir $OutFile
        [System.IO.File]::WriteAllBytes($OutFile, $wire)
        [Console]::Error.WriteLine(
            [System.Convert]::ToHexStringLower((Get-ItbBlob $pipe)))
        Write-Output ('encrypted {0} -> {1} ({2} -> {3} bytes)' -f `
                $InFile, $OutFile, $plain.Length, $wire.Length)
    }
    finally { $pipe.Dispose() }
}

function Invoke-CmdDecrypt {
    param([string]$Profile, [string]$BlobHex, [string]$InFile, [string]$OutFile)
    $blob = [System.Convert]::FromHexString($BlobHex)
    $wire = [System.IO.File]::ReadAllBytes($InFile)
    $pipe = Open-ItbPipeline -Profile $Profile -Blob $blob
    try {
        $plain = if (Test-StreamingProfile $Profile) {
            Invoke-ItbDecryptStream -Pipeline $pipe -Data $wire
        } else {
            Invoke-ItbDecrypt -Pipeline $pipe -Data $wire
        }
        Assert-ParentDir $OutFile
        [System.IO.File]::WriteAllBytes($OutFile, $plain)
        Write-Output ('decrypted {0} -> {1} ({2} -> {3} bytes)' -f `
                $InFile, $OutFile, $wire.Length, $plain.Length)
    }
    finally { $pipe.Dispose() }
}

try {
    $restCount = if ($null -ne $Rest) { $Rest.Count } else { 0 }
    switch ($Command) {
        'version' { Invoke-CmdVersion }
        'hashes' { Invoke-CmdHashes }
        'encrypt' {
            if ($restCount -ne 3) { Show-Usage }
            Invoke-CmdEncrypt -Profile $Rest[0] -InFile $Rest[1] -OutFile $Rest[2]
        }
        'decrypt' {
            if ($restCount -ne 4) { Show-Usage }
            Invoke-CmdDecrypt -Profile $Rest[0] -BlobHex $Rest[1] `
                -InFile $Rest[2] -OutFile $Rest[3]
        }
        default { Show-Usage }
    }
    exit 0
}
catch {
    [Console]::Error.WriteLine("eitb: $($_.Exception.Message)")
    exit 1
}
