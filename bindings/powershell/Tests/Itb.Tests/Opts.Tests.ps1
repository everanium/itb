# New-ItbOpts hashtable rendering, verified behaviorally through the
# Go-side validator (the query string itself is internal to the C#
# assembly): accepted keys Init cleanly, rejected keys surface
# BadInput, typed values (bool / int / array / byte[]) render into
# forms the Go parser accepts.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelper.ps1')
}

Describe 'Opts' {
    It 'returns an [Itb.Opts] instance' {
        (New-ItbOpts) | Should -BeOfType ([Itb.Opts])
        (New-ItbOpts @{ chunkSize = 4096 }) | Should -BeOfType ([Itb.Opts])
    }

    It 'renders typed values the Go side accepts' {
        $opts = New-ItbOpts ([ordered]@{
                nonceBits    = 512
                keyBits      = 1024
                withParallax = $false
                withWrapper  = $false
                innerHash    = 'areion512'
            })
        $pipe = New-ItbPipeline -Profile 'singlemsg-triple-mac-v1' -Opts $opts
        try {
            $wire = Invoke-ItbEncrypt -Pipeline $pipe -Data 'typed opts'
            $wire.Length | Should -BeGreaterThan 0
        }
        finally { $pipe.Dispose() }
    }

    It 'accepts a plain hashtable directly on -Opts' {
        $pipe = New-ItbPipeline -Profile 'singlemsg-triple-mac-v1' `
            -Opts @{ chunkSize = 65536 }
        try {
            $back = Invoke-ItbDecrypt -Pipeline (
                Import-ItbPipeline -Blob (Save-ItbPipeline $pipe)) `
                -Data (Invoke-ItbEncrypt -Pipeline $pipe -Data 'hashtable opts')
            [System.Text.Encoding]::UTF8.GetString($back) | Should -Be 'hashtable opts'
        }
        finally { $pipe.Dispose() }
    }

    It 'relays an unknown opts key to Go as BadInput' {
        # Typoed key (lowercase s) — Go rejects unknown keys.
        { New-ItbPipeline -Profile 'singlemsg-triple-mac-v1' `
                -Opts @{ chunksize = 4096 } } |
            Should -Throw -ExceptionType ([Itb.ItbException])
        try {
            New-ItbPipeline -Profile 'singlemsg-triple-mac-v1' -Opts @{ chunksize = 4096 }
        }
        catch {
            $_.Exception.Status | Should -Be ([Itb.Status]::BadInput)
        }
    }

    It 'comma-joins array values (parallaxPalette shape)' {
        # An array value renders as a comma-joined list; a bad name in
        # the list is rejected Go-side, proving the list reached the
        # parser as a palette.
        try {
            New-ItbPipeline -Profile 'singlemsg-triple-mac-v1' `
                -Opts @{ parallaxPalette = @('no-such-cipher', 'chacha20') }
            throw 'expected ItbException'
        }
        catch [Itb.ItbException] {
            $_.Exception.Status | Should -Not -Be ([Itb.Status]::Ok)
        }
    }

    It 'rejects an unsupported -Opts argument type' {
        { New-ItbPipeline -Profile 'singlemsg-triple-mac-v1' -Opts 42 } | Should -Throw
    }
}
