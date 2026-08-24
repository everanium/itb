# Error-mapping surface: opaque-string relay, closed Pipeline,
# duplicate profile registration (with an 8-entry innerHashes
# constellation).

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelper.ps1')
}

Describe 'Error mapping' {
    It 'surfaces an unknown profile as BadInput with a diagnostic' {
        try {
            New-ItbPipeline -Profile 'no-such-profile'
            throw 'expected ItbException'
        }
        catch [Itb.ItbException] {
            $_.Exception.Status | Should -Be ([Itb.Status]::BadInput)
            $_.Exception.Message | Should -Not -BeNullOrEmpty
        }
    }

    It 'reports TripleClosed after Close-ItbPipeline -KeepHandle' {
        $pipe = New-ItbPipeline -Profile 'singlemsg-triple-mac-v1'
        try {
            Close-ItbPipeline -Pipeline $pipe -KeepHandle
            Close-ItbPipeline -Pipeline $pipe -KeepHandle   # idempotent
            try {
                Invoke-ItbEncrypt -Pipeline $pipe -Data 'payload'
                throw 'expected ItbException'
            }
            catch [Itb.ItbException] {
                $_.Exception.Status | Should -Be ([Itb.Status]::TripleClosed)
            }
        }
        finally { $pipe.Dispose() }
    }

    It 'registers a mixed profile, round-trips it, and rejects a duplicate' {
        # 8-entry width-256 innerHashes constellation, layers off.
        $opts = [ordered]@{
            mode        = 'singlemsg-nomac'
            width       = 256
            innerHashes = @('blake3', 'blake2s', 'areion256', 'blake2b256',
                'chacha20', 'blake3', 'blake2s', 'areion256')
            keyBits     = 1024
            parallaxOn  = $false
            wrapperOn   = $false
        }
        Register-ItbProfile -Name 'pwsh-binding-test-mixed' -Opts $opts

        $sender = New-ItbPipeline -Profile 'pwsh-binding-test-mixed'
        try {
            $receiver = Open-ItbPipeline -Profile 'pwsh-binding-test-mixed' `
                -Blob (Get-ItbBlob $sender)
            try {
                $wire = Invoke-ItbEncrypt -Pipeline $sender -Data 'custom profile'
                $back = Invoke-ItbDecrypt -Pipeline $receiver -Data $wire
                [System.Text.Encoding]::UTF8.GetString($back) | Should -Be 'custom profile'
            }
            finally { $receiver.Dispose() }
        }
        finally { $sender.Dispose() }

        # Duplicate name is a distinct status.
        try {
            Register-ItbProfile -Name 'pwsh-binding-test-mixed' -Opts $opts
            throw 'expected ItbException'
        }
        catch [Itb.ItbException] {
            $_.Exception.Status | Should -Be ([Itb.Status]::ProfileExists)
        }
    }

    It 'relays an opaque unknown primitive name to Go for rejection' {
        # The binding performs no name validation of its own.
        try {
            New-ItbPipeline -Profile 'singlemsg-triple-mac-v1' `
                -Opts @{ innerHash = 'no-such-hash' }
            throw 'expected ItbException'
        }
        catch [Itb.ItbException] {
            $_.Exception.Status | Should -Not -Be ([Itb.Status]::Ok)
        }
    }
}
