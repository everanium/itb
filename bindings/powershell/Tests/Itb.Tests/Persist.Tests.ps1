# Session persistence surface: Save-ItbPipeline / Import-ItbPipeline
# (bytes and -Path), Get-ItbProfile (-Name / -Blob),
# Get-ItbProfileName, Register-ItbProfile with a record,
# Set-ItbMaxWorkers clamping.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelper.ps1')
    $script:Plain = [System.Text.Encoding]::UTF8.GetBytes('persisted session payload')
}

Describe 'Persistence' {
    It 'round-trips Save-ItbPipeline -> Import-ItbPipeline' {
        $sender = New-ItbPipeline -Profile 'singlemsg-triple-mac-v1'
        try {
            $blob = Save-ItbPipeline $sender
            $blob.Length | Should -BeGreaterThan 0
            (Test-BytesEqual $blob (Save-ItbPipeline $sender)) | Should -BeTrue
            $receiver = Import-ItbPipeline -Blob $blob
            try {
                (Test-BytesEqual $blob (Save-ItbPipeline $receiver)) | Should -BeTrue
                $back = Invoke-ItbDecrypt -Pipeline $receiver `
                    -Data (Invoke-ItbEncrypt -Pipeline $sender -Data $script:Plain)
                (Test-BytesEqual $back $script:Plain) | Should -BeTrue
            }
            finally { $receiver.Dispose() }
        }
        finally { $sender.Dispose() }
    }

    It 'round-trips Save-ItbPipeline -Path -> Import-ItbPipeline -Path' {
        $dir = Join-Path ([System.IO.Path]::GetTempPath()) ("itb-pwsh-" + [guid]::NewGuid())
        New-Item -ItemType Directory -Path $dir | Out-Null
        $file = Join-Path $dir 'session.blob'
        $sender = New-ItbPipeline -Profile 'streaming-aead-triple-mac-v1'
        try {
            Save-ItbPipeline -Pipeline $sender -Path $file
            (Test-BytesEqual ([System.IO.File]::ReadAllBytes($file)) (Save-ItbPipeline $sender)) |
                Should -BeTrue
            $receiver = Import-ItbPipeline -Path $file
            try {
                $back = Invoke-ItbDecryptStream -Pipeline $receiver `
                    -Data (Invoke-ItbEncryptStream -Pipeline $sender -Data $script:Plain)
                (Test-BytesEqual $back $script:Plain) | Should -BeTrue
            }
            finally { $receiver.Dispose() }
        }
        finally {
            $sender.Dispose()
            Remove-Item -Recurse -Force $dir
        }
    }

    It 'loads with a master override after rekey' {
        $perm = [byte[]]::new(32); [Array]::Fill($perm, [byte]0x33)
        $wrap = [byte[]]::new(32); [Array]::Fill($wrap, [byte]0x44)
        $sender = New-ItbPipeline -Profile 'singlemsg-triple-mac-v1'
        try {
            $blob = Save-ItbPipeline $sender
            $rotated = Invoke-ItbRekey -Pipeline $sender -PermMaster $perm -WrapMaster $wrap
            (Test-BytesEqual $blob $rotated) | Should -BeFalse
            $receiver = Import-ItbPipeline -Blob $blob -PermMaster $perm -WrapMaster $wrap
            try {
                $back = Invoke-ItbDecrypt -Pipeline $receiver `
                    -Data (Invoke-ItbEncrypt -Pipeline $sender -Data $script:Plain)
                (Test-BytesEqual $back $script:Plain) | Should -BeTrue
            }
            finally { $receiver.Dispose() }
        }
        finally { $sender.Dispose() }
    }

    It 'inspects the embedded record and matches the registry' {
        $pipe = New-ItbPipeline -Profile 'streaming-aead-triple-mac-v1'
        try {
            $prof = Get-ItbProfile -Blob (Save-ItbPipeline $pipe)
            $prof | Should -BeOfType ([Itb.Profile])
            $prof.Name | Should -Be 'streaming-aead-triple-mac-v1'
            $prof.Mode | Should -Be 'streaming-aead'
            $prof.Width | Should -Be 512
            (Get-ItbProfile -Name 'streaming-aead-triple-mac-v1').ToJson() | Should -Be $prof.ToJson()
        }
        finally { $pipe.Dispose() }
    }

    It 'lists the catalogue' {
        $names = Get-ItbProfileName
        $names | Should -Contain 'singlemsg-triple-mac-v1'
        $names | Should -Contain 'streaming-aead-triple-mac-v1'
    }

    It 'registers a copy of a shipped profile' {
        $copy = Get-ItbProfile -Name 'singlemsg-triple-nomac-v1'
        $copy.Name = ''
        Register-ItbProfile -Name 'pwsh-binding-test-copy' -Profile $copy
        (Get-ItbProfile -Name 'pwsh-binding-test-copy').Mode | Should -Be $copy.Mode
        Get-ItbProfileName | Should -Contain 'pwsh-binding-test-copy'
        $sender = New-ItbPipeline -Profile 'pwsh-binding-test-copy'
        try {
            $receiver = Import-ItbPipeline -Blob (Save-ItbPipeline $sender)
            try {
                $back = Invoke-ItbDecrypt -Pipeline $receiver `
                    -Data (Invoke-ItbEncrypt -Pipeline $sender -Data $script:Plain)
                (Test-BytesEqual $back $script:Plain) | Should -BeTrue
            }
            finally { $receiver.Dispose() }
        }
        finally { $sender.Dispose() }
    }

    It 'clamps Set-ItbMaxWorkers and accepts maxWorkers=-1 at init' {
        $pipe = New-ItbPipeline -Profile 'singlemsg-triple-mac-v1' -Opts @{ maxWorkers = -1 }
        try {
            Set-ItbMaxWorkers -Pipeline $pipe -Count 2
            Set-ItbMaxWorkers -Pipeline $pipe -Count -1
            Set-ItbMaxWorkers -Pipeline $pipe -Count 1000
            $back = Invoke-ItbDecrypt -Pipeline $pipe `
                -Data (Invoke-ItbEncrypt -Pipeline $pipe -Data $script:Plain)
            (Test-BytesEqual $back $script:Plain) | Should -BeTrue
        }
        finally { $pipe.Dispose() }
    }
}
