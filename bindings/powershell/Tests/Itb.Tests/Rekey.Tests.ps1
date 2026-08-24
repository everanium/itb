# Init -> Rekey -> Open receiver with the rotated blob -> round trip.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelper.ps1')
}

Describe 'Rekey' {
    It 'rotates the masters, refreshes the blob, and round-trips' {
        $sender = New-ItbPipeline -Profile 'singlemsg-triple-mac-v1'
        try {
            $blobBefore = Get-ItbBlob -Pipeline $sender

            $perm = [byte[]]::new(32)
            $wrap = [byte[]]::new(32)
            for ($i = 0; $i -lt 32; $i++) {
                $perm[$i] = 0x11
                $wrap[$i] = 0x22
            }
            $blobAfter = Invoke-ItbRekey -Pipeline $sender `
                -PermMaster $perm -WrapMaster $wrap
            (Test-BytesEqual $blobAfter $blobBefore) | Should -BeFalse

            # Invoke-ItbRekey returns the same bytes Get-ItbBlob reads.
            (Test-BytesEqual $blobAfter (Get-ItbBlob $sender)) | Should -BeTrue

            $receiver = Open-ItbPipeline -Profile 'singlemsg-triple-mac-v1' `
                -Blob $blobAfter
            try {
                $wire = Invoke-ItbEncrypt -Pipeline $sender -Data 'post-rekey payload'
                $back = Invoke-ItbDecrypt -Pipeline $receiver -Data $wire
                [System.Text.Encoding]::UTF8.GetString($back) |
                    Should -Be 'post-rekey payload'
            }
            finally { $receiver.Dispose() }
        }
        finally { $sender.Dispose() }
    }
}
