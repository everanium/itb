# Module manifest for the ITB PowerShell binding.

@{
    RootModule           = 'Itb.psm1'
    ModuleVersion        = '0.3.5'
    GUID                 = 'ac3aa715-a34c-46de-906f-51d29510463b'
    Author               = 'Everanium'
    CompanyName          = 'Everanium'
    Copyright            = '(c) Everanium. All rights reserved.'
    Description          = 'ITB Triple Pipeline binding — thin proxy over the C# binding (Itb.dll CLR assembly) and the libitb shared library.'
    PowerShellVersion    = '7.4'
    CompatiblePSEditions = @('Core')
    FunctionsToExport    = @(
        'New-ItbOpts'
        'New-ItbPipeline'
        'Open-ItbPipeline'
        'Get-ItbBlob'
        'Invoke-ItbRekey'
        'Register-ItbProfile'
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
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData          = @{
        PSData = @{
            Tags       = @('encryption', 'itb', 'crypto', 'binding')
            LicenseUri = 'https://github.com/everanium/itb/blob/main/LICENSE'
            ProjectUri = 'https://github.com/everanium/itb'
        }
    }
}
