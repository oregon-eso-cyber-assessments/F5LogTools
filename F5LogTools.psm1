[CmdletBinding()]
param()
Get-ChildItem -Path $PSScriptRoot -Filter *.ps1 | Tee-Object -Variable AllPs1Files | ForEach-Object {
    . $_.FullName
}
Export-ModuleMember -Function $AllPs1Files.BaseName