# F5LogTools

Some PowerShell tools for working with F5 logs.

## Getting Started

Clone the repo to get started...

```powershell
$F5LogTools = "$($env:PSModulePath.Split(';')[0])/F5LogTools"

if (-not (Test-Path -Path $F5LogTools)) {

    $F5LogTools = (New-Item -Path $F5LogTools -ItemType Directory -Force).FullName

}

git clone https://github.com/oregon-eso-cyber-assessments/F5LogTools.git $F5LogTools

Import-Module $F5LogTools

Get-Help ConvertFrom-F5Log -Examples
```
