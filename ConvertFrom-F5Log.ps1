function ConvertFrom-F5Log {

    <#
    .SYNOPSIS
        Converts F5 log files into PowerShell objects.
    .DESCRIPTION
        Converts F5 log files into PowerShell objects.
    .EXAMPLE
        ConvertFrom-F5AuditLog -Path C:\path\to\audit.log
        Converts 'audit.log' into PowerShell objects.
    .EXAMPLE
        ConvertFrom-F5AuditLog -Path C:\path\to\var\log -IncludeRegEx tmsh -FileFilter audit*
        Converts all files under 'C:\path\to\var\log' named 'audit*' into PowerShell objects.
        Filters the output to only entries related to F5 Traffic Management Shell (tmsh).
    .PARAMETER Path
        Path to the file(s) or folder(s) to be converted.
    .PARAMETER IncludeRegEx
        RegEx filter for logs to include. Defaults to '.*'
    .PARAMETER ExcludeRegEx
        RegEx filter for logs to exclude. Defaults to '^$'
    .PARAMETER FileFilter
        Path filter for input files. Defaults to '*'
    .PARAMETER TimeStampToString
        Switch to convert TimeStamp parameter from [datetime] to [string].
    .INPUTS
        System.Object
    .OUTPUTS
        System.Object
    .NOTES
        #######################################################################################
        Author:     State of Oregon, Enterprise Security Office, Cybersecurity Assessment Team
        Version:    1.0
        #######################################################################################
        License:    https://unlicense.org/UNLICENSE
        #######################################################################################
    .LINK
        https://github.com/oregon-eso-cyber-assessments
    .FUNCTIONALITY
        Converts F5 log files into powershell objects.
    #>

    [CmdletBinding()]

    param (

        [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [Alias('PSPath','FullName')]
        [string[]]
        $Path,

        [string]
        $IncludeRegEx,

        [string]
        $ExcludeRegEx,

        [string]
        $FileFilter,

        [switch]
        $TimeStampToString

    ) #param

    begin {

        if (-not ($PSBoundParameters['FileFilter'])) {
            $FileFilter = '*'
        } #if FileFilter

        if (-not ($PSBoundParameters['IncludeRegEx'])) {
            $IncludeRegEx = '.*'
        } #if IncludeRegEx

        if (-not ($PSBoundParameters['ExcludeRegEx'])) {
            $ExcludeRegEx = '^$'
        } #if ExcludeRegEx

        $DateFormatRegEx = '^\w\w\w\s+\d+\s\d\d:\d\d:\d\d'
        $LogSeverityRegEx = '(emerg|alert|crit|err|warning|notice|info|debug)'

    } #begin

    process {

        $Path | ForEach-Object {

            $EachItem = $_ | Get-Item

            if (-not $EachItem.PSIsContainer) {

                $EachItem | Get-Content | Where-Object {
                    $_ -match $DateFormatRegEx -and
                    $_ -match $LogSeverityRegEx -and
                    $_ -match $IncludeRegEx -and
                    $_ -notmatch $ExcludeRegEx
                }

            } elseif ($EachItem.PSIsContainer) {

                $EachItem | Get-ChildItem -Recurse -File -Filter $FileFilter | Get-Content | Where-Object {
                    $_ -match $DateFormatRegEx -and
                    $_ -match $LogSeverityRegEx -and
                    $_ -match $IncludeRegEx -and
                    $_ -notmatch $ExcludeRegEx
                }

            } #if

        } | ForEach-Object {

            $ValueArray = $_.SubString(16).Split(' ')
            $Hostname = $ValueArray[0]
            $Level = $ValueArray[1]
            $Source = $ValueArray[2].Split('[')[0].Split('(')[0] -replace '(-|:)'
            $MessageArray = ($ValueArray | Select-Object -Skip 4)
            $MetaArray = $MessageArray | Where-Object { $_ -match '=' }
            $UserEnum = $MetaArray | Where-Object { $_ -match 'user' }

            if ($UserEnum) {
                $User = ($UserEnum).Split('=')[-1].Split('(')[0]
            } else {
                $User = '-'
            } #if

            $Year = (Get-Date).Year.ToString()
            $Date = Get-Date -Date "$("$($_.SubString(0,6)) $Year" -replace '\s\s',' ') $($_.SubString(7,8))"

            if ($TimeStampToString) {
                $TimeStamp = [string]$Date.GetDateTimeFormats('s')
            } else {
                $TimeStamp = $Date
            } #if

            $MessageText = (($MessageArray | Where-Object { $_ -notmatch '=' }) -join ' ').Split(']')[-1].Trim()

            New-Object -TypeName psobject -Property @{
                TimeStamp = $TimeStamp
                Hostname = $Hostname
                Level = $Level
                Source = $Source
                User = $User
                Message = $MessageText
            }

        } | Select-Object -Property TimeStamp,Hostname,Level,Source,User,Message | Where-Object { $_.Message }

    } #process

} #function ConvertFrom-F5Log