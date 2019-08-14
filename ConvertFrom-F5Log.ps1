function ConvertFrom-F5Log {

    <#
    .SYNOPSIS
        Converts F5 log files into PowerShell objects.
    .DESCRIPTION
        Converts F5 log files into PowerShell objects.
    .EXAMPLE
        ConvertFrom-F5Log -Path C:\path\to\audit.log
        Converts 'audit.log' into PowerShell objects.
    .EXAMPLE
        ConvertFrom-F5Log -Path C:\path\to\var\log -IncludeRegEx tmsh -FileFilter audit*
        Converts all files under 'C:\path\to\var\log' named 'audit*' into PowerShell objects.
        Filters the output to only entries related to F5 Traffic Management Shell (tmsh).
    .EXAMPLE
        # Search ltm logs for attacks and calculate the duration of each one.
        ConvertFrom-F5Log -Path 'C:\path\to\var\log' -FileFilter ltm* -IncludeRegEx attack | ForEach-Object {
            $AttackID = $_.Message.Split(' ')[-1] -replace '\.'
            $AttackVector = [regex]::Matches($($_.Message),'vector\s.+(?=,)').Value.ToString() -replace 'vector\s'
            Add-Member -InputObject $_ -MemberType NoteProperty -Name AttackID -Value $AttackID
            Add-Member -InputObject $_ -MemberType NoteProperty -Name AttackVector -Value $AttackVector -PassThru
        } | Group-Object -Property AttackID | Where-Object { $_.Count -eq 2 } | ForEach-Object {
            $TheEvents = $_.Group | Sort-Object -Property TimeStamp
            $TotalSeconds = (New-TimeSpan -Start $TheEvents[0].TimeStamp -End $TheEvents[-1].TimeStamp).TotalSeconds
            New-Object -TypeName psobject -Property @{
                Hostname = $TheEvents[0].Hostname
                AttackID = $TheEvents[0].AttackID
                AttackVector = $TheEvents[0].AttackVector
                StartTime = $TheEvents[0].TimeStamp
                StopTime = $TheEvents[-1].TimeStamp
                TotalSeconds = [int]$TotalSeconds
            }
        } | Tee-Object -Variable Attacks |
        Select-Object -Property Hostname,AttackID,AttackVector,StartTime,StopTime,TotalSeconds
    .EXAMPLE
        $Attacks | Group-Object -Property AttackVector | Sort-Object -Property Count -Descending
        Assuming you already ran example 3, summarize attack totals by vector.
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
    .PARAMETER Year
        The year as a string.
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
        $TimeStampToString,

        [string]
        $Year

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

        if (-not ($PSBoundParameters['Year'])) {
            $Year = (Get-Date).Year.ToString()
        } #if Year

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