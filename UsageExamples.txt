<#
    Example 1: Measure the duration of each attack logged in /var/log/ltm*
#>
. .\ConvertFrom-F5Log.ps1
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

<#
    Example 2: Summarize the number of attacks per AttackVector (Assumes you already ran "Example 1")
#>
$Attacks | Group-Object -Property AttackVector | Sort-Object -Property Count -Descending